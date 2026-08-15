package noise

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/noise/bindings"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

const (
	registerEndpoint = "/machine/register"

	streamStrategyPerChunk  = "per_chunk"
	streamStrategyCollapsed = "collapsed"

	// nodeKeySignature is the tailnet-lock signature stripped (never rebound) when its bound node key is mutated.
	nlBinding = "tailnet_lock_node_key_signature"
	nlReason  = "unrebindable_no_tailnet_lock_key"

	// annStrippedBindings holds the list of per-binding strip records when a single
	// replay strips more than one binding (else the flat single-record shape is kept).
	annStrippedBindings = "stripped_bindings"
)

// OnSidecarSend serves replay (source flow inlined) and injection (no source flow).
// The SDK Handler signature carries no context, so a background context is used
// deliberately: the produced flows (including long-lived streams) outlive the call.
// p.Force / p.FollowRedirects / p.Destination are ignored for tailscale.control
// flows because the destination is intrinsic to the tunnel.
func (h *Handler) OnSidecarSend(p wire.SidecarSendParams) (wire.SidecarSendResult, error) {
	if p.Flow == nil && p.FlowID == "" {
		return h.inject(h.baseCtx, p)
	}
	return h.replay(h.baseCtx, p)
}

// replay re-sends a captured control request through the source's tunnel (or a
// fresh one), applying the mutation grammar then rebinding invalidated bindings.
func (h *Handler) replay(ctx context.Context, p wire.SidecarSendParams) (wire.SidecarSendResult, error) {
	src := p.Flow
	if src == nil || src.Request == nil {
		return wire.SidecarSendResult{}, errors.New("replay: source flow has no request to replay")
	}
	switch p.StreamStrategy {
	case "", streamStrategyPerChunk, streamStrategyCollapsed:
	default:
		return wire.SidecarSendResult{}, fmt.Errorf("replay: unknown stream_strategy %q", p.StreamStrategy)
	}
	if isStreamSource(src) && p.StreamStrategy == streamStrategyCollapsed {
		return wire.SidecarSendResult{}, errors.New("replay: collapsed stream_strategy is not supported for map.stream")
	}

	req := src.Request.Clone()
	normalizePathQuery(req)
	if err := sidecar.ApplyMutations(req, p.Mutations); err != nil {
		return wire.SidecarSendResult{}, err
	}
	// endpoint is read post-mutation: a path mutation that crosses endpoints
	// intentionally re-routes rebind to the new endpoint's binding set
	endpoint := req.Path

	at, cleanup, crossTunnel, err := h.selectTunnel(ctx, src.ParentFlowID, endpoint, bodyVersion(req.Body))
	if err != nil {
		return wire.SidecarSendResult{}, h.sendFailed("replay", endpoint, "select tunnel", nil, false, err)
	}
	reused := !crossTunnel
	// cleanup ownership transfers to emitProduced on success (a stream drains
	// asynchronously); until then it covers the pre-emit error paths
	var committed bool
	defer func() {
		if !committed && cleanup != nil {
			cleanup()
		}
	}()

	// TODO - binding-verification testing (forwarding the request verbatim without
	// rebinding, to send deliberately stale/invalid signatures and session handles)
	// should be reintroduced as a dedicated adapter-owned MCP tool, not a field on
	// the shared send params.
	strip, resign, err := h.rebind(endpoint, req, at, crossTunnel, p.Mutations)
	if err != nil {
		return wire.SidecarSendResult{}, h.sendFailed("replay", endpoint, "rebind", at, reused, err)
	}

	// reflect method/path mutations on the wire: buildUpstreamRequest reads the
	// pseudo-headers, which ApplyMutations does not touch
	syncPseudoHeaders(req)
	outReq, err := buildUpstreamRequest(ctx, at.controlHost, req.Headers, req.Body)
	if err != nil {
		return wire.SidecarSendResult{}, h.sendFailed("replay", endpoint, "build upstream request", at, reused, err)
	}
	resp, err := h.forwardTunnel(ctx, at, outReq)
	if err != nil {
		return wire.SidecarSendResult{}, h.sendFailed("replay", endpoint, "forward upstream", at, reused, err)
	}
	f := sendFields(endpoint, at, reused)
	f["resign"], f["status"] = resign, resp.StatusCode
	_ = h.conn.Log("info", "replay sent", f)

	// replay classifies by parent_flow_id (the source flow), not an annotation
	committed = true
	return h.emitProduced(ctx, req, resp, p.FlowID, strip, cleanup)
}

// selectTunnel picks the upstream tunnel for a replay of endpoint: register always opens a
// fresh dedicated-session tunnel (one-shot, non-idempotent — never reuse or coalesce onto a
// live conn), other endpoints reuse the source flow's still-open tunnel when present else a
// fresh pooled one. crossTunnel is true whenever a fresh tunnel is opened; its cleanup must be deferred.
func (h *Handler) selectTunnel(ctx context.Context, tunnelID, endpoint string, version uint16) (at *activeTunnel, cleanup func(), crossTunnel bool, err error) {
	// fresh originate identity, distinct from any live client's node session
	mk := key.NewMachine()
	if endpoint == registerEndpoint {
		at, cleanup, err = h.openFreshTunnel(ctx, h.controlHost, mk, version, h.dedicatedPoolSession())
		if err != nil {
			return nil, nil, false, err
		}
		return at, cleanup, true, nil
	}
	if at = h.getTunnel(tunnelID); at != nil {
		// hold a ref so idle-close can't tear the upstream down mid-send; fall through
		// to a fresh tunnel if it was already torn down under us
		up, _ := at.current()
		if release, ok := h.tryAcquireUpstream(up); ok {
			return at, release, false, nil
		}
	}
	at, cleanup, err = h.openFreshTunnel(ctx, h.controlHost, mk, version, h.freshPoolSession())
	if err != nil {
		return nil, nil, false, err
	}
	return at, cleanup, true, nil
}

// sendFields returns the common log fields identifying a replay/inject send. reused reports
// whether the send rode an existing tunnel (the source flow's for replay, a live client's for
// inject) rather than a freshly opened one. Precondition: at != nil.
func sendFields(endpoint string, at *activeTunnel, reused bool) map[string]any {
	return map[string]any{
		"endpoint": endpoint, "tunnel_id": at.flowID, "reused": reused,
		"machine_key": adapter.KeyPrefix(at.machineKey.Public().String()),
		"upstream":    at.controlHost,
	}
}

// sendFailed logs a replay/inject failure with tunnel context (at may be nil before a
// tunnel is selected) and returns the error wrapped with the same context. op is "replay"
// or "inject"; stage names the failing step.
func (h *Handler) sendFailed(op, endpoint, stage string, at *activeTunnel, reused bool, err error) error {
	f := map[string]any{"endpoint": endpoint, "stage": stage, "error": err.Error()}
	var tunnelID string
	if at != nil {
		tunnelID = at.flowID
		f["tunnel_id"] = tunnelID
		f["reused"] = reused
		f["machine_key"] = adapter.KeyPrefix(at.machineKey.Public().String())
		f["upstream"] = at.controlHost
	}
	_ = h.conn.Log("error", op+" failed", f)
	return fmt.Errorf("%s %s (tunnel=%s reused=%v %s): %w", op, endpoint, tunnelID, reused, stage, err)
}

// rebind recomputes the cryptographic bindings a replay invalidates, re-signing with configured key material
// or stripping and annotating otherwise. It returns the strip annotations (if any) and whether the signature
// resign path ran (a device/attestation signature was recomputed or stripped; a bare session reset is not counted).
func (h *Handler) rebind(endpoint string, req *wire.FlowMessage, at *activeTunnel, crossTunnel bool, muts []wire.Mutation) (map[string]any, bool, error) {
	switch endpoint {
	case registerEndpoint:
		var strips []map[string]any
		if mutationTouches(muts, "NodeKey") {
			body, a, err := stripNodeKeySignature(req.Body)
			if err != nil {
				return nil, false, err
			}
			req.Body = body
			if a != nil {
				strips = append(strips, a)
			}
		}
		if crossTunnel || mutationTouches(muts, "Timestamp", "DeviceCert", "Signature", "SignatureType") {
			res, err := bindings.ResignRegisterRequest(req.Body, "https://"+at.controlHost, at.serverLegacy, at.machineKey.Public(), h.regSigner)
			if err != nil {
				return nil, false, err
			}
			req.Body = res.Body
			if res.Annotations != nil {
				strips = append(strips, res.Annotations)
			}
			return stripAnnotations(strips), true, nil
		}
		return stripAnnotations(strips), false, nil
	case mapEndpoint:
		var ann map[string]any
		var resigned bool
		if mutationTouches(muts, "NodeKey", "HardwareAttestationKey", "HardwareAttestationKeySignature", "HardwareAttestationKeySignatureTimestamp") {
			res, err := bindings.ResignHardwareAttestation(req.Body, time.Now(), h.hwSigner)
			if err != nil {
				return nil, false, err
			}
			req.Body, ann, resigned = res.Body, res.Annotations, true
		}
		if crossTunnel || mutationTouches(muts, "MapSessionHandle", "MapSessionSeq") {
			res, err := bindings.ResetMapSession(req.Body)
			if err != nil {
				return nil, false, err
			}
			req.Body = res.Body
		}
		return ann, resigned, nil
	}
	return nil, false, nil
}

// emitProduced forwards the produced request/response as a flow parented to parentFlowID
// (the replay source, or empty for injection) and carrying ann, and returns the produced
// flow ids and the response form. A streamed MapResponse returns the stream parent id
// without blocking. cleanup (may be nil) tears down a fresh tunnel.
func (h *Handler) emitProduced(ctx context.Context, req *wire.FlowMessage, resp *http.Response, parentFlowID string, ann map[string]any, cleanup func()) (wire.SidecarSendResult, error) {
	now := time.Now()

	if req.Path == mapEndpoint && isStreamingMap(req.Path, req.Body) {
		statusHeaders := responseHeaders(resp)
		parentID, err := h.conn.PushFlow(ctx, wire.Flow{
			ProtocolTag:  streamProtocolTag,
			Direction:    adapter.DirServerToClient,
			ParentFlowID: parentFlowID,
			Response:     &wire.FlowMessage{StatusCode: resp.StatusCode, Headers: statusHeaders},
			Annotations:  ann,
			StartedAt:    now,
		})
		if err != nil {
			_ = resp.Body.Close()
			if cleanup != nil {
				cleanup()
			}
			return wire.SidecarSendResult{}, err
		}
		go func() {
			reader := newMapStreamReader(ctx, h, resp.Body, parentID)
			if _, cerr := io.Copy(io.Discard, reader); cerr != nil {
				_ = h.conn.Log("error", "stream capture failed", map[string]any{"flow_id": parentID, "error": cerr.Error()})
			}
			_ = reader.Close()
			if cleanup != nil {
				cleanup()
			}
		}()
		return wire.SidecarSendResult{
			NewFlowIDs: []string{parentID},
			Response:   &wire.FlowMessage{StatusCode: resp.StatusCode, Headers: statusHeaders},
		}, nil
	}

	if cleanup != nil {
		defer cleanup()
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return wire.SidecarSendResult{}, err
	}
	respMsg := &wire.FlowMessage{StatusCode: resp.StatusCode, Headers: responseHeaders(resp), Body: body}
	id, err := h.conn.PushFlow(ctx, wire.Flow{
		ProtocolTag:  controlProtocolTag,
		Direction:    adapter.DirClientToServer,
		ParentFlowID: parentFlowID,
		Request:      &wire.FlowMessage{Method: req.Method, Path: req.Path, Query: req.Query, Headers: req.Headers, Body: req.Body},
		Response:     respMsg,
		Annotations:  ann,
		StartedAt:    now,
		CompletedAt:  now,
	})
	if err != nil {
		return wire.SidecarSendResult{}, err
	}
	return wire.SidecarSendResult{NewFlowIDs: []string{id}, Response: respMsg}, nil
}

// normalizePathQuery lifts a query embedded in the :path pseudo-header into the
// message Path/Query, so the mutation grammar and syncPseudoHeaders operate on one
// consistent model. A no-op when :path carries no
// query (the common control endpoints). Run before ApplyMutations.
func normalizePathQuery(msg *wire.FlowMessage) {
	for i := range msg.Headers {
		if msg.Headers[i].Name != ":path" {
			continue
		}

		if path, query, ok := strings.Cut(msg.Headers[i].Value, "?"); ok {
			msg.Path = path
			if msg.Query == "" {
				msg.Query = query
			}
		}
		return
	}
}

// syncPseudoHeaders rebuilds the :method/:path pseudo-headers from the message fields, so
// method/path/query mutations reach the request built from headers. The query rides in :path.
// msg.Query is preserved by normalizePathQuery when no query mutation changed it, and is
// forwarded verbatim rather than re-encoded, keeping wire fidelity on an unchanged replay.
func syncPseudoHeaders(msg *wire.FlowMessage) {
	setPseudoHeader(&msg.Headers, ":method", msg.Method)
	if msg.Path == "" {
		return
	}
	path := msg.Path
	if msg.Query != "" {
		path += "?" + msg.Query
	}
	setPseudoHeader(&msg.Headers, ":path", path)
}

func setPseudoHeader(headers *[]wire.Header, name, value string) {
	if value == "" {
		return
	}
	for i := range *headers {
		if (*headers)[i].Name == name {
			(*headers)[i].Value = value
			return
		}
	}
	*headers = append(*headers, wire.Header{Name: name, Value: value})
}

// isStreamSource reports whether a source flow is an actually-streamed MapResponse
// (a stream child, or a MapRequest whose body sets Stream:true).
func isStreamSource(f *wire.Flow) bool {
	return f.ProtocolTag == streamProtocolTag ||
		(f.Request != nil && isStreamingMap(f.Request.Path, f.Request.Body))
}

// mutationTouches reports whether any mutation edits one of fields
// (matching a field, its child path, or a whole-body replace).
func mutationTouches(muts []wire.Mutation, fields ...string) bool {
	return slices.ContainsFunc(muts, func(m wire.Mutation) bool {
		if m.Op == "body" {
			return true
		}
		return slices.ContainsFunc(fields, func(f string) bool {
			return m.Name == f || strings.HasPrefix(m.Name, f+".") || strings.HasPrefix(m.Name, f+"[")
		})
	})
}

// stripNodeKeySignature removes the tailnet-lock NodeKeySignature when present
// (tailnet lock enabled), returning the strip annotation. It is a no-op otherwise.
func stripNodeKeySignature(body []byte) ([]byte, map[string]any, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return body, nil, err
	}
	raw, ok := m["NodeKeySignature"]
	if !ok {
		return body, nil, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return body, nil, err
	}
	// absent for a tailnet without tailnet lock: null or empty signature
	if v == nil {
		return body, nil, nil
	}
	if s, isStr := v.(string); isStr && s == "" {
		return body, nil, nil
	}
	delete(m, "NodeKeySignature")
	out, err := json.Marshal(m)
	if err != nil {
		return body, nil, err
	}
	return out, map[string]any{
		bindings.AnnBinding:        nlBinding,
		bindings.AnnStrippedFields: []string{"NodeKeySignature"},
		bindings.AnnReason:         nlReason,
	}, nil
}

// stripAnnotations folds one or more per-binding strip records into the flow
// annotation: nil for none, the flat single record (binding/stripped_fields/reason,
// the spec shape) for one, and a stripped_bindings list for multiple, so distinct
// bindings never collapse into one mislabeled record.
func stripAnnotations(strips []map[string]any) map[string]any {
	switch len(strips) {
	case 0:
		return nil
	case 1:
		return strips[0]
	default:
		return map[string]any{annStrippedBindings: strips}
	}
}

// bodyVersion recovers the capability version carried in a captured RegisterRequest
// or MapRequest body (JSON field "Version"), falling back to the sidecar's build
// version for custom-endpoint injections and non-JSON bodies.
func bodyVersion(body []byte) uint16 {
	var v struct {
		Version int `json:"Version"`
	}
	if err := json.Unmarshal(body, &v); err == nil && v.Version > 0 {
		return uint16(v.Version)
	}
	return uint16(tsproto.CurrentCapabilityVersion)
}
