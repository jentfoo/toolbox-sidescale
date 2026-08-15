package noise

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
)

// InjectToolName is the sidecar-registered MCP tool that originates a control request into an active or fresh tunnel.
const InjectToolName = "tailscale_inject"

// injectionRequest is the injection_target payload.
type injectionRequest struct {
	TunnelID    string            `json:"tunnel_id"`
	Endpoint    string            `json:"endpoint"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Body        json.RawMessage   `json:"body"`
	Stream      bool              `json:"stream"`
	AsMachine   string            `json:"as_machine"`
	AsVersion   uint16            `json:"as_version"`
	ReuseTunnel bool              `json:"reuse_tunnel"`
	Mutations   []wire.Mutation   `json:"mutations"`
}

// inject originates a control request from a sidecar_send with no source flow.
func (h *Handler) inject(ctx context.Context, p wire.SidecarSendParams) (wire.SidecarSendResult, error) {
	// source-less send carries the injection spec in Payload, or Target when Payload is empty
	payload := p.Payload
	if len(payload) == 0 {
		payload = p.Target
	}
	ir, err := parseInjection(payload)
	if err != nil {
		return wire.SidecarSendResult{}, err
	}
	res, _, err := h.injectObject(ctx, ir)
	return res, err
}

// OnInvokeTool serves the tailscale_inject MCP tool, delegating to the same origination path as sidecar_send injection.
func (h *Handler) OnInvokeTool(p wire.InvokeToolParams) (wire.InvokeToolResult, error) {
	if p.Name != InjectToolName {
		return wire.InvokeToolResult{}, fmt.Errorf("invoke_tool: unknown tool %q", p.Name)
	}
	ir, err := parseInjection(p.Arguments)
	if err != nil {
		return wire.InvokeToolResult{IsError: true, Content: err.Error()}, nil
	}
	res, reused, err := h.injectObject(h.baseCtx, ir)
	if err != nil {
		return wire.InvokeToolResult{IsError: true, Content: err.Error()}, nil
	}
	structured, _ := json.Marshal(map[string]any{"new_flow_ids": res.NewFlowIDs})
	return wire.InvokeToolResult{Content: injectSummary(ir, res.NewFlowIDs, reused), StructuredContent: structured}, nil
}

// injectObject builds and sends the inner request through the named live tunnel when
// reuse_tunnel opts in, else a fresh distinct-identity tunnel; the second result reports
// whether it actually rode a live tunnel.
func (h *Handler) injectObject(ctx context.Context, ir injectionRequest) (wire.SidecarSendResult, bool, error) {
	if ir.Endpoint == "" {
		return wire.SidecarSendResult{}, false, errors.New("inject: endpoint required")
	}
	if len(ir.Body) == 0 {
		return wire.SidecarSendResult{}, false, errors.New("inject: body required")
	}
	method := ir.Method
	if method == "" {
		method = http.MethodPost
	}
	// honor stream: true by forcing Stream in the MapRequest body, since the
	// upstream keys streaming off the body field, not the injection flag
	if ir.Stream && ir.Endpoint == mapEndpoint {
		body, err := ensureStreamFlag(ir.Body)
		if err != nil {
			return wire.SidecarSendResult{}, false, err
		}
		ir.Body = body
	}

	mk, err := h.injectionMachineKey(ir.AsMachine)
	if err != nil {
		return wire.SidecarSendResult{}, false, err
	}
	// reuse the named live tunnel only when reuse_tunnel opts in and as_machine matches its
	// bound identity; otherwise a fresh distinct-identity tunnel avoids disturbing the client
	var at *activeTunnel
	var cleanup func()
	var disturbsLive bool
	if ir.ReuseTunnel && ir.TunnelID != "" {
		if t := h.getTunnel(ir.TunnelID); t != nil && (ir.AsMachine == "" || mk.Public() == t.machineKey.Public()) {
			// hold a ref so idle-close can't tear the upstream down mid-send
			up, _ := t.current()
			if release, ok := h.tryAcquireUpstream(up); ok {
				at, cleanup, disturbsLive = t, release, true
				_ = h.conn.Log("warn", "inject riding live tunnel; client map may pause",
					map[string]any{"tunnel_id": ir.TunnelID})
			}
		}
	}
	if at == nil {
		// as_version overrides the cleartext initiation/prologue version independently
		// of the body Version, to exercise the initiation binding and the server version floor
		version := bodyVersion(ir.Body)
		if ir.AsVersion != 0 {
			version = ir.AsVersion
		}
		if at, cleanup, err = h.openFreshTunnel(ctx, h.controlHost, mk, version, h.freshPoolSession()); err != nil {
			return wire.SidecarSendResult{}, false, h.sendFailed("inject", ir.Endpoint, "open tunnel", nil, false, err)
		}
	}
	// cleanup ownership transfers to emitProduced on success (a stream drains asynchronously)
	// until then it covers the pre-emit error paths
	var committed bool
	defer func() {
		if !committed && cleanup != nil {
			cleanup()
		}
	}()

	msg := &wire.FlowMessage{
		Method:  method,
		Path:    ir.Endpoint,
		Headers: injectionHeaders(method, ir.Endpoint, at.controlHost, ir.Headers),
		Body:    []byte(ir.Body),
	}
	normalizePathQuery(msg)
	if err := sidecar.ApplyMutations(msg, ir.Mutations); err != nil {
		return wire.SidecarSendResult{}, false, h.sendFailed("inject", ir.Endpoint, "apply mutations", at, disturbsLive, err)
	}
	syncPseudoHeaders(msg)
	outReq, err := buildUpstreamRequest(ctx, at.controlHost, msg.Headers, msg.Body)
	if err != nil {
		return wire.SidecarSendResult{}, false, h.sendFailed("inject", ir.Endpoint, "build upstream request", at, disturbsLive, err)
	}
	resp, err := h.forwardTunnel(ctx, at, outReq)
	if err != nil {
		return wire.SidecarSendResult{}, false, h.sendFailed("inject", ir.Endpoint, "forward upstream", at, disturbsLive, err)
	}
	f := sendFields(ir.Endpoint, at, disturbsLive)
	f["status"] = resp.StatusCode
	_ = h.conn.Log("info", "inject sent", f)
	// an originated flow has no source, so no parent; adapter.AnnInjected distinguishes it
	ann := map[string]any{adapter.AnnInjected: true}
	if disturbsLive {
		ann[adapter.AnnDisturbsLiveNode] = true
	}
	committed = true
	res, err := h.emitProduced(ctx, msg, resp, "", ann, cleanup)
	return res, disturbsLive, err
}

// ensureStreamFlag sets Stream:true on a MapRequest JSON body.
func ensureStreamFlag(body json.RawMessage) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return body, fmt.Errorf("inject: stream requires a JSON object body: %w", err)
	}
	m["Stream"] = json.RawMessage("true")
	out, err := json.Marshal(m)
	if err != nil {
		return body, err
	}
	return out, nil
}

// injectionMachineKey returns the machine identity for a fresh injection tunnel: the
// as_machine override key text, or a fresh identity distinct from any live client.
func (h *Handler) injectionMachineKey(asMachine string) (key.MachinePrivate, error) {
	if asMachine == "" {
		return key.NewMachine(), nil
	}
	var k key.MachinePrivate
	if err := k.UnmarshalText([]byte(asMachine)); err != nil {
		return key.MachinePrivate{}, fmt.Errorf("inject: parse as_machine: %w", err)
	}
	return k, nil
}

func parseInjection(raw json.RawMessage) (injectionRequest, error) {
	if len(raw) == 0 {
		return injectionRequest{}, errors.New("inject: empty injection payload")
	}
	var ir injectionRequest
	if err := json.Unmarshal(raw, &ir); err != nil {
		return injectionRequest{}, fmt.Errorf("inject: parse payload: %w", err)
	}
	return ir, nil
}

// injectionHeaders renders the inner request headers as HTTP/2 pseudo-headers plus
// the supplied regular headers, mirroring a captured request's header shape.
func injectionHeaders(method, path, authority string, hdr map[string]string) []wire.Header {
	out := make([]wire.Header, 0, 4+len(hdr))
	out = append(out,
		wire.Header{Name: ":method", Value: method},
		wire.Header{Name: ":path", Value: path},
		wire.Header{Name: ":authority", Value: authority},
		wire.Header{Name: ":scheme", Value: "https"},
	)
	for k, v := range hdr {
		out = append(out, wire.Header{Name: k, Value: v})
	}
	return out
}

func injectSummary(ir injectionRequest, ids []string, reused bool) string {
	method := ir.Method
	if method == "" {
		method = http.MethodPost
	}
	target := "a fresh tunnel"
	if reused {
		target = "live tunnel " + ir.TunnelID
	}
	return fmt.Sprintf("Injected %s %s into %s; produced flow(s): %s", strings.ToUpper(method), ir.Endpoint, target, strings.Join(ids, ", "))
}
