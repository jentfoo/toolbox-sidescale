package derp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"tailscale.com/derp"
	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/pkg/addr"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp/derpproto"
)

// OnSidecarSend serves DERP replay (source flow inlined) and injection (no source flow).
// Ignored: Destination/Target/Force/FollowRedirects/StreamStrategy. A frame's destination is intrinsic to its tunnel.
func (h *Handler) OnSidecarSend(p wire.SidecarSendParams) (wire.SidecarSendResult, error) {
	if p.Flow == nil && p.FlowID == "" {
		return h.inject(h.baseCtx, p)
	}
	return h.replay(h.baseCtx, p)
}

// replay re-sends a captured frame on the appropriate side of its tunnel.
func (h *Handler) replay(ctx context.Context, p wire.SidecarSendParams) (wire.SidecarSendResult, error) {
	src := p.Flow
	if src == nil {
		return wire.SidecarSendResult{}, errors.New("derp replay: source flow not inlined")
	}
	dir := src.Direction
	msg := src.Request
	if dir == adapter.DirServerToClient {
		msg = src.Response
	}
	if msg == nil {
		return wire.SidecarSendResult{}, errors.New("derp replay: source flow has no frame to replay")
	}
	tgt, err := h.resolveSide(ctx, src.ParentFlowID, dir, true)
	if err != nil {
		return wire.SidecarSendResult{}, err
	}
	// replay classifies by parent_flow_id (the source flow), not an annotation
	return h.reframeAndSend(ctx, tgt, msg, p.Mutations, p.FlowID, nil)
}

// sendTarget is the resolved write side plus the key material a re-seal needs.
type sendTarget struct {
	flowID      string
	dir         string
	fr          *frameConn
	clientKey   key.NodePublic  // SERVER_INFO re-seal target
	nodeKey     key.NodePrivate // CLIENT_INFO re-seal identity (relay only)
	upstreamPub key.NodePublic  // CLIENT_INFO re-seal target (relay only)
	mesh        bool
	cleanup     func() // when non-nil, tears down a fresh upstream opened for the send
}

// resolveSide selects the frame side to write to for a tunnel and direction, opening a
// fresh upstream (relay, client->server, torn-down tunnel) when allowFresh.
func (h *Handler) resolveSide(ctx context.Context, tunnelID, dir string, allowFresh bool) (*sendTarget, error) {
	if h.relay != nil {
		if dir == adapter.DirClientToServer {
			return nil, errors.New("derp: client_to_server send has no upstream under terminate mode")
		}
		if tunnelID == "" {
			return nil, errors.New("derp: tunnel_id required to target a terminate-mode client")
		}
		rc := h.relay.byTunnelID(tunnelID)
		if rc == nil {
			return nil, fmt.Errorf("derp: no registered client for tunnel %q", tunnelID)
		}
		return &sendTarget{flowID: tunnelID, dir: adapter.DirServerToClient, fr: rc.fr, clientKey: rc.clientKey, mesh: rc.mesh}, nil
	}

	if at := h.getTunnel(tunnelID); at != nil {
		fr := at.upstreamF
		if dir == adapter.DirServerToClient {
			fr = at.clientFr
		}
		if fr == nil {
			return nil, fmt.Errorf("derp: tunnel %q has no %s side", tunnelID, dir)
		}
		return &sendTarget{flowID: tunnelID, dir: dir, fr: fr, clientKey: at.clientKey, nodeKey: at.nodeKey, upstreamPub: at.upstreamPub, mesh: at.mesh}, nil
	}

	// no live tunnel: server_to_client has no client to reach; client_to_server can open a fresh upstream when allowed
	if dir == adapter.DirServerToClient {
		return nil, fmt.Errorf("derp: tunnel %q not live, server_to_client send needs a live client", tunnelID)
	}
	if !allowFresh {
		return nil, fmt.Errorf("derp: tunnel %q not found", tunnelID)
	}
	host, ok := h.retainedTunnelHost(tunnelID)
	if !ok {
		// bare send with no named tunnel: fall back to the sole configured host
		if host, ok = h.soleDerpHost(); !ok {
			return nil, errors.New("derp: no live tunnel and no single derp host to open a fresh upstream")
		}
	}
	return h.openFreshUpstream(ctx, host)
}

// soleDerpHost returns the single configured DERP host, or false when zero or multiple are configured.
func (h *Handler) soleDerpHost() (string, bool) {
	if len(h.cfg.DerpHosts) != 1 {
		return "", false
	}
	host, _ := addr.Parse(h.cfg.DerpHosts[0], "https")
	return host, true
}

// openFreshUpstream dials a new upstream to host and returns an ephemeral send target
// whose cleanup tears it down after the send. Fresh tunnels are always non-mesh, the
// sidecar cannot re-present the client's secret mesh key.
func (h *Handler) openFreshUpstream(ctx context.Context, host string) (*sendTarget, error) {
	// fresh originate identity, distinct from any live client's relay session
	nodeKey := key.NewNode()
	// no live client to source ClientInfo from, synthesize a minimal one
	ci := &derp.ClientInfo{Version: derpproto.ProtocolVersion}
	up, err := h.openUpstream(ctx, host, nodeKey, ci)
	if err != nil {
		return nil, err
	}
	tunnelID, err := h.emitTunnelEnvelope(ctx, envelopeInfo{
		tunnelKey:    up.streamID,
		upstreamAddr: up.addr,
		clientInfo:   ci,
		serverInfo:   up.serverInfo,
		upstreamPub:  up.serverPub,
		nodeKey:      nodeKey.Public(),
		relayMode:    RelayModeRelay,
	})
	if err != nil {
		up.close()
		return nil, err
	}
	cleanup := func() {
		up.close()
		_ = h.conn.CompleteFlow(context.Background(), tunnelID, nil, time.Now())
	}
	return &sendTarget{
		flowID:      tunnelID,
		dir:         adapter.DirClientToServer,
		fr:          up.fr,
		nodeKey:     nodeKey,
		upstreamPub: up.serverPub,
		cleanup:     cleanup,
	}, nil
}

// reframeAndSend writes the re-sealed, mutated frame on tgt's side and emits the produced
// frame flow parented to parentFlowID (the replay source, or empty for injection) and
// carrying ann. Shared by replay and injection.
func (h *Handler) reframeAndSend(ctx context.Context, tgt *sendTarget, msg *wire.FlowMessage, muts []wire.Mutation, parentFlowID string, ann map[string]any) (wire.SidecarSendResult, error) {
	if tgt.cleanup != nil {
		defer tgt.cleanup()
	}
	m := msg.Clone()
	if err := sidecar.ApplyMutations(m, muts); err != nil {
		return wire.SidecarSendResult{}, err
	}
	t, _, err := resolveFrameType(m.Method)
	if err != nil {
		return wire.SidecarSendResult{}, err
	}
	payload, extra, err := h.reframePayload(tgt, t, m, muts)
	if err != nil {
		return wire.SidecarSendResult{}, err
	}
	if _, err := tgt.fr.Write(derpproto.EncodeFrame(t, payload)); err != nil {
		return wire.SidecarSendResult{}, err
	}
	// merge any re-seal annotation into the caller's base annotations
	if len(extra) > 0 {
		if ann == nil {
			ann = map[string]any{}
		}
		maps.Copy(ann, extra)
	}
	return h.emitProduced(ctx, tgt, m, parentFlowID, ann)
}

// reframePayload builds the wire payload for a frame, re-sealing CLIENT_INFO/SERVER_INFO boxes, and
// returns any annotation for an unhonorable node-key mutation. It may normalize m to match the sent bytes.
func (h *Handler) reframePayload(tgt *sendTarget, t derpproto.FrameType, m *wire.FlowMessage, muts []wire.Mutation) ([]byte, map[string]any, error) {
	switch t {
	case derpproto.FrameClientInfo:
		if tgt.nodeKey.IsZero() {
			return nil, nil, errors.New("derp: CLIENT_INFO replay requires a relay upstream")
		}
		var ci derp.ClientInfo
		if err := json.Unmarshal(m.Body, &ci); err != nil {
			return nil, nil, fmt.Errorf("derp: CLIENT_INFO body: %w", err)
		}
		payload, err := derpproto.ClientInfoPayload(tgt.nodeKey, tgt.upstreamPub, &ci)
		if err != nil {
			return nil, nil, err
		}
		// always sealed with the held node key, so a set to an unheld key is not honored
		// a remove_header leaves no target key and is not an unheld-key situation, so ignore it
		var ann map[string]any
		if setsHeader(muts, "X-Derp-Node-Key") && headerValue(m.Headers, "X-Derp-Node-Key") != tgt.nodeKey.Public().String() {
			ann = map[string]any{"binding": "derp_node_key", "reason": "unheld_node_private_key"}
		}
		return payload, ann, nil

	case derpproto.FrameServerInfo:
		var si derp.ServerInfo
		if err := json.Unmarshal(m.Body, &si); err != nil {
			return nil, nil, fmt.Errorf("derp: SERVER_INFO body: %w", err)
		}
		payload, err := derpproto.ServerInfoPayload(h.serverKey, tgt.clientKey, &si)
		if err != nil {
			return nil, nil, err
		}
		return payload, nil, nil

	case derpproto.FrameSendPacket, derpproto.FrameRecvPacket, derpproto.FrameForwardPacket:
		// a body mutation replaces the opaque payload (ApplyMutations writes Body, never BodyRaw)
		// fold it back so the sent bytes and the recorded flow agree
		if len(m.Body) > 0 {
			m.BodyRaw = m.Body
			m.Body = nil
		}
		return encodePayload(frameFromMessage(m, t)), nil, nil

	default:
		return encodePayload(frameFromMessage(m, t)), nil, nil
	}
}

// emitProduced records the sent frame as a completed frame flow parented to parentFlowID, and returns its flow id.
func (h *Handler) emitProduced(ctx context.Context, tgt *sendTarget, m *wire.FlowMessage, parentFlowID string, ann map[string]any) (wire.SidecarSendResult, error) {
	flow := wire.Flow{
		ProtocolTag:  frameProtocolTag,
		Direction:    tgt.dir,
		ParentFlowID: parentFlowID,
		Annotations:  ann,
		StartedAt:    time.Now(),
	}
	flow.CompletedAt = flow.StartedAt
	setMessage(&flow, tgt.dir, m)
	id, err := h.conn.PushFlow(ctx, flow)
	if err != nil {
		return wire.SidecarSendResult{}, err
	}
	return wire.SidecarSendResult{NewFlowIDs: []string{id}}, nil
}

// frameFromMessage rebuilds decoded frame fields from a frame message (inverse of frameMessage).
func frameFromMessage(m *wire.FlowMessage, t derpproto.FrameType) frameFields {
	return frameFields{typ: t, headers: m.Headers, body: m.Body, bodyRaw: m.BodyRaw}
}

// setsHeader reports whether any mutation sets the named header (not remove).
func setsHeader(muts []wire.Mutation, name string) bool {
	return slices.ContainsFunc(muts, func(m wire.Mutation) bool {
		return m.Op == "set_header" && strings.EqualFold(m.Name, name)
	})
}
