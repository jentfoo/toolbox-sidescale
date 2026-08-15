package derp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp/derpproto"
)

// injectionRequest is the derp_inject / injection_target payload.
type injectionRequest struct {
	TunnelID    string          `json:"tunnel_id"`
	Frame       string          `json:"frame"`
	Direction   string          `json:"direction"`
	SrcKey      string          `json:"src_key"`
	DstKey      string          `json:"dst_key"`
	PeerKey     string          `json:"peer_key"`
	Reason      int             `json:"reason"`
	Flags       int             `json:"flags"`
	Home        bool            `json:"home"`
	ReconnectMs uint32          `json:"reconnect_ms"`
	TryForMs    uint32          `json:"try_for_ms"`
	Body        string          `json:"body"`
	Mutations   []wire.Mutation `json:"mutations"`
}

// defaultDirs is the write side each injectable frame defaults to.
var defaultDirs = map[derpproto.FrameType]string{
	derpproto.FrameRecvPacket:    adapter.DirServerToClient,
	derpproto.FramePeerGone:      adapter.DirServerToClient,
	derpproto.FramePeerPresent:   adapter.DirServerToClient,
	derpproto.FrameHealth:        adapter.DirServerToClient,
	derpproto.FrameRestarting:    adapter.DirServerToClient,
	derpproto.FramePing:          adapter.DirServerToClient,
	derpproto.FramePong:          adapter.DirServerToClient,
	derpproto.FrameSendPacket:    adapter.DirClientToServer,
	derpproto.FrameNotePreferred: adapter.DirClientToServer,
	derpproto.FrameWatchConns:    adapter.DirClientToServer,
	derpproto.FrameClosePeer:     adapter.DirClientToServer,
}

// inject originates a frame from a sidecar_send with no source flow.
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
	return h.injectFrame(ctx, ir)
}

// OnInvokeTool serves the derp_inject MCP tool, sharing the injection origination path.
func (h *Handler) OnInvokeTool(p wire.InvokeToolParams) (wire.InvokeToolResult, error) {
	if p.Name != InjectToolName {
		return wire.InvokeToolResult{}, fmt.Errorf("invoke_tool: unknown tool %q", p.Name)
	}
	ir, err := parseInjection(p.Arguments)
	if err != nil {
		return wire.InvokeToolResult{IsError: true, Content: err.Error()}, nil
	}
	res, err := h.injectFrame(h.baseCtx, ir)
	if err != nil {
		return wire.InvokeToolResult{IsError: true, Content: err.Error()}, nil
	}
	structured, _ := json.Marshal(map[string]any{"new_flow_ids": res.NewFlowIDs})
	return wire.InvokeToolResult{Content: injectSummary(ir, res.NewFlowIDs), StructuredContent: structured}, nil
}

// injectFrame builds a frame, resolves the tunnel side, and sends it.
func (h *Handler) injectFrame(ctx context.Context, ir injectionRequest) (wire.SidecarSendResult, error) {
	t, known, err := resolveFrameType(ir.Frame)
	if err != nil {
		return wire.SidecarSendResult{}, err
	}
	dir := ir.Direction
	if dir == "" {
		d, ok := defaultDirs[t]
		if !ok {
			return wire.SidecarSendResult{}, fmt.Errorf("derp inject: direction required for frame %q", ir.Frame)
		}
		dir = d
	}
	if dir != adapter.DirClientToServer && dir != adapter.DirServerToClient {
		return wire.SidecarSendResult{}, fmt.Errorf("derp inject: invalid direction %q", dir)
	}

	f, err := buildFrameFields(t, known, ir)
	if err != nil {
		return wire.SidecarSendResult{}, err
	}
	tgt, err := h.resolveSide(ctx, ir.TunnelID, dir, true)
	if err != nil {
		return wire.SidecarSendResult{}, err
	}
	// mesh frames require a tunnel that presented a mesh key
	if (t == derpproto.FrameWatchConns || t == derpproto.FrameClosePeer) && !tgt.mesh {
		if tgt.cleanup != nil { // don't leak a fresh upstream opened by resolveSide
			tgt.cleanup()
		}
		return wire.SidecarSendResult{}, errors.New("derp inject: mesh frame requires a mesh tunnel")
	}
	// an originated frame has no source, so no parent; adapter.AnnInjected distinguishes it
	return h.reframeAndSend(ctx, tgt, frameMessage(t, f), ir.Mutations, "", map[string]any{adapter.AnnInjected: true})
}

// resolveFrameType resolves a frame name, or a "0xNN" / "FRAME_0xNN" hex type for an
// arbitrary/unknown frame. known reports whether it matched a named frame.
func resolveFrameType(name string) (t derpproto.FrameType, known bool, err error) {
	if t, ok := derpproto.FrameTypeByName(name); ok {
		return t, true, nil
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(name, "FRAME_"), 0, 8)
	if err != nil {
		return 0, false, fmt.Errorf("derp inject: unknown frame %q", name)
	}
	return derpproto.FrameType(n), false, nil
}

// buildFrameFields constructs the typed fields for an injected frame. known reports
// whether t resolved from a frame name; an unknown (hex) type is originated as an opaque body.
func buildFrameFields(t derpproto.FrameType, known bool, ir injectionRequest) (frameFields, error) {
	f := frameFields{typ: t}
	if !known {
		body, err := base64.StdEncoding.DecodeString(ir.Body)
		if err != nil {
			return f, err
		}
		f.bodyRaw = body
		return f, nil
	}
	switch t {
	case derpproto.FrameRecvPacket:
		return packetFields(t, "X-Derp-Src-Key", ir.SrcKey, ir.Body)
	case derpproto.FrameSendPacket:
		return packetFields(t, "X-Derp-Dst-Key", ir.DstKey, ir.Body)
	case derpproto.FramePeerGone:
		peer, err := nodeKeyHeader("X-Derp-Peer-Key", ir.PeerKey)
		if err != nil {
			return f, err
		}
		f.headers = []wire.Header{peer, {Name: "X-Derp-Peer-Gone-Reason", Value: strconv.Itoa(ir.Reason)}}
	case derpproto.FramePeerPresent:
		peer, err := nodeKeyHeader("X-Derp-Peer-Key", ir.PeerKey)
		if err != nil {
			return f, err
		}
		f.headers = []wire.Header{peer}
		// tail rides as a header so it survives the frameMessage round-trip; f.tail is  hot-path only and not serialized
		if ir.Flags != 0 {
			f.headers = append(f.headers, wire.Header{Name: "X-Derp-Peer-Present-Tail", Value: base64.StdEncoding.EncodeToString([]byte{byte(ir.Flags)})})
		}
	case derpproto.FrameHealth:
		f.body = []byte(ir.Body)
	case derpproto.FrameRestarting:
		f.headers = []wire.Header{
			{Name: "X-Derp-Reconnect-Ms", Value: strconv.FormatUint(uint64(ir.ReconnectMs), 10)},
			{Name: "X-Derp-Try-For-Ms", Value: strconv.FormatUint(uint64(ir.TryForMs), 10)},
		}
	case derpproto.FramePing, derpproto.FramePong:
		f.headers = []wire.Header{{Name: "X-Derp-Ping-Token", Value: ir.Body}}
	case derpproto.FrameNotePreferred:
		f.headers = []wire.Header{{Name: "X-Derp-Home", Value: strconv.FormatBool(ir.Home)}}
	case derpproto.FrameClosePeer:
		peer, err := nodeKeyHeader("X-Derp-Peer-Key", ir.PeerKey)
		if err != nil {
			return f, err
		}
		f.headers = []wire.Header{peer}
	case derpproto.FrameWatchConns:
		// empty payload
	default:
		return f, fmt.Errorf("derp inject: frame %q not injectable", ir.Frame)
	}
	return f, nil
}

// packetFields builds a packet frame's fields: a validated node key header plus the opaque base64 payload as body_raw.
func packetFields(t derpproto.FrameType, keyHeader, keyValue, body string) (frameFields, error) {
	f := frameFields{typ: t}
	kh, err := nodeKeyHeader(keyHeader, keyValue)
	if err != nil {
		return f, err
	}
	payload, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return f, err
	}
	f.headers = append([]wire.Header{kh}, packetMetaHeaders(payload)...)
	f.bodyRaw = payload
	return f, nil
}

// nodeKeyHeader validates a node key string and returns its header, erroring on an empty or malformed key.
func nodeKeyHeader(name, value string) (wire.Header, error) {
	if value == "" {
		return wire.Header{}, fmt.Errorf("derp inject: %s required", name)
	}
	var k key.NodePublic
	if err := k.UnmarshalText([]byte(value)); err != nil {
		return wire.Header{}, fmt.Errorf("derp inject: invalid %s %q: %w", name, value, err)
	}
	return wire.Header{Name: name, Value: k.String()}, nil
}

func parseInjection(raw json.RawMessage) (injectionRequest, error) {
	if len(raw) == 0 {
		return injectionRequest{}, errors.New("derp inject: empty payload")
	}
	var ir injectionRequest
	if err := json.Unmarshal(raw, &ir); err != nil {
		return injectionRequest{}, fmt.Errorf("derp inject: parse payload: %w", err)
	} else if ir.Frame == "" {
		return injectionRequest{}, errors.New("derp inject: frame required")
	}
	return ir, nil
}

func injectSummary(ir injectionRequest, ids []string) string {
	target := "a fresh tunnel"
	if ir.TunnelID != "" {
		target = "tunnel " + ir.TunnelID
	}
	return fmt.Sprintf("Injected %s into %s, produced flow(s): %s", ir.Frame, target, strings.Join(ids, ", "))
}
