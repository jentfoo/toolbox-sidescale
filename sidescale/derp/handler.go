package derp

import (
	"context"
	"encoding/json"
	"slices"
	"sync"

	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sidecar"
)

// derpPath is the DERP upgrade path claimed under relay mode.
const derpPath = "/derp"

// InjectToolName is the MCP tool that originates a DERP frame.
const InjectToolName = "derp_inject"

// derpProtocols are the flow protocol tags this surface emits.
var derpProtocols = []string{tunnelProtocolTag, frameProtocolTag}

// InjectToolDescription documents the derp_inject tool / injection target.
const InjectToolDescription = "Originate a DERP frame into an active tunnel (or, under relay mode, a fresh one) and capture it. Most useful for server->client frames a malicious relay could send (RECV_PACKET, PEER_GONE, PEER_PRESENT, HEALTH, RESTARTING, PONG)."

// InjectionTargetSchema is the payload the derp_inject tool / invoke_adapter accepts.
var InjectionTargetSchema = json.RawMessage(`{
  "type": "object",
  "required": ["frame"],
  "properties": {
    "tunnel_id": {"type": "string", "description": "flow_id of an active tunnel envelope; a fresh tunnel is opened (relay mode) when absent or unmatched"},
    "frame": {"type": "string", "description": "frame name to originate (e.g. RECV_PACKET, PEER_GONE, HEALTH), or a hex type like 0x99 for an arbitrary/unknown frame"},
    "direction": {"type": "string", "description": "which side to write to; defaults from frame, required for a hex/unknown frame"},
    "src_key": {"type": "string", "description": "source node key (as the frame requires)"},
    "dst_key": {"type": "string", "description": "destination node key (as the frame requires)"},
    "peer_key": {"type": "string", "description": "peer node key (as the frame requires)"},
    "reason": {"type": "integer", "description": "reason code for PEER_GONE"},
    "flags": {"type": "integer", "description": "flags for PEER_PRESENT"},
    "home": {"type": "boolean", "description": "home flag for NOTE_PREFERRED"},
    "reconnect_ms": {"type": "integer", "description": "reconnect delay for RESTARTING"},
    "try_for_ms": {"type": "integer", "description": "try-for duration for RESTARTING"},
    "body": {"type": "string", "description": "base64 payload for packet frames and PING/PONG tokens, UTF-8 for HEALTH"},
    "mutations": {"type": "array", "description": "mutation ops applied to the frame before sending"}
  }
}`)

// Protocols returns the DERP flow protocol tags.
func Protocols() []string { return slices.Clone(derpProtocols) }

// Handler is the DERP protocol surface: a full MITM of a DERP connection that terminates the protocol
// on both sides (relay) or runs a synthetic relay (terminate), capturing every frame as a flow.
type Handler struct {
	sidecar.BaseHandler
	baseCtx   context.Context // connection lifetime; roots handler-spawned work
	conn      *sidecar.Conn
	cfg       *DerpConfig
	name      string          // adapter name, for tunnel envelope paths
	serverKey key.NodePrivate // client-facing substitute/borrow server node key
	nodeKey   func(client string) (key.NodePrivate, error)

	relay *syntheticRelay // terminate-mode shared registry; nil under relay mode

	router *sidecar.StreamRouter // shared: accepts claimed streams, dials upstreams

	mu              sync.Mutex
	tunnels         map[string]*activeTunnel // keyed by tunnel envelope flow_id
	tunnelHosts     map[string]string        // upstream host retained past teardown for fresh-replay re-proxy
	tunnelHostOrder []string                 // insertion order for FIFO eviction
}

// NewHandler returns a DERP handler for the given connection. ctx bounds the
// connection lifetime and roots handler-spawned work.
func NewHandler(ctx context.Context, conn *sidecar.Conn, router *sidecar.StreamRouter, cfg *DerpConfig, name string, serverKey key.NodePrivate, nodeKey func(client string) (key.NodePrivate, error)) *Handler {
	h := &Handler{
		baseCtx:     ctx,
		conn:        conn,
		cfg:         cfg,
		name:        name,
		serverKey:   serverKey,
		nodeKey:     nodeKey,
		router:      router,
		tunnels:     map[string]*activeTunnel{},
		tunnelHosts: map[string]string{},
	}
	if cfg.RelayMode == RelayModeTerminate {
		h.relay = newSyntheticRelay(h)
	}
	return h
}

// ServeStream drives an accepted DERP stream: a relay-mode tunnel, or a
// terminate-mode synthetic relay endpoint.
func (h *Handler) ServeStream(ctx context.Context, sc *sidecar.StreamConn) {
	p := sc.Open()
	switch {
	case p.Path == derpPath:
		h.runTunnel(ctx, sc)
	case p.Path == "" && h.cfg.RelayMode == RelayModeTerminate:
		h.runTerminate(ctx, sc)
	default:
		_ = sc.Close()
	}
}
