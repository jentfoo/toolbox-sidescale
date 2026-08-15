package derp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"go4.org/mem"
	"tailscale.com/derp"
	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sidecar"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp/derpproto"
)

// keepAliveInterval is the server keepalive cadence under terminate mode.
const keepAliveInterval = 60 * time.Second

// runTerminate drives one client stream as a synthetic DERP relay endpoint,
// capturing and routing its frames between registered peers.
func (h *Handler) runTerminate(ctx context.Context, client *sidecar.StreamConn) {
	defer func() { _ = client.Close() }()
	p := client.Open()

	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		h.tunnelError(p.StreamID, "read derp upgrade", err)
		return
	}
	_ = req.Body.Close()
	if req.URL.Path != derpPath {
		h.tunnelError(p.StreamID, "derp upgrade path", fmt.Errorf("unexpected path %q", req.URL.Path))
		return
	}
	// always a normal 101; Derp-Fast-Start is treated as absent (never suppress it)
	if _, err := client.Write(upgradeResponse()); err != nil {
		h.tunnelError(p.StreamID, "write 101", err)
		return
	}

	clientFr := newFrameConn(client)
	clientFr.prefix(drainReader(br))

	if err := clientFr.WriteFrame(derpproto.FrameServerKey, derpproto.ServerKeyPayload(h.serverKey.Public())); err != nil {
		h.tunnelError(p.StreamID, "write server key", err)
		return
	}
	clientPub, clientInfo, clientBox, err := h.readClientInfo(clientFr)
	if err != nil {
		h.tunnelError(p.StreamID, "client info", err)
		return
	}

	// synthesize the server login response with no upstream
	serverInfo := &derp.ServerInfo{Version: derpproto.ProtocolVersion}
	siPayload, err := derpproto.ServerInfoPayload(h.serverKey, clientPub, serverInfo)
	if err != nil {
		h.tunnelError(p.StreamID, "seal server info", err)
		return
	}

	tunnelID, err := h.emitTunnelEnvelope(ctx, envelopeInfo{
		tunnelKey:  p.StreamID,
		clientAddr: p.PeerAddr,
		clientPub:  clientPub,
		clientInfo: clientInfo,
		serverInfo: serverInfo,
		relayMode:  RelayModeTerminate,
	})
	if err != nil {
		h.tunnelError(p.StreamID, "tunnel envelope", err)
		return
	}
	defer func() { _ = h.conn.CompleteFlow(context.Background(), tunnelID, nil, time.Now()) }()

	if err := clientFr.WriteFrame(derpproto.FrameServerInfo, siPayload); err != nil {
		h.tunnelError(p.StreamID, "write server info", err)
		return
	}
	// capture the login handshake frames for visibility
	if ci, err := json.Marshal(clientInfo); err == nil {
		_ = h.captureHandshakeFrame(ctx, tunnelID, derpproto.FrameClientInfo, clientPub, clientBox, ci, adapter.DirClientToServer)
	}
	if si, err := json.Marshal(serverInfo); err == nil {
		_ = h.captureHandshakeFrame(ctx, tunnelID, derpproto.FrameServerInfo, h.serverKey.Public(), siPayload, si, adapter.DirServerToClient)
	}

	c := h.relay.register(clientPub, clientFr, tunnelID, !clientInfo.MeshKey.IsZero())
	defer h.relay.remove(context.Background(), c)

	_ = h.conn.Log("info", "derp synthetic client joined", map[string]any{"flow_id": tunnelID, "node": clientPub.String()})

	stop := make(chan struct{})
	go h.terminateKeepAlive(ctx, tunnelID, clientFr, stop)
	defer close(stop)

	h.terminateLoop(ctx, tunnelID, c)
}

// terminateLoop reads each client frame, captures it, and drives the synthetic relay:
// routing packets to peers, answering pings, and dropping unroutable frames.
func (h *Handler) terminateLoop(ctx context.Context, tunnelID string, c *relayClient) {
	for {
		t, payload, err := c.fr.ReadTypedFrame()
		if err != nil {
			return
		}
		frame := derpproto.EncodeFrame(t, payload)
		out, err := h.captureFrame(ctx, tunnelID, frame, adapter.DirClientToServer)
		if err != nil {
			// a capture glitch must not tear down the whole synthetic-relay session
			h.tunnelError(tunnelID, "capture frame", err)
			out = frame
		}
		payload = derpproto.FramePayload(out) // route the possibly-mutated bytes
		switch t {
		case derpproto.FrameSendPacket:
			h.relay.route(ctx, c, payload)
		case derpproto.FramePing:
			h.emitAndWrite(ctx, tunnelID, c.fr, derpproto.FramePong, payload)
		default:
			// note-preferred, watch-conns, close-peer, and mesh forward-packet:
			// captured, not relayed
		}
	}
}

// emitAndWrite captures an originated server->client frame on tunnelID, then writes it
// (or its rule-mutated form) to fr. Capture failures are logged, not fatal, so the relay never stalls.
func (h *Handler) emitAndWrite(ctx context.Context, tunnelID string, fr *frameConn, t derpproto.FrameType, payload []byte) {
	frame := derpproto.EncodeFrame(t, payload)
	out, err := h.captureFrame(ctx, tunnelID, frame, adapter.DirServerToClient)
	if err != nil {
		h.tunnelError(tunnelID, "capture originated frame", err)
		out = frame
	}
	_, _ = fr.Write(out)
}

// terminateKeepAlive originates FrameKeepAlive on the server ticker until stop closes.
func (h *Handler) terminateKeepAlive(ctx context.Context, tunnelID string, fr *frameConn, stop <-chan struct{}) {
	tick := time.NewTicker(keepAliveInterval)
	defer tick.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
			h.emitAndWrite(ctx, tunnelID, fr, derpproto.FrameKeepAlive, nil)
		}
	}
}

// upgradeResponse is the synthesized 101 for a terminate-mode DERP upgrade.
func upgradeResponse() []byte {
	return []byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: " + derpUpgradeProto + "\r\n" +
		"Connection: Upgrade\r\n\r\n")
}

// relayClient is one connected client in the terminate-mode synthetic relay.
type relayClient struct {
	fr           *frameConn
	tunnelFlowID string
	clientKey    key.NodePublic // for SERVER_INFO re-seal to this client
	mesh         bool           // client presented a mesh key
	disabled     bool           // fighting dup set, receives no packets under disable_fighters
	// peers this client has received packets from, for PeerGone(Disconnected) on exit
	received map[key.NodePublic]struct{}
}

// clientSet holds every live connection sharing one node key and the active receive target.
type clientSet struct {
	active      *relayClient   // RecvPacket target; nil while a fighting set is disabled
	last        *relayClient   // most recent sender, drives active selection
	conns       []*relayClient // live connections, connect order (most recent last)
	sendHistory []*relayClient // senders in order, for disable_fighters detection
}

// syntheticRelay is the terminate-mode registry of connected clients keyed by node key,
// with best-effort packet routing between them.
type syntheticRelay struct {
	h               *Handler
	disableFighters bool // disable a dup key whose connections interleave sends
	mu              sync.Mutex
	byKey           map[key.NodePublic]*clientSet // node key -> connection set
	byTunnel        map[string]*relayClient       // tunnel flow_id -> connection
}

func newSyntheticRelay(h *Handler) *syntheticRelay {
	return &syntheticRelay{
		h:               h,
		disableFighters: h.cfg.DupPolicy == DupPolicyDisableFighters,
		byKey:           map[key.NodePublic]*clientSet{},
		byTunnel:        map[string]*relayClient{},
	}
}

// register adds a connection for k, makes it the active receive target, and returns it for remove.
func (r *syntheticRelay) register(k key.NodePublic, fr *frameConn, tunnelFlowID string, mesh bool) *relayClient {
	r.mu.Lock()
	defer r.mu.Unlock()

	c := &relayClient{fr: fr, tunnelFlowID: tunnelFlowID, clientKey: k, mesh: mesh, received: map[key.NodePublic]struct{}{}}
	cs := r.byKey[k]
	if cs == nil {
		cs = &clientSet{}
		r.byKey[k] = cs
	}
	cs.conns = append(cs.conns, c)
	cs.active, cs.last = c, c // newest connection receives, matching real DERP
	r.byTunnel[tunnelFlowID] = c
	return c
}

// byTunnelID returns the connection whose tunnel envelope is flowID, or nil.
func (r *syntheticRelay) byTunnelID(flowID string) *relayClient {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.byTunnel[flowID]
}

// remove drops c from the registry, promoting a survivor or announcing the key gone on the last departure.
func (r *syntheticRelay) remove(ctx context.Context, c *relayClient) {
	r.mu.Lock()
	delete(r.byTunnel, c.tunnelFlowID)
	cs := r.byKey[c.clientKey]
	var gone bool
	if cs != nil {
		cs.conns = slices.DeleteFunc(cs.conns, func(x *relayClient) bool { return x == c })
		if cs.last == c {
			cs.last = nil
		}
		switch len(cs.conns) {
		case 0:
			delete(r.byKey, c.clientKey)
			gone = true
		case 1:
			// collapse to a single connection: clear fighting state and re-enable
			s := cs.conns[0]
			s.disabled = false
			cs.active, cs.last, cs.sendHistory = s, s, nil
		default:
			// active follows the last writer while enabled, else the set stays inactive
			cs.active = nil
			if cs.last != nil && !cs.last.disabled {
				cs.active = cs.last
			}
		}
	}
	r.mu.Unlock()
	if gone {
		r.announceGone(ctx, c.clientKey)
	}
}

// route delivers src's SendPacket to the addressed peer as RecvPacket, capturing the
// delivered frame on the peer's tunnel. An unknown destination that carries a disco
// payload gets a PeerGone(NotHere) back to the sender; other misses are dropped.
func (r *syntheticRelay) route(ctx context.Context, src *relayClient, payload []byte) {
	if len(payload) < key.NodePublicRawLen {
		return
	}
	dst := key.NodePublicFromRaw32(mem.B(payload[:key.NodePublicRawLen]))
	packet := payload[key.NodePublicRawLen:]

	r.mu.Lock()
	r.noteActivity(src)
	dcs := r.byKey[dst]
	var peer *relayClient
	if dcs != nil {
		peer = dcs.active
	}
	if peer != nil {
		peer.received[src.clientKey] = struct{}{} // recorded under the lookup lock
	}
	r.mu.Unlock()

	if peer == nil {
		// NotHere only when the key has no connections; a disabled dup set drops silently
		if dcs == nil && derpproto.IsDisco(packet) {
			r.h.emitAndWrite(ctx, src.tunnelFlowID, src.fr, derpproto.FramePeerGone, peerGonePayload(dst, derp.PeerGoneReasonNotHere))
		}
		return
	}
	recv := append(src.clientKey.AppendTo(make([]byte, 0, key.NodePublicRawLen+len(packet))), packet...)
	r.h.emitAndWrite(ctx, peer.tunnelFlowID, peer.fr, derpproto.FrameRecvPacket, recv)
}

// noteActivity updates the active receiver for src's dup set and, under disable_fighters,
// disables the whole set when its connections interleave sends. Caller holds r.mu.
func (r *syntheticRelay) noteActivity(src *relayClient) {
	cs := r.byKey[src.clientKey]
	if cs == nil || len(cs.conns) < 2 || src.disabled {
		return
	}
	if !r.disableFighters {
		cs.last, cs.active = src, src // last writer receives
		return
	}
	if cs.last == nil {
		cs.last, cs.active = src, src // first speaker receives
	}
	if len(cs.sendHistory) > 0 && cs.sendHistory[len(cs.sendHistory)-1] == src {
		return // already the last sender
	}
	if slices.Contains(cs.sendHistory, src) { // interleaved senders => fighting
		for _, x := range cs.conns {
			x.disabled = true
		}
		cs.active = nil
	}
	cs.sendHistory = append(cs.sendHistory, src)
}

// announceGone synthesizes PeerGone(Disconnected) to every connection that had received packets from the departing key.
func (r *syntheticRelay) announceGone(ctx context.Context, gone key.NodePublic) {
	r.mu.Lock()
	var targets []*relayClient
	for _, c := range r.byTunnel {
		if _, ok := c.received[gone]; ok {
			targets = append(targets, c)
			delete(c.received, gone)
		}
	}
	r.mu.Unlock()
	for _, c := range targets {
		r.h.emitAndWrite(ctx, c.tunnelFlowID, c.fr, derpproto.FramePeerGone, peerGonePayload(gone, derp.PeerGoneReasonDisconnected))
	}
}

// peerGonePayload builds a FramePeerGone payload: 32-B peer key + 1-B reason.
func peerGonePayload(peer key.NodePublic, reason derp.PeerGoneReasonType) []byte {
	return append(peer.AppendTo(make([]byte, 0, key.NodePublicRawLen+1)), byte(reason))
}
