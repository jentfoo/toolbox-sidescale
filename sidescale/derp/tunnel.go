package derp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"tailscale.com/derp"
	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"

	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp/derpproto"
)

const (
	tunnelProtocolTag = "tailscale.derp.tunnel"
	frameProtocolTag  = "tailscale.derp.frame"

	// derpUpgradeProto is the HTTP Upgrade token for the DERP protocol.
	derpUpgradeProto = "DERP"

	// upstreamHandshakeTimeout bounds the upstream DERP handshake reads; the real
	// server enforces a 10-s deadline over its greeting and client-info steps.
	upstreamHandshakeTimeout = 10 * time.Second
)

// maxRetainedTunnelHosts bounds the fresh-replay host record so tunnel churn can't grow it without limit.
const maxRetainedTunnelHosts = 256

// activeTunnel is a live DERP tunnel retained for teardown and (relay) frame bridging.
type activeTunnel struct {
	flowID      string
	clientKey   key.NodePublic
	client      *sidecar.StreamConn
	clientFr    *frameConn
	upstream    *sidecar.StreamConn // nil under terminate
	upstreamF   *frameConn          // nil under terminate
	upstreamID  string
	nodeKey     key.NodePrivate // this tunnel's upstream client key (CLIENT_INFO re-seal)
	upstreamPub key.NodePublic  // real upstream server key (CLIENT_INFO re-seal target)
	mesh        bool            // client presented a mesh key
	host        string          // upstream host, for fresh-replay re-proxy
}

func (h *Handler) registerTunnel(id string, t *activeTunnel) {
	h.mu.Lock()
	h.tunnels[id] = t
	h.retainTunnelHost(id, t.host)
	h.mu.Unlock()
}

// retainTunnelHost records a tunnel's upstream host for later fresh-replay re-proxy. Caller holds h.mu.
func (h *Handler) retainTunnelHost(id, host string) {
	if _, ok := h.tunnelHosts[id]; !ok {
		if len(h.tunnelHosts) >= maxRetainedTunnelHosts && len(h.tunnelHostOrder) > 0 {
			oldest := h.tunnelHostOrder[0]
			h.tunnelHostOrder = h.tunnelHostOrder[1:]
			delete(h.tunnelHosts, oldest)
		}
		h.tunnelHostOrder = append(h.tunnelHostOrder, id)
	}
	h.tunnelHosts[id] = host
}

// getTunnel returns the live tunnel registered under a tunnel-envelope flow_id, or nil.
func (h *Handler) getTunnel(id string) *activeTunnel {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.tunnels[id]
}

// retainedTunnelHost returns the upstream host of a (possibly torn-down) tunnel.
func (h *Handler) retainedTunnelHost(id string) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	host, ok := h.tunnelHosts[id]
	return host, ok
}

func (h *Handler) deregisterTunnel(id string) {
	h.mu.Lock()
	delete(h.tunnels, id)
	h.mu.Unlock()
}

// runTunnel drives one client-facing /derp stream into a full bidirectional DERP MITM, capturing every bridged frame.
func (h *Handler) runTunnel(ctx context.Context, client *sidecar.StreamConn) {
	defer func() { _ = client.Close() }()
	p := client.Open()

	host := p.Host
	clientFr := newFrameConn(client)

	// client-facing handshake: server greeting, then read + open the client's box
	if err := clientFr.WriteFrame(derpproto.FrameServerKey, derpproto.ServerKeyPayload(h.serverKey.Public())); err != nil {
		h.tunnelError(p.StreamID, "write server key", err)
		return
	}
	clientPub, clientInfo, clientBox, err := h.readClientInfo(clientFr)
	if err != nil {
		h.tunnelError(p.StreamID, "client info", err)
		return
	}

	// upstream handshake as a DERP client
	nodeKey, err := h.nodeKey(clientPub.String())
	if err != nil {
		h.tunnelError(p.StreamID, "node identity", err)
		return
	}
	up, err := h.openUpstream(ctx, host, nodeKey, clientInfo)
	if err != nil {
		h.tunnelError(p.StreamID, "open upstream", err)
		return
	}
	defer up.close()

	tunnelID, err := h.emitTunnelEnvelope(ctx, envelopeInfo{
		parentFlowID: p.RequestFlowID,
		tunnelKey:    p.StreamID,
		clientAddr:   p.PeerAddr,
		upstreamAddr: up.addr,
		clientPub:    clientPub,
		clientInfo:   clientInfo,
		serverInfo:   up.serverInfo,
		upstreamPub:  up.serverPub,
		nodeKey:      nodeKey.Public(),
		relayMode:    RelayModeRelay,
	})
	if err != nil {
		h.tunnelError(p.StreamID, "tunnel envelope", err)
		return
	}
	defer func() { _ = h.conn.CompleteFlow(context.Background(), tunnelID, nil, time.Now()) }()

	h.registerTunnel(tunnelID, &activeTunnel{
		flowID:      tunnelID,
		clientKey:   clientPub,
		client:      client,
		clientFr:    clientFr,
		upstream:    up.stream,
		upstreamF:   up.fr,
		upstreamID:  up.streamID,
		nodeKey:     nodeKey,
		upstreamPub: up.serverPub,
		mesh:        !clientInfo.MeshKey.IsZero(),
		host:        host,
	})
	defer h.deregisterTunnel(tunnelID)

	// seal the upstream ServerInfo to the client to complete its login
	siPayload, err := derpproto.ServerInfoPayload(h.serverKey, clientPub, up.serverInfo)
	if err != nil {
		h.tunnelError(p.StreamID, "seal server info", err)
		return
	} else if err := clientFr.WriteFrame(derpproto.FrameServerInfo, siPayload); err != nil {
		h.tunnelError(p.StreamID, "write server info", err)
		return
	}

	// capture the login handshake frames for visibility (boxes re-sealed above)
	if ci, err := json.Marshal(clientInfo); err == nil {
		_ = h.captureHandshakeFrame(ctx, tunnelID, derpproto.FrameClientInfo, clientPub, clientBox, ci, adapter.DirClientToServer)
	}
	if si, err := json.Marshal(up.serverInfo); err == nil {
		_ = h.captureHandshakeFrame(ctx, tunnelID, derpproto.FrameServerInfo, up.serverPub, up.serverInfoBox, si, adapter.DirServerToClient)
	}

	_ = h.conn.Log("info", "derp tunnel established", map[string]any{"flow_id": tunnelID, "host": host})

	// bridge frames both directions until either side closes
	done := make(chan struct{}, 2)
	go h.pumpFrames(ctx, tunnelID, up.fr, clientFr, adapter.DirServerToClient, done)
	go h.pumpFrames(ctx, tunnelID, clientFr, up.fr, adapter.DirClientToServer, done)
	<-done
}

// pumpFrames reads complete frames off src, captures each under tunnelID with the
// given source direction, and forwards the (possibly mutated) frame to dst. A capture
// failure logs and forwards the original bytes rather than tearing down the tunnel.
func (h *Handler) pumpFrames(ctx context.Context, tunnelID string, src, dst *frameConn, dir string, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	for {
		frame, err := src.ReadFrame()
		if err != nil {
			return
		}
		out, err := h.captureFrame(ctx, tunnelID, frame, dir)
		if err != nil {
			// a capture glitch must not tear down a live tunnel
			h.tunnelError(tunnelID, "capture frame", err)
			out = frame
		}
		if _, err := dst.Write(out); err != nil {
			return
		}
	}
}

// readClientInfo reads the client's FrameClientInfo, opens it with the server key, and
// returns the recovered node key, ClientInfo, and the raw box (for capture fidelity).
func (h *Handler) readClientInfo(fr *frameConn) (key.NodePublic, *derp.ClientInfo, []byte, error) {
	t, payload, err := fr.ReadTypedFrame()
	if err != nil {
		return key.NodePublic{}, nil, nil, err
	}
	if t != derpproto.FrameClientInfo {
		return key.NodePublic{}, nil, nil, fmt.Errorf("derp: expected client info, got %s", derpproto.FrameName(t))
	}
	clientPub, info, err := derpproto.OpenClientInfo(h.serverKey, payload)
	if err != nil {
		return key.NodePublic{}, nil, nil, err
	}
	var box []byte
	if len(payload) >= key.NodePublicRawLen {
		box = payload[key.NodePublicRawLen:]
	}
	return clientPub, info, box, nil
}

// upstreamTunnel bundles the established upstream (server-facing) half of a DERP tunnel.
type upstreamTunnel struct {
	streamID      string
	stream        *sidecar.StreamConn
	fr            *frameConn
	serverPub     key.NodePublic
	serverInfo    *derp.ServerInfo
	serverInfoBox []byte
	addr          string
}

func (u *upstreamTunnel) close() {
	if u.stream != nil {
		_ = u.stream.Close()
	}
}

// openUpstream dials the real DERP server and completes the DERP login as a client using nodeKey.
func (h *Handler) openUpstream(ctx context.Context, host string, nodeKey key.NodePrivate, clientInfo *derp.ClientInfo) (*upstreamTunnel, error) {
	dialHost, dialPort, useTLS := h.upstreamDial(host)
	var tlsSpec *wire.DialUpstreamTLS
	if useTLS {
		tlsSpec = &wire.DialUpstreamTLS{Enabled: true, SNI: dialHost, ALPN: []string{"http/1.1"}}
	}
	stream, err := h.router.DialUpstream(ctx, wire.DialUpstreamParams{
		Host: dialHost,
		Port: dialPort,
		TLS:  tlsSpec,
	})
	if err != nil {
		return nil, fmt.Errorf("dial upstream: %w", err)
	}
	streamID := stream.StreamID()
	var ok bool
	defer func() {
		if !ok {
			_ = stream.Close()
		}
	}()

	if _, err := stream.Write(buildUpgradeRequest(dialHost)); err != nil {
		return nil, fmt.Errorf("write upgrade: %w", err)
	}

	// bound the handshake reads; cleared once established so the frame phase is unbounded
	_ = stream.SetReadDeadline(time.Now().Add(upstreamHandshakeTimeout))

	br := bufio.NewReader(stream)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, fmt.Errorf("read upgrade response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("upstream upgrade status %s", resp.Status)
	}

	// bytes br buffered past the 101 belong to the frame stream; preserve them
	fr := newFrameConn(stream)
	fr.prefix(drainReader(br))

	serverPub, err := h.readUpstreamServerKey(fr)
	if err != nil {
		return nil, err
	}
	ci := &derp.ClientInfo{Version: derpproto.ProtocolVersion, MeshKey: clientInfo.MeshKey, CanAckPings: clientInfo.CanAckPings, IsProber: clientInfo.IsProber}
	ciPayload, err := derpproto.ClientInfoPayload(nodeKey, serverPub, ci)
	if err != nil {
		return nil, fmt.Errorf("seal client info: %w", err)
	}
	if err := fr.WriteFrame(derpproto.FrameClientInfo, ciPayload); err != nil {
		return nil, fmt.Errorf("write client info: %w", err)
	}
	serverInfo, siBox, err := h.readUpstreamServerInfo(fr, nodeKey, serverPub)
	if err != nil {
		return nil, err
	}
	_ = stream.SetReadDeadline(time.Time{})
	ok = true

	_ = h.conn.Log("info", "derp upstream connected", map[string]any{
		"stream": streamID, "host": dialHost, "node_key": adapter.KeyPrefix(nodeKey.Public().String()),
	})
	return &upstreamTunnel{
		streamID:      streamID,
		stream:        stream,
		fr:            fr,
		serverPub:     serverPub,
		serverInfo:    serverInfo,
		serverInfoBox: siBox,
		addr:          net.JoinHostPort(dialHost, strconv.Itoa(dialPort)),
	}, nil
}

// readUpstreamServerKey reads the real server's FrameServerKey greeting.
func (h *Handler) readUpstreamServerKey(fr *frameConn) (key.NodePublic, error) {
	t, payload, err := fr.ReadTypedFrame()
	if err != nil {
		return key.NodePublic{}, fmt.Errorf("read server key: %w", err)
	}
	if t != derpproto.FrameServerKey {
		return key.NodePublic{}, fmt.Errorf("derp: expected server key, got %s", derpproto.FrameName(t))
	}
	return derpproto.ParseServerKey(payload)
}

// readUpstreamServerInfo reads and opens the real server's FrameServerInfo, returning
// the decoded info and the raw box (for capture fidelity).
func (h *Handler) readUpstreamServerInfo(fr *frameConn, nodeKey key.NodePrivate, serverPub key.NodePublic) (*derp.ServerInfo, []byte, error) {
	t, payload, err := fr.ReadTypedFrame()
	if err != nil {
		return nil, nil, fmt.Errorf("read server info: %w", err)
	}
	if t != derpproto.FrameServerInfo {
		return nil, nil, fmt.Errorf("derp: expected server info, got %s", derpproto.FrameName(t))
	}
	info, err := derpproto.OpenServerInfo(nodeKey, serverPub, payload)
	if err != nil {
		return nil, nil, err
	}
	return info, payload, nil
}

// upstreamDial resolves the dial target, honoring upstream_overrides. TLS is used unless an
// override selects the http scheme.
func (h *Handler) upstreamDial(host string) (dialHost string, port int, useTLS bool) {
	t := adapter.ResolveUpstream(host, h.cfg.UpstreamOverrides[host], h.cfg.DerpHosts, "https")
	return t.Host, t.Port, t.Scheme == "https"
}

// buildUpgradeRequest builds the upstream GET /derp upgrade (no Derp-Fast-Start, so the
// real key is read off the stream, not a metacert).
func buildUpgradeRequest(host string) []byte {
	return []byte("GET " + derpPath + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: " + derpUpgradeProto + "\r\n" +
		"Connection: Upgrade\r\n\r\n")
}

// envelopeInfo carries the tunnel-envelope flow fields.
type envelopeInfo struct {
	parentFlowID string
	tunnelKey    string
	clientAddr   string
	upstreamAddr string // zero under terminate
	clientPub    key.NodePublic
	clientInfo   *derp.ClientInfo
	serverInfo   *derp.ServerInfo
	upstreamPub  key.NodePublic // zero under terminate
	nodeKey      key.NodePublic // zero under terminate
	relayMode    string
}

// emitTunnelEnvelope pushes the tunnel-envelope flow and returns its flow_id, used as
// parent_flow_id for every frame flow.
func (h *Handler) emitTunnelEnvelope(ctx context.Context, in envelopeInfo) (string, error) {
	meshFlag := strconv.FormatBool(!in.clientInfo.MeshKey.IsZero())
	headers := []wire.Header{
		{Name: "X-Derp-Protocol-Version", Value: strconv.Itoa(derpproto.ProtocolVersion)},
		{Name: "X-Derp-Transport", Value: "http-upgrade"},
		{Name: "X-Derp-Relay-Mode", Value: in.relayMode},
		{Name: "X-Derp-Client-Facing-Server-Pubkey", Value: h.serverKey.Public().String()},
		{Name: "X-Derp-Client-Node-Pubkey", Value: in.clientPub.String()},
		{Name: "X-Derp-Mesh", Value: meshFlag},
		{Name: "X-Derp-Client-Addr", Value: in.clientAddr},
	}
	if ci, err := json.Marshal(in.clientInfo); err == nil {
		headers = append(headers, wire.Header{Name: "X-Derp-Client-Info", Value: string(ci)})
	}
	if in.serverInfo != nil {
		if si, err := json.Marshal(in.serverInfo); err == nil {
			headers = append(headers, wire.Header{Name: "X-Derp-Server-Info", Value: string(si)})
		}
	}
	if in.relayMode == RelayModeRelay {
		headers = append(headers,
			wire.Header{Name: "X-Derp-Server-Facing-Server-Pubkey", Value: in.upstreamPub.String()},
			wire.Header{Name: "X-Derp-Sidecar-Node-Pubkey", Value: in.nodeKey.String()},
			wire.Header{Name: "X-Derp-Upstream-Addr", Value: in.upstreamAddr},
		)
	}
	return h.conn.PushFlow(ctx, wire.Flow{
		ProtocolTag:  tunnelProtocolTag,
		Direction:    adapter.DirBidirectional,
		ParentFlowID: in.parentFlowID,
		Request: &wire.FlowMessage{
			Method:  "TUNNEL",
			Path:    "/" + h.name + "/derp/tunnel/" + in.tunnelKey,
			Headers: headers,
		},
		StartedAt: time.Now(),
	})
}

func (h *Handler) tunnelError(streamID, stage string, err error) {
	_ = h.conn.Log("error", "derp tunnel failed: "+stage,
		map[string]any{"stream": streamID, "error": err.Error()})
}

// frameConn buffers a StreamConn's bytes into complete DERP frames on read and encodes frames on write.
type frameConn struct {
	conn net.Conn
	re   sidecar.Reassembler
	// set when an oversized length prefix tears the stream down at the buffering seam,
	// before unbounded bytes accumulate
	frameErr error
}

func newFrameConn(conn net.Conn) *frameConn { return &frameConn{conn: conn} }

// prefix seeds the reassembler with bytes buffered ahead of the frame stream.
func (fc *frameConn) prefix(b []byte) {
	if len(b) > 0 {
		fc.re.Append(b)
	}
}

func (fc *frameConn) split(buf []byte) (int, bool) {
	n, ok, err := derpproto.SplitFrame(buf)
	if err != nil {
		fc.frameErr = err
		return 0, false
	}
	return n, ok
}

// ReadFrame returns the next complete wire frame (header + payload).
func (fc *frameConn) ReadFrame() ([]byte, error) {
	for {
		if frame, ok := fc.re.Next(fc.split); ok {
			return frame, nil
		}
		if fc.frameErr != nil {
			return nil, fc.frameErr
		}
		buf := make([]byte, 32*1024)
		n, err := fc.conn.Read(buf)
		if n > 0 {
			fc.re.Append(buf[:n])
		}
		if err != nil {
			return nil, err
		}
	}
}

// ReadTypedFrame reads the next frame and splits its type and payload.
func (fc *frameConn) ReadTypedFrame() (derpproto.FrameType, []byte, error) {
	frame, err := fc.ReadFrame()
	if err != nil {
		return 0, nil, err
	}
	t, _, ok := derpproto.FrameHeader(frame)
	if !ok {
		return 0, nil, errors.New("derp: short frame")
	}
	return t, derpproto.FramePayload(frame), nil
}

// WriteFrame encodes and writes one frame.
func (fc *frameConn) WriteFrame(t derpproto.FrameType, payload []byte) error {
	_, err := fc.conn.Write(derpproto.EncodeFrame(t, payload))
	return err
}

// Write sends already-encoded frame bytes.
func (fc *frameConn) Write(frame []byte) (int, error) { return fc.conn.Write(frame) }

// drainReader returns the bytes a bufio.Reader has buffered without blocking.
func drainReader(br *bufio.Reader) []byte {
	n := br.Buffered()
	if n == 0 {
		return nil
	}
	b, _ := br.Peek(n)
	out := make([]byte, len(b))
	copy(out, b)
	_, _ = br.Discard(n)
	return out
}
