package noise

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

const (
	// coreAdapter is the reserved native-proxy adapter name for invoke_adapter.
	coreAdapter = "sectool"
	// noiseProtocolName is the control-plane Noise variant.
	noiseProtocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s"

	tunnelProtocolTag  = "tailscale.tunnel"
	controlProtocolTag = "tailscale.control"
	streamProtocolTag  = "tailscale.control.map.stream"
)

// upstreamHandshakeTimeout bounds the upstream ts2021/Noise handshake reads.
const upstreamHandshakeTimeout = 30 * time.Second

// earlyNoise holds a forwarded EarlyNoise frame and its parsed payload.
type earlyNoise struct {
	raw []byte
	msg *tailcfg.EarlyNoise
}

// runTunnel drives one client-facing ts2021 stream into a full bidirectional Noise
// MITM: it completes the client responder handshake, dials and handshakes upstream,
// emits the tunnel envelope, then bridges inner HTTP/2 until the client closes.
func (h *Handler) runTunnel(ctx context.Context, sc *sidecar.StreamConn, init []byte) {
	defer func() { _ = sc.Close() }()
	p := sc.Open()

	controlHost := p.Host
	if controlHost == "" {
		controlHost = h.controlHost
	}
	version, err := tsproto.InitiationVersion(init)
	if err != nil {
		h.tunnelError(p.StreamID, "read initiation version", err)
		return
	}

	innerClient, err := tsproto.Responder(ctx, sc, h.responderKey, init)
	if err != nil {
		h.tunnelError(p.StreamID, "client responder handshake", err)
		return
	}
	defer func() { _ = innerClient.Close() }()

	machineKey, err := h.machineKey(innerClient.Peer().String())
	if err != nil {
		h.tunnelError(p.StreamID, "machine identity", err)
		return
	}

	u, err := h.getOrCreateUpstream(ctx, controlHost, machineKey, version, h.poolSession(p.StreamID))
	if err != nil {
		h.tunnelError(p.StreamID, "open upstream", err)
		return
	}
	at := &activeTunnel{
		up:           u,
		bridge:       u.uc.bridge,
		controlHost:  controlHost,
		serverPub:    u.uc.serverPub,
		serverLegacy: u.uc.serverLegacy,
		machineKey:   machineKey,
		version:      version,
		session:      h.poolSession(p.StreamID),
	}
	// release whichever upstream the tunnel is bound to at close, healed or not
	defer func() { cur, _ := at.current(); h.releaseUpstream(cur) }()

	tunnelID, err := h.emitTunnelEnvelope(ctx, envelopeInfo{
		parentFlowID: p.RequestFlowID,
		tunnelKey:    p.StreamID,
		clientAddr:   p.PeerAddr,
		upstreamAddr: u.uc.addr,
		version:      version,
		client:       innerClient,
		upstream:     u.uc.inner,
		serverPub:    u.uc.serverPub,
		machineKey:   machineKey,
		early:        u.uc.early,
	})
	if err != nil {
		h.tunnelError(p.StreamID, "tunnel envelope", err)
		return
	}
	// complete the envelope on every subsequent exit so it is never left in-flight;
	// teardown must not ride the base context, which may be cancelled
	defer func() { _ = h.conn.CompleteFlow(context.Background(), tunnelID, nil, time.Now()) }()

	at.flowID = tunnelID
	h.registerTunnel(tunnelID, at)
	defer h.deregisterTunnel(tunnelID)

	// forward the server EarlyNoise to the client before HTTP/2, per the configured
	// mode (forward verbatim / suppress / replace with a synthesized challenge)
	early, err := h.clientEarlyNoise(u.uc.early)
	if err != nil {
		h.tunnelError(p.StreamID, "build early noise", err)
		return
	}
	if len(early) > 0 {
		if _, err := innerClient.Write(early); err != nil {
			h.tunnelError(p.StreamID, "forward early noise", err)
			return
		}
	}

	_ = h.conn.Log("info", "tunnel established", map[string]any{"flow_id": tunnelID, "control_host": controlHost})
	u.uc.bridge.ServeCapture(innerClient, h.captureInner(ctx, at))
}

// clientEarlyNoise returns the EarlyNoise bytes to forward to the client per the
// configured mode: the upstream frame verbatim (forward), nothing (suppress), or a
// synthesized frame with a fresh per-tunnel challenge (replace).
func (h *Handler) clientEarlyNoise(up earlyNoise) ([]byte, error) {
	switch h.cfg.EarlyNoise {
	case EarlyNoiseSuppress:
		return nil, nil
	case EarlyNoiseReplace:
		return tsproto.EncodeEarlyNoise(&tailcfg.EarlyNoise{NodeKeyChallenge: key.NewChallenge().Public()})
	default:
		return up.raw, nil
	}
}

// upstreamConn bundles the established upstream (server-facing) half of a Noise
// tunnel: the decrypted Noise conn, the HTTP/2 bridge over it, and metadata.
type upstreamConn struct {
	streamID     string
	stream       *sidecar.StreamConn
	inner        *controlbase.Conn
	bridge       *tsproto.H2Bridge
	serverPub    key.MachinePublic
	serverLegacy key.MachinePublic
	early        earlyNoise
	addr         string
}

func (u *upstreamConn) close() {
	_ = u.bridge.Close()
	_ = u.inner.Close()
	if u.stream != nil {
		_ = u.stream.Close()
	}
}

// openUpstream dials the real control server, completes the upstream Noise IK
// handshake as initiator with machineKey, and builds the HTTP/2 bridge over it.
// Shared by the client-driven tunnel and the replay/injection fresh-tunnel paths.
func (h *Handler) openUpstream(ctx context.Context, controlHost string, machineKey key.MachinePrivate, version uint16, parentFlowID string) (*upstreamConn, error) {
	serverPub, err := h.upstreamServerKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("upstream key: %w", err)
	}
	serverLegacy, err := h.upstreamLegacyKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("upstream legacy key: %w", err)
	}
	dialHost, dialPort, scheme := h.upstreamDial(controlHost)
	// http scheme dials plaintext (TLS nil); the ts2021 upgrade is cleartext either way
	var dialTLS *wire.DialUpstreamTLS
	if scheme == UpstreamSchemeHTTPS {
		dialTLS = &wire.DialUpstreamTLS{Enabled: true, SNI: dialHost, ALPN: []string{"http/1.1"}}
	}
	upstream, err := h.router.DialUpstream(ctx, wire.DialUpstreamParams{
		Host:         dialHost,
		Port:         dialPort,
		TLS:          dialTLS,
		ParentFlowID: parentFlowID,
	})
	if err != nil {
		return nil, fmt.Errorf("dial upstream: %w", err)
	}
	upstreamInner, bridgeConn, early, err := h.upstreamHandshake(ctx, upstream, dialHost, machineKey, serverPub, version)
	if err != nil {
		_ = upstream.Close()
		return nil, fmt.Errorf("upstream handshake: %w", err)
	}
	bridge, err := tsproto.NewH2Bridge(bridgeConn)
	if err != nil {
		_ = upstreamInner.Close()
		_ = upstream.Close()
		return nil, fmt.Errorf("upstream http2: %w", err)
	}
	return &upstreamConn{
		streamID:     upstream.StreamID(),
		stream:       upstream,
		inner:        upstreamInner,
		bridge:       bridge,
		serverPub:    serverPub,
		serverLegacy: serverLegacy,
		early:        early,
		addr:         net.JoinHostPort(dialHost, strconv.Itoa(dialPort)),
	}, nil
}

// activeTunnel is a live Noise tunnel retained for replay-reuse and injection by
// tunnel_id. The bridge's upstream HTTP/2 client is safe for concurrent RoundTrip,
// so replayed/injected requests ride the same connection as the client's traffic.
// up/bridge are swapped in place when the upstream conn dies and the tunnel heals onto
// a fresh one; mu is a leaf lock never held while calling into h.mu.
type activeTunnel struct {
	mu           sync.Mutex      // guards up/bridge across a heal swap
	up           *sharedUpstream // current pooled upstream backing bridge; nil in tests
	bridge       *tsproto.H2Bridge
	controlHost  string
	serverPub    key.MachinePublic
	serverLegacy key.MachinePublic
	machineKey   key.MachinePrivate
	version      uint16
	session      string // pool discriminator, to re-dial on heal
	flowID       string
	healFailed   bool // guards the wedge signal to one line per dead-upstream episode
}

// current returns the tunnel's live upstream and bridge for forwarding.
func (at *activeTunnel) current() (*sharedUpstream, *tsproto.H2Bridge) {
	at.mu.Lock()
	defer at.mu.Unlock()
	return at.up, at.bridge
}

// forwardTunnel forwards req over the tunnel's current upstream, healing onto a fresh
// conn when the current one is unusable. The failed request is not retried.
func (h *Handler) forwardTunnel(ctx context.Context, at *activeTunnel, req *http.Request) (*http.Response, error) {
	up, bridge := at.current()
	resp, err := bridge.Forward(req)
	if err != nil && up != nil && !bridge.Usable() {
		h.healUpstream(ctx, at, up, err.Error())
	}
	return resp, err
}

// healUpstream swaps a bound tunnel off the dead upstream (evicted for reason) onto a freshly
// dialed one, so the next forward recovers. Compare-and-swap on at.up heals concurrent requests once.
func (h *Handler) healUpstream(ctx context.Context, at *activeTunnel, dead *sharedUpstream, reason string) {
	at.mu.Lock()
	stale := at.up == dead
	at.mu.Unlock()
	if !stale { // a concurrent request already healed
		return
	}

	h.evictUpstream(dead, reason) // idempotent; frees the pool key so re-dial builds fresh
	fresh, err := h.getOrCreateUpstream(ctx, at.controlHost, at.machineKey, at.version, at.session)
	if err != nil {
		// leave at.up on dead; the next forward re-attempts the heal
		at.mu.Lock()
		firstFail := !at.healFailed
		at.healFailed = true
		at.mu.Unlock()
		if firstFail { // one-shot: name the wedge once, not per failed poll
			_ = h.conn.Log("warn", "upstream heal dial failed", map[string]any{"flow_id": at.flowID, "error": err.Error()})
		}
		return
	}

	at.mu.Lock()
	if at.up != dead { // lost the race; drop our fresh ref
		at.mu.Unlock()
		h.releaseUpstream(fresh)
		return
	}
	at.up, at.bridge, at.healFailed = fresh, fresh.uc.bridge, false
	at.mu.Unlock()
	h.releaseUpstream(dead) // return the ref the tunnel held on the dead conn
	_ = h.conn.Log("info", "upstream healed", map[string]any{"flow_id": at.flowID, "stream": fresh.uc.streamID})
}

func (h *Handler) registerTunnel(id string, t *activeTunnel) {
	h.mu.Lock()
	h.tunnels[id] = t
	h.mu.Unlock()
}

func (h *Handler) deregisterTunnel(id string) {
	h.mu.Lock()
	delete(h.tunnels, id)
	h.mu.Unlock()
}

func (h *Handler) getTunnel(id string) *activeTunnel {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.tunnels[id]
}

// openFreshTunnel opens a new upstream Noise tunnel with no client-facing side, at the
// given capability version, for the replay fresh-tunnel fallback and injection into a
// fresh tunnel. It registers the activeTunnel and returns a cleanup that deregisters it,
// two-phase completes the envelope, and tears down the upstream.
func (h *Handler) openFreshTunnel(ctx context.Context, controlHost string, machineKey key.MachinePrivate, version uint16, session string) (*activeTunnel, func(), error) {
	u, err := h.getOrCreateUpstream(ctx, controlHost, machineKey, version, session)
	if err != nil {
		return nil, nil, err
	}
	tunnelID, err := h.emitTunnelEnvelope(ctx, envelopeInfo{
		tunnelKey:    u.uc.streamID,
		upstreamAddr: u.uc.addr,
		version:      version,
		upstream:     u.uc.inner,
		serverPub:    u.uc.serverPub,
		machineKey:   machineKey,
		early:        u.uc.early,
	})
	if err != nil {
		h.releaseUpstream(u)
		return nil, nil, fmt.Errorf("tunnel envelope: %w", err)
	}
	at := &activeTunnel{
		up:           u,
		bridge:       u.uc.bridge,
		controlHost:  controlHost,
		serverPub:    u.uc.serverPub,
		serverLegacy: u.uc.serverLegacy,
		machineKey:   machineKey,
		version:      version,
		session:      session,
		flowID:       tunnelID,
	}
	h.registerTunnel(tunnelID, at)
	cleanup := func() {
		h.deregisterTunnel(tunnelID)
		// teardown must not ride the request context, which may be cancelled
		_ = h.conn.CompleteFlow(context.Background(), tunnelID, nil, time.Now())
		// release the current upstream, which may have healed onto a fresh conn
		cur, _ := at.current()
		h.releaseUpstream(cur)
	}
	return at, cleanup, nil
}

// upstreamServerKey resolves the real upstream server Noise key: the borrowed key's
// public half, or the substitute strategy's fetched-and-cached upstream key.
func (h *Handler) upstreamServerKey(ctx context.Context) (key.MachinePublic, error) {
	if h.cfg.KeyStrategy == KeyStrategyBorrow {
		return h.responderKey.Public(), nil
	}
	return h.keysub.realServerKey(ctx)
}

// upstreamLegacyKey resolves the real upstream legacy machine key bound by the register SignatureV2 hash.
// Zero under borrow, where operator-controlled upstreams do not use device-cert SignatureV2.
func (h *Handler) upstreamLegacyKey(ctx context.Context) (key.MachinePublic, error) {
	if h.cfg.KeyStrategy == KeyStrategyBorrow {
		return key.MachinePublic{}, nil
	}
	return h.keysub.realLegacyServerKey(ctx)
}

// upstreamDial resolves the dial target and transport scheme, honoring upstream_overrides and the
// configured upstream_scheme. The returned scheme (http/https) tells the caller whether to terminate TLS upstream.
func (h *Handler) upstreamDial(controlHost string) (host string, port int, scheme string) {
	scheme = UpstreamSchemeHTTPS
	if h.cfg.UpstreamScheme == UpstreamSchemeHTTP {
		scheme = UpstreamSchemeHTTP
	}
	t := adapter.ResolveUpstream(controlHost, h.cfg.UpstreamOverrides[controlHost], h.cfg.ControlHosts, scheme)
	return t.Host, t.Port, t.Scheme
}

// upstreamHandshake sends the ts2021 upgrade with the sidecar's initiation, reads the 101 and the
// Noise response, and consumes any leading EarlyNoise. It returns the decrypted upstream conn,
// a reader-wrapped conn for the HTTP/2 bridge, and the forwarded EarlyNoise.
func (h *Handler) upstreamHandshake(ctx context.Context, upstream *sidecar.StreamConn, host string, machineKey key.MachinePrivate, serverPub key.MachinePublic, version uint16) (*controlbase.Conn, net.Conn, earlyNoise, error) {
	initiation, err := tsproto.Initiator(machineKey, serverPub, version)
	if err != nil {
		return nil, nil, earlyNoise{}, err
	}
	if _, err := upstream.Write(buildUpgradeRequest(host, initiation.Header)); err != nil {
		return nil, nil, earlyNoise{}, err
	}

	// bound the handshake reads so a hung upstream can't leak the goroutine
	// cleared once established so the long-lived HTTP/2 phase is unbounded
	_ = upstream.SetReadDeadline(time.Now().Add(upstreamHandshakeTimeout))

	br := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return nil, nil, earlyNoise{}, fmt.Errorf("read upgrade response: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, nil, earlyNoise{}, fmt.Errorf("upstream upgrade status %s", resp.Status)
	}

	inner, err := initiation.Complete(ctx, prefixedConn{Conn: upstream, r: br})
	if err != nil {
		return nil, nil, earlyNoise{}, err
	}

	ibr := bufio.NewReader(inner)
	raw, msg, _, err := tsproto.ReadEarlyNoise(ibr)
	if err != nil {
		_ = inner.Close()
		return nil, nil, earlyNoise{}, fmt.Errorf("read early noise: %w", err)
	}
	_ = upstream.SetReadDeadline(time.Time{})
	return inner, prefixedConn{Conn: inner, r: ibr}, earlyNoise{raw: raw, msg: msg}, nil
}

// buildUpgradeRequest builds the upstream ts2021 POST carrying the base64 initiation.
func buildUpgradeRequest(host string, initiation []byte) []byte {
	return []byte("POST " + ts2021Path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: " + tsproto.UpgradeProtocol + "\r\n" +
		"Connection: upgrade\r\n" +
		tsproto.HandshakeHeaderName + ": " + base64.StdEncoding.EncodeToString(initiation) + "\r\n" +
		"Content-Length: 0\r\n\r\n")
}

// envelopeInfo carries the fields needed to emit the tunnel envelope flow. The client-facing
// fields (client, clientAddr) are empty for a fresh tunnel opened by replay/injection, which has no client-facing side.
type envelopeInfo struct {
	parentFlowID string // captured /ts2021 upgrade flow (client path); empty for fresh
	tunnelKey    string // path/id suffix: client StreamID or the upstream stream id
	clientAddr   string
	upstreamAddr string
	version      uint16
	client       *controlbase.Conn // nil for a fresh (upstream-only) tunnel
	upstream     *controlbase.Conn
	serverPub    key.MachinePublic
	machineKey   key.MachinePrivate
	early        earlyNoise
}

// emitTunnelEnvelope pushes the tunnel-envelope flow and returns its flow_id, used as parent_flow_id for
// every inner flow. Client-facing headers are added only when a client-facing side exists.
func (h *Handler) emitTunnelEnvelope(ctx context.Context, in envelopeInfo) (string, error) {
	serverHash := in.upstream.HandshakeHash()
	headers := []wire.Header{
		{Name: "X-TS-Noise-Protocol", Value: noiseProtocolName},
		{Name: "X-TS-Protocol-Version", Value: strconv.Itoa(int(in.version))},
		{Name: "X-TS-Handshake-Hash-Server", Value: hex.EncodeToString(serverHash[:])},
		{Name: "X-TS-Client-Facing-Server-Pubkey", Value: h.responderKey.Public().String()},
		{Name: "X-TS-Server-Facing-Server-Pubkey", Value: in.serverPub.String()},
		{Name: "X-TS-Sidecar-Machine-Pubkey", Value: in.machineKey.Public().String()},
		{Name: "X-TS-Upstream-Addr", Value: in.upstreamAddr},
	}
	if in.client != nil {
		clientHash := in.client.HandshakeHash()
		headers = append(headers,
			wire.Header{Name: "X-TS-Handshake-Hash-Client", Value: hex.EncodeToString(clientHash[:])},
			wire.Header{Name: "X-TS-Client-Machine-Pubkey", Value: in.client.Peer().String()},
			wire.Header{Name: "X-TS-Client-Addr", Value: in.clientAddr},
		)
	}
	var body []byte
	if in.early.msg != nil {
		if b, err := json.Marshal(in.early.msg); err == nil {
			body = b
		}
	}
	return h.conn.PushFlow(ctx, wire.Flow{
		ProtocolTag:  tunnelProtocolTag,
		Direction:    adapter.DirBidirectional,
		ParentFlowID: in.parentFlowID,
		Request: &wire.FlowMessage{
			Method:  "TUNNEL",
			Path:    "/" + h.name + "/tunnel/" + in.tunnelKey,
			Headers: headers,
			Body:    body,
		},
		StartedAt: time.Now(),
	})
}

// fetchKeyBody fetches the raw /key response body from the real control server via
// the native proxy (attributable, outside any client-facing substitution).
func fetchKeyBody(ctx context.Context, conn keyFetcher, scheme, authority string, version uint16) ([]byte, error) {
	target, err := json.Marshal(map[string]string{
		"url":    scheme + "://" + authority + "/key?v=" + strconv.Itoa(int(version)),
		"method": "GET",
	})
	if err != nil {
		return nil, err
	}
	wait := true
	res, err := conn.InvokeAdapter(ctx, wire.InvokeAdapterParams{
		Adapter:         coreAdapter,
		Target:          target,
		WaitForResponse: &wait,
	})
	if err != nil {
		return nil, err
	}
	if res.Response == nil {
		return nil, errors.New("no /key response")
	}
	return res.Response.Body, nil
}

// keyFetcher is the subset of *sidecar.Conn used to fetch /key.
type keyFetcher interface {
	InvokeAdapter(ctx context.Context, p wire.InvokeAdapterParams) (wire.InvokeAdapterResult, error)
}

func (h *Handler) tunnelError(streamID, stage string, err error) {
	_ = h.conn.Log("error", "tunnel failed: "+stage,
		map[string]any{"stream": streamID, "error": err.Error()})
}

// prefixedConn reads through a buffered reader wrapping Conn so bytes buffered
// during handshake framing are not lost, while writes go straight to Conn.
type prefixedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c prefixedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
