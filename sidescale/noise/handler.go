package noise

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/pkg/addr"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/noise/bindings"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

// ts2021Path is the control-protocol upgrade path claimed on the control host.
const ts2021Path = "/ts2021"

// mitmProtocols are the flow protocol tags the Noise surface emits.
var mitmProtocols = []string{tunnelProtocolTag, controlProtocolTag, streamProtocolTag}

// Protocols returns the Noise flow protocol tags.
func Protocols() []string { return slices.Clone(mitmProtocols) }

// Handler is the inbound callback surface for the sidecar connection.
type Handler struct {
	sidecar.BaseHandler
	baseCtx      context.Context // connection lifetime; roots handler-spawned work
	conn         *sidecar.Conn
	cfg          ControlConfig
	name         string // adapter name, for tunnel envelope paths
	controlHost  string // host part of cfg.ControlHosts[0]
	responderKey key.MachinePrivate
	machineKey   func(client string) (key.MachinePrivate, error)
	keysub       *keySubstituter

	// dialFn opens one upstream Noise+HTTP/2 conn; injectable for tests
	dialFn func(ctx context.Context, host string, machineKey key.MachinePrivate, version uint16) (*upstreamConn, error)

	// binding key material, loaded once at startup (connection-time config)
	regSigner *bindings.RegisterSigner
	hwSigner  *ecdsa.PrivateKey

	// freshSeq issues unique per_client pool sessions for fresh replay/injection tunnels
	freshSeq atomic.Uint64

	// setupDone closes when Setup finishes (ok or failed); tunnels accepted during the
	// startup window wait on it so substitution state is never half-initialized
	setupDone chan struct{}
	setupErr  error // Setup's error, read after setupDone closes

	router *sidecar.StreamRouter // shared: accepts claimed streams, dials upstreams

	mu        sync.Mutex
	tunnels   map[string]*activeTunnel    // keyed by tunnel envelope flow_id
	upstreams map[poolKey]*sharedUpstream // pooled upstream conns, shared across tunnels
}

// NewHandler builds the Noise control-surface handler. ctx bounds the connection lifetime and roots handler-spawned work.
func NewHandler(ctx context.Context, conn *sidecar.Conn, router *sidecar.StreamRouter, cfg *ControlConfig, name string, responderKey key.MachinePrivate, machineKey func(client string) (key.MachinePrivate, error)) *Handler {
	host, _ := addr.Parse(cfg.ControlHosts[0], "https")
	h := &Handler{
		baseCtx:      ctx,
		conn:         conn,
		cfg:          *cfg,
		name:         name,
		controlHost:  host,
		responderKey: responderKey,
		machineKey:   machineKey,
		router:       router,
		setupDone:    make(chan struct{}),
		tunnels:      map[string]*activeTunnel{},
		upstreams:    map[poolKey]*sharedUpstream{},
	}
	h.dialFn = func(ctx context.Context, host string, machineKey key.MachinePrivate, version uint16) (*upstreamConn, error) {
		return h.openUpstream(ctx, host, machineKey, version, "")
	}
	return h
}

// SetBindingKeys installs the replay rebind key material (connection-time config).
func (h *Handler) SetBindingKeys(reg *bindings.RegisterSigner, hw *ecdsa.PrivateKey) {
	h.regSigner = reg
	h.hwSigner = hw
}

// Setup arms the /key substitution (fetch + responder registration). Call once at
// startup; it may run while the dispatcher already serves streams, which waitSetup gates.
func (h *Handler) Setup(ctx context.Context) error {
	ks, err := setupKeySubstitution(ctx, h)
	h.keysub = ks
	h.setupErr = err
	close(h.setupDone) // publishes keysub/setupErr
	return err
}

// waitSetup blocks until Setup has finished, so a tunnel accepted during the startup
// window never serves with half-initialized substitution state. Borrow needs no setup
// state and passes at once. ctx bounds the wait.
func (h *Handler) waitSetup(ctx context.Context) error {
	if h.cfg.KeyStrategy == KeyStrategyBorrow {
		return nil
	}
	select {
	case <-h.setupDone:
		return h.setupErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down the /key substitution responder. It runs in the dispatcher's
// OnClose cleanup window, while the peer still accepts RPCs.
func (h *Handler) Close(ctx context.Context) {
	if h.keysub != nil {
		h.keysub.close(ctx)
	}
}

// ServeStream drives an accepted stream: a ts2021 tunnel, or a cleartext /key request
// on the host-terminated control claim (sidecar_tls mode).
func (h *Handler) ServeStream(ctx context.Context, sc *sidecar.StreamConn) {
	p := sc.Open()
	switch {
	case p.Path == ts2021Path:
		if err := h.waitSetup(ctx); err != nil {
			h.tunnelError(p.StreamID, "setup pending", err)
			_ = sc.Close()
			return
		}
		init, err := handshakeInit(p.RequestHeaders)
		if err != nil {
			_ = h.conn.Log("error", "ts2021: initiation header", map[string]any{adapter.FieldStream: p.StreamID, adapter.FieldError: err.Error()})
			_ = sc.Close()
			return
		}
		h.runTunnel(ctx, sc, init)
	case h.cfg.KeyStrategy == KeyStrategySubstitute && h.cfg.KeySubstitution == KeySubSidecarTLS:
		if err := h.waitSetup(ctx); err != nil {
			h.tunnelError(p.StreamID, "setup pending", err)
			_ = sc.Close()
			return
		}
		h.keysub.serveKey(ctx, sc, p.StreamID)
	default:
		_ = sc.Close()
	}
}

func (h *Handler) OnShutdown(drainSeconds int) {
	_ = h.conn.Log("info", "sidescale shutdown requested", map[string]any{"drain_seconds": drainSeconds})
}

// handshakeInit recovers the base64 Noise initiation from the captured request headers of the ts2021 upgrade.
func handshakeInit(headers []wire.Header) ([]byte, error) {
	for _, hd := range headers {
		if strings.EqualFold(hd.Name, tsproto.HandshakeHeaderName) {
			return base64.StdEncoding.DecodeString(hd.Value)
		}
	}
	return nil, errors.New("missing " + tsproto.HandshakeHeaderName + " header")
}
