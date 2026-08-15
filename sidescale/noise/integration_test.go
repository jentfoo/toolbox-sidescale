//go:build unix

package noise

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

// servingHandler stands up a sidecar host that serves its router (so dialed upstream
// streams pump bytes), and returns a control handler whose responder key is serverKey —
// under borrow strategy that key is what upstreamServerKey hands the initiation, so the
// handshake targets the test server below.
func servingHandler(t *testing.T, cfg *ControlConfig, serverKey key.MachinePrivate) *Handler {
	t.Helper()

	socket := filepath.Join(t.TempDir(), "sidecar.sock")
	hostCfg := scsidecar.Config{Socket: socket}
	mgr := scsidecar.NewManager(hostCfg, &protocol.Registry{}, newRecordingFlows(), noopCore{}, stubRules{})
	lst, err := scsidecar.NewListener(hostCfg, mgr)
	require.NoError(t, err)
	go func() { _ = lst.Serve() }()
	t.Cleanup(func() { _ = lst.Close(context.Background()) })

	reg := sidecar.Registration{Name: "sidescale.test", InstanceID: testInstanceID, Resume: true}
	conn, err := sidecar.Dial(t.Context(), socket, reg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	router := sidecar.NewStreamRouter(conn)
	h := NewHandler(ctx, conn, router, cfg, "sidescale.test", serverKey,
		func(string) (key.MachinePrivate, error) { return key.NewMachine(), nil })
	go func() { _ = conn.Serve(ctx, router) }()
	return h
}

// serveTS2021 answers one upstream connection like a real control server: it reads the
// HTTP/1.1 ts2021 upgrade, extracts the base64 Noise initiation, switches protocols, runs
// the Noise IK responder, sends an early-noise frame, then serves HTTP/2 over the inner conn.
// It runs in a goroutine and must not touch *testing.T, so errors are best-effort dropped.
func serveTS2021(ctx context.Context, ln net.Listener, serverKey key.MachinePrivate) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	initHeader, err := base64.StdEncoding.DecodeString(req.Header.Get(tsproto.HandshakeHeaderName))
	if err != nil {
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: "+tsproto.UpgradeProtocol+"\r\nConnection: upgrade\r\n\r\n"); err != nil {
		return
	}

	inner, err := tsproto.Responder(ctx, prefixedConn{Conn: conn, r: br}, serverKey, initHeader)
	if err != nil {
		return
	}
	// the client reads an early-noise frame before HTTP/2; without one its read blocks
	frame, err := tsproto.EncodeEarlyNoise(&tsproto.EarlyNoise{NodeKeyChallenge: key.NewChallenge().Public()})
	if err != nil {
		return
	}
	if _, err := inner.Write(frame); err != nil {
		return
	}
	(&http2.Server{}).ServeConn(inner, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"path":"` + r.URL.Path + `"}`))
		}),
	})
}

// TestUpstreamHandshakeAgainstRealServer drives the control handler's upstream half
// (openUpstream: dial via the sidecar router, POST /ts2021 upgrade, Noise IK initiation
// against tsproto.Responder, early-noise read, HTTP/2 bridge) against a minimal ts2021
// server built from Tailscale's own controlbase responder. Borrow strategy pins the
// upstream server key so no /key fetch is needed.
func TestUpstreamHandshakeAgainstRealServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	t.Parallel()

	serverKey := key.NewMachine()

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go serveTS2021(t.Context(), ln, serverKey)

	cfg, err := defaultControlConfig()
	require.NoError(t, err)
	cfg.KeyStrategy = KeyStrategyBorrow // upstreamServerKey returns responderKey, no /key fetch
	cfg.ControlHosts = []string{"ctrl.example"}
	cfg.UpstreamOverrides = map[string]string{"ctrl.example": "http://" + ln.Addr().String()}
	h := servingHandler(t, &cfg, serverKey)

	machineKey := key.NewMachine()
	up, err := h.openUpstream(t.Context(), "ctrl.example", machineKey, uint16(tsproto.CurrentCapabilityVersion), "")
	require.NoError(t, err)
	t.Cleanup(up.close)

	// the IK handshake completed against the real responder, so the pinned server key stuck
	assert.Equal(t, serverKey.Public(), up.serverPub)
	require.NotNil(t, up.bridge)
	assert.True(t, up.bridge.Usable())

	// the HTTP/2 bridge over the Noise tunnel carries a real request end to end
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://ctrl.example/machine/map", nil)
	require.NoError(t, err)
	resp, err := up.bridge.Forward(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.JSONEq(t, `{"path":"/machine/map"}`, string(body))
}
