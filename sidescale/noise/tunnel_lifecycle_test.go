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
	"strings"
	"testing"
	"time"

	"github.com/go-analyze/bulk"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/control/controlbase"
	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

// ts2021Harness wires the full end-to-end client-facing tunnel path: a sidecar host whose
// registry carries the /ts2021 upgrade claim, a noise handler serving accepted streams, a
// fake control server on the upstream side, and a client listener the test connects to.
type ts2021Harness struct {
	h        *Handler
	flows    *recordingFlows
	clientLn net.Listener
	cancel   context.CancelFunc
}

func newTS2021Harness(t *testing.T) *ts2021Harness {
	t.Helper()

	serverKey := key.NewMachine()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	// fake control server answering the upstream half of every tunnel
	var lc net.ListenConfig
	upLn, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = upLn.Close() })
	go serveTS2021Loop(ctx, upLn, serverKey)

	cfg, err := defaultControlConfig()
	require.NoError(t, err)
	cfg.KeyStrategy = KeyStrategyBorrow // upstreamServerKey returns the responder key, no /key fetch
	cfg.ControlHosts = []string{"ctrl.example"}
	cfg.UpstreamOverrides = map[string]string{"ctrl.example": "http://" + upLn.Addr().String()}

	// sidecar host with the /ts2021 upgrade claim active, as the registration declares
	flows := newRecordingFlows()
	registry := &protocol.Registry{}
	hostCfg := scsidecar.Config{Socket: filepath.Join(t.TempDir(), "sidecar.sock")}
	mgr := scsidecar.NewManager(hostCfg, registry, flows, noopCore{}, stubRules{})
	lst, err := scsidecar.NewListener(ctx, hostCfg, mgr)
	require.NoError(t, err)
	t.Cleanup(func() { _ = lst.Close(context.Background()) })
	go func() { _ = lst.Serve() }()

	reg := sidecar.Registration{
		Name:       "sidescale.test",
		InstanceID: testInstanceID,
		Resume:     true,
		Capabilities: wire.Capabilities{UpgradeClaims: []wire.UpgradeClaim{{
			HostPattern:   "ctrl.example",
			PathPattern:   ts2021Path,
			UpgradeSignal: "http_101",
			MethodSet:     []string{"POST"},
		}}},
	}
	conn, err := sidecar.Dial(ctx, hostCfg.Socket, reg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	router := sidecar.NewStreamRouter(conn)
	h := NewHandler(ctx, conn, router, &cfg, "sidescale.test", serverKey,
		func(string) (key.MachinePrivate, error) { return key.NewMachine(), nil })
	go func() { _ = conn.Serve(ctx, router) }()
	// mirror main's dispatcher: route accepted /ts2021 streams to the noise surface
	go func() {
		for {
			sc, aerr := router.Accept(ctx)
			if aerr != nil {
				return
			}
			if sc.Open().Path == ts2021Path {
				go h.ServeStream(ctx, sc)
				continue
			}
			_ = sc.Close()
		}
	}()

	// accept fake-client conns, parse the upgrade request, and hand each to the
	// claiming adapter, mirroring the proxy's upgrade path
	var clc net.ListenConfig
	clientLn, err := clc.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = clientLn.Close() })
	go func() {
		for {
			raw, aerr := clientLn.Accept()
			if aerr != nil {
				return
			}
			go serveUpgradeConn(ctx, registry, raw)
		}
	}()

	return &ts2021Harness{h: h, flows: flows, clientLn: clientLn, cancel: cancel}
}

// tunnelClient is one established client-facing tunnel: the HTTP/2 client speaking over the
// decrypted inner conn, plus the raw pre-upgrade conn whose close drives teardown.
type tunnelClient struct {
	cc  *http.ClientConn
	raw net.Conn
}

// closeRaw closes the raw conn without the HTTP/2 client's graceful shutdown, like a
// client process dying mid-session.
func (tc *tunnelClient) closeRaw() error { return tc.raw.Close() }

// dialTunnel connects a fake ts2021 client through the host: it sends the upgrade request
// with a Noise initiation, completes the client-facing handshake over the streamed conn,
// consumes EarlyNoise, and returns the tunnel client.
func (th *ts2021Harness) dialTunnel(ctx context.Context, t *testing.T) *tunnelClient {
	t.Helper()

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", th.clientLn.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = raw.Close() })

	initiation, cont, err := controlbase.ClientDeferred(key.NewMachine(), th.h.responderKey.Public(), uint16(tsproto.CurrentCapabilityVersion))
	require.NoError(t, err)
	rawUpgrade := "POST " + ts2021Path + " HTTP/1.1\r\n" +
		"Host: ctrl.example\r\n" +
		"Upgrade: " + tsproto.UpgradeProtocol + "\r\n" +
		"Connection: upgrade\r\n" +
		tsproto.HandshakeHeaderName + ": " + base64.StdEncoding.EncodeToString(initiation) + "\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, err = raw.Write([]byte(rawUpgrade))
	require.NoError(t, err)

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	inner, err := cont(ctx, prefixedConn{Conn: raw, r: br})
	require.NoError(t, err)

	// the tunnel forwards the upstream EarlyNoise before HTTP/2
	ibr := bufio.NewReader(inner)
	_, _, _, err = tsproto.ReadEarlyNoise(ibr)
	require.NoError(t, err)

	tr := &http.Transport{Protocols: &http.Protocols{}}
	tr.Protocols.SetUnencryptedHTTP2(true)
	tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return prefixedConn{Conn: inner, r: ibr}, nil
	}
	cc, err := tr.NewClientConn(ctx, "http", "ctrl.example:443")
	require.NoError(t, err)
	return &tunnelClient{cc: cc, raw: raw}
}

// serveUpgradeConn parses one client upgrade request, matches it against the registry
// claims, and hands the conn to the claiming adapter. It runs for the conn's lifetime.
func serveUpgradeConn(ctx context.Context, registry *protocol.Registry, raw net.Conn) {
	br := bufio.NewReader(raw)
	req, err := http.ReadRequest(br)
	if err != nil {
		_ = raw.Close()
		return
	}
	uc := &protocol.UpgradeClaimCtx{
		Req: &types.RawHTTP1Request{
			Method:  req.Method,
			Path:    req.URL.Path,
			Version: req.Proto,
			Headers: rawRequestHeaders(req),
		},
		Target: &types.Target{Hostname: "ctrl.example", Port: 443},
		Signal: "http_101",
	}
	upgradeAdapter, ok := registry.ClaimUpgrade(uc)
	if !ok {
		_ = raw.Close()
		return
	}
	upgradeAdapter.ServeUpgrade(ctx, uc, protocol.UpgradeConns{ClientConn: raw, ClientReader: br})
}

// rawRequestHeaders renders a parsed upgrade request as sectool's header shape.
func rawRequestHeaders(req *http.Request) types.Headers {
	out := make(types.Headers, 0, len(req.Header))
	for name, vs := range req.Header {
		if len(vs) == 0 {
			continue
		}
		out = append(out, types.Header{Name: name, Value: vs[0]})
	}
	return out
}

// tunnelRequest sends one inner POST over the tunnel and returns the echoed body.
func tunnelRequest(ctx context.Context, t *testing.T, cc *http.ClientConn, path string) string {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://ctrl.example"+path, strings.NewReader("hello-body"))
	require.NoError(t, err)
	resp, err := cc.RoundTrip(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

// controlChildren returns the captured inner request/response flows under the tunnel envelope.
func (th *ts2021Harness) controlChildren(envID string) []*types.Flow {
	return bulk.SliceFilter(func(f *types.Flow) bool {
		return f.ProtocolTag == controlProtocolTag && f.ParentFlowID == envID
	}, th.flows.list())
}

// tunnelEnvelope returns the tunnel envelope flow, failing when absent or duplicated.
func (th *ts2021Harness) tunnelEnvelope(t *testing.T) *types.Flow {
	t.Helper()

	envelopes := bulk.SliceFilter(func(f *types.Flow) bool {
		return f.ProtocolTag == tunnelProtocolTag
	}, th.flows.list())
	require.Len(t, envelopes, 1)
	return envelopes[0]
}

// requireLiveTunnel asserts the envelope is captured, registered, and in-flight.
func (th *ts2021Harness) requireLiveTunnel(t *testing.T) string {
	t.Helper()

	env := th.tunnelEnvelope(t)
	require.NotEmpty(t, env.FlowID)
	assert.NotNil(t, th.h.getTunnel(env.FlowID))
	assert.False(t, th.flows.wasCompleted(env.FlowID))
	return env.FlowID
}

// requireTornDown asserts the tunnel finished exactly once: envelope completed and the
// registry entry gone.
func (th *ts2021Harness) requireTornDown(t *testing.T, envID string) {
	t.Helper()

	require.Eventually(t, func() bool { return th.flows.wasCompleted(envID) },
		5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return th.h.getTunnel(envID) == nil },
		5*time.Second, 10*time.Millisecond)
}

func TestServeStreamTunnelLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping end-to-end tunnel test in -short mode")
	}
	t.Parallel()

	t.Run("survives_multiple_requests", func(t *testing.T) {
		th := newTS2021Harness(t)
		tc := th.dialTunnel(t.Context(), t)

		assert.JSONEq(t, `{"path":"/machine/register"}`, tunnelRequest(t.Context(), t, tc.cc, "/machine/register"))
		envID := th.requireLiveTunnel(t)

		// the second request rides the live tunnel, proving ServeCapture did not
		// return right after establishment
		assert.JSONEq(t, `{"path":"/machine/map"}`, tunnelRequest(t.Context(), t, tc.cc, "/machine/map"))

		// both exchanges captured as children of the live envelope
		require.Eventually(t, func() bool {
			return len(th.controlChildren(envID)) >= 4 // request + response flow per inner request
		}, 5*time.Second, 10*time.Millisecond)
		th.requireLiveTunnel(t)
	})

	t.Run("teardown_on_client_close", func(t *testing.T) {
		th := newTS2021Harness(t)
		tc := th.dialTunnel(t.Context(), t)
		_ = tunnelRequest(t.Context(), t, tc.cc, "/machine/register")
		envID := th.requireLiveTunnel(t)

		// teardown rides the client-facing conn closing
		require.NoError(t, tc.closeRaw())
		th.requireTornDown(t, envID)
	})

	t.Run("teardown_on_ctx_cancel", func(t *testing.T) {
		th := newTS2021Harness(t)
		tc := th.dialTunnel(t.Context(), t)
		_ = tunnelRequest(t.Context(), t, tc.cc, "/machine/register")
		envID := th.requireLiveTunnel(t)

		// canceling the session ctx ends the served conn. The envelope complete rides
		// the same dying sidecar conn, so only the local teardown is observable
		th.cancel()
		require.Eventually(t, func() bool { return th.h.getTunnel(envID) == nil },
			5*time.Second, 10*time.Millisecond)

		closed := make(chan error, 1)
		go func() { _, err := tc.raw.Read(make([]byte, 1)); closed <- err }()
		require.Eventually(t, func() bool {
			select {
			case err := <-closed:
				return err != nil
			default:
				return false
			}
		}, 5*time.Second, 10*time.Millisecond)
	})
}
