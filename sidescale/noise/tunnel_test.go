package noise

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"

	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

func TestUpstreamDial(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		scheme    string
		hosts     []string
		overrides map[string]string
		wantHost  string
		wantPort  int
		wantSch   string
	}{
		{"auto_defaults_https", UpstreamSchemeAuto, nil, nil, "ctrl.example", 443, "https"},
		{"http_scheme_port80", UpstreamSchemeHTTP, nil, nil, "ctrl.example", 80, "http"},
		{"configured_port_no_override", UpstreamSchemeAuto, []string{"ctrl.example:8443"}, nil, "ctrl.example", 8443, "https"},
		{"configured_port_http", UpstreamSchemeHTTP, []string{"ctrl.example:8080"}, nil, "ctrl.example", 8080, "http"},
		{"override_wins_over_configured", UpstreamSchemeAuto, []string{"ctrl.example:8443"}, map[string]string{"ctrl.example": "1.2.3.4:9443"}, "1.2.3.4", 9443, "https"},
		{"override_hostport", UpstreamSchemeAuto, nil, map[string]string{"ctrl.example": "1.2.3.4:8443"}, "1.2.3.4", 8443, "https"},
		{"override_url_http", UpstreamSchemeAuto, nil, map[string]string{"ctrl.example": "http://1.2.3.4:8080"}, "1.2.3.4", 8080, "http"},
		{"override_url_http_default_port", UpstreamSchemeAuto, nil, map[string]string{"ctrl.example": "http://1.2.3.4"}, "1.2.3.4", 80, "http"},
		{"override_url_https", UpstreamSchemeHTTP, nil, map[string]string{"ctrl.example": "https://1.2.3.4"}, "1.2.3.4", 443, "https"},
		{"override_bare_host", UpstreamSchemeHTTP, nil, map[string]string{"ctrl.example": "1.2.3.4"}, "1.2.3.4", 80, "http"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{cfg: ControlConfig{ControlHosts: tc.hosts, UpstreamScheme: tc.scheme, UpstreamOverrides: tc.overrides}}
			host, port, scheme := h.upstreamDial("ctrl.example")
			assert.Equal(t, tc.wantHost, host)
			assert.Equal(t, tc.wantPort, port)
			assert.Equal(t, tc.wantSch, scheme)
		})
	}
}

func TestClientEarlyNoise(t *testing.T) {
	t.Parallel()

	up := earlyNoise{raw: []byte{0x01, 0x02, 0x03}}

	t.Run("forward", func(t *testing.T) {
		h := &Handler{cfg: ControlConfig{EarlyNoise: EarlyNoiseForward}}
		got, err := h.clientEarlyNoise(up)
		require.NoError(t, err)
		assert.Equal(t, up.raw, got)
	})
	t.Run("suppress", func(t *testing.T) {
		h := &Handler{cfg: ControlConfig{EarlyNoise: EarlyNoiseSuppress}}
		got, err := h.clientEarlyNoise(up)
		require.NoError(t, err)
		assert.Nil(t, got)
	})
	t.Run("replace", func(t *testing.T) {
		h := &Handler{cfg: ControlConfig{EarlyNoise: EarlyNoiseReplace}}
		got, err := h.clientEarlyNoise(up)
		require.NoError(t, err)
		require.NotEmpty(t, got)
		assert.NotEqual(t, up.raw, got)
		// a synthesized frame decodes as a valid EarlyNoise with a challenge
		msg, _, ok, derr := tsproto.DecodeEarlyNoise(got)
		require.NoError(t, derr)
		require.True(t, ok)
		require.NotNil(t, msg)
	})
}

// deadTunnel registers an activeTunnel bound to a pooled upstream whose bridge is closed,
// so the next forward over it errors with an unusable conn.
func deadTunnel(t *testing.T, h *Handler, ver uint16) *activeTunnel {
	t.Helper()

	dead := fakeUpstream(t, h, key.NewMachine().Public(), "ctrl.example", ver, okSrv())
	h.upstreams[dead.key] = dead
	at := &activeTunnel{up: dead, bridge: dead.uc.bridge, controlHost: "ctrl.example", machineKey: key.NewMachine(), version: ver, flowID: "t1"}
	h.registerTunnel("t1", at)
	_ = dead.uc.bridge.Close() // make the bound conn unusable
	return at
}

func mapReq(ctx context.Context) *http.Request {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://ctrl.example/machine/map", nil)
	return req
}

func TestHealUpstream(t *testing.T) {
	t.Parallel()

	cfg, err := defaultControlConfig()
	require.NoError(t, err)
	ver := uint16(tsproto.CurrentCapabilityVersion)

	t.Run("heals_and_swaps", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		var calls int32
		h.dialFn = func(_ context.Context, host string, _ key.MachinePrivate, version uint16) (*upstreamConn, error) {
			atomic.AddInt32(&calls, 1)
			return fakeUpstreamConn(t, h, host, version, okSrv()), nil
		}
		at := deadTunnel(t, h, ver)
		dead, _ := at.current()

		// the failing forward heals but is not retried, so it still errors
		resp, ferr := h.forwardTunnel(t.Context(), at, mapReq(t.Context()))
		require.Error(t, ferr)
		assert.Nil(t, resp)

		fresh, bridge := at.current()
		assert.NotSame(t, dead, fresh)
		assert.True(t, bridge.Usable())
		assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
		h.mu.Lock()
		assert.True(t, dead.closed)
		assert.Equal(t, 0, dead.refs)
		assert.Equal(t, 1, fresh.refs)
		h.mu.Unlock()

		// the next forward rides the healed conn
		resp2, ferr := h.forwardTunnel(t.Context(), at, mapReq(t.Context()))
		require.NoError(t, ferr)
		assert.Equal(t, http.StatusOK, resp2.StatusCode)
		require.NoError(t, resp2.Body.Close())
	})

	t.Run("heals_once_under_concurrency", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		var calls int32
		release := make(chan struct{})
		h.dialFn = func(_ context.Context, host string, _ key.MachinePrivate, version uint16) (*upstreamConn, error) {
			atomic.AddInt32(&calls, 1)
			<-release // hold the dial so every healer contends
			return fakeUpstreamConn(t, h, host, version, okSrv()), nil
		}
		at := deadTunnel(t, h, ver)
		dead, _ := at.current()

		const n = 8
		done := make(chan struct{}, n)
		for range n {
			go func() {
				_, _ = h.forwardTunnel(t.Context(), at, mapReq(t.Context()))
				done <- struct{}{}
			}()
		}
		require.Eventually(t, func() bool { return atomic.LoadInt32(&calls) == 1 }, time.Second, time.Millisecond)
		close(release)
		for range n {
			<-done
		}

		fresh, _ := at.current()
		assert.NotSame(t, dead, fresh)
		assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
		h.mu.Lock()
		assert.Equal(t, 1, fresh.refs)
		assert.Equal(t, 0, dead.refs)
		h.mu.Unlock()
	})

	t.Run("fresh_tunnel_cleanup_releases_healed", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		h.dialFn = func(_ context.Context, host string, _ key.MachinePrivate, version uint16) (*upstreamConn, error) {
			return fakeUpstreamConn(t, h, host, version, okSrv()), nil
		}
		at, cleanup, err := h.openFreshTunnel(t.Context(), "ctrl.example", key.NewMachine(), ver, h.dedicatedPoolSession())
		require.NoError(t, err)
		u1, _ := at.current()
		_ = u1.uc.bridge.Close() // the fresh conn dies before the send lands

		_, ferr := h.forwardTunnel(t.Context(), at, mapReq(t.Context()))
		require.Error(t, ferr)
		u2, _ := at.current()
		require.NotSame(t, u1, u2)

		cleanup()
		h.mu.Lock()
		assert.Equal(t, 0, u2.refs) // cleanup releases the healed upstream, not the dead original
		h.mu.Unlock()
	})

	t.Run("dial_failure_retries_next", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		var fail atomic.Bool
		fail.Store(true)
		h.dialFn = func(_ context.Context, host string, _ key.MachinePrivate, version uint16) (*upstreamConn, error) {
			if fail.Load() {
				return nil, errors.New("dial boom")
			}
			return fakeUpstreamConn(t, h, host, version, okSrv()), nil
		}
		at := deadTunnel(t, h, ver)
		dead, _ := at.current()

		_, ferr := h.forwardTunnel(t.Context(), at, mapReq(t.Context()))
		require.Error(t, ferr)
		cur, _ := at.current()
		assert.Same(t, dead, cur)      // heal dial failed, still bound to dead
		assert.True(t, healFailed(at)) // wedge signal armed on first failure

		_, ferr = h.forwardTunnel(t.Context(), at, mapReq(t.Context()))
		require.Error(t, ferr)
		assert.True(t, healFailed(at)) // still wedged: one-shot, not re-logged per poll

		fail.Store(false)
		_, ferr = h.forwardTunnel(t.Context(), at, mapReq(t.Context())) // forward on dead fails, heal swaps
		require.Error(t, ferr)
		cur, _ = at.current()
		assert.NotSame(t, dead, cur)
		assert.False(t, healFailed(at)) // cleared on recovery, so a later wedge re-signals

		resp, ferr := h.forwardTunnel(t.Context(), at, mapReq(t.Context()))
		require.NoError(t, ferr)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		require.NoError(t, resp.Body.Close())
	})
}

func healFailed(at *activeTunnel) bool {
	at.mu.Lock()
	defer at.mu.Unlock()
	return at.healFailed
}
