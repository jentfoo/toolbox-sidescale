package noise

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"tailscale.com/control/controlbase"
	"tailscale.com/types/key"

	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

// pairedNoiseConn returns a live upstream-side controlbase.Conn from a completed IK
// handshake over an in-memory pipe, so upstreamConn teardown exercises real Close paths.
func pairedNoiseConn(t *testing.T, version uint16) *controlbase.Conn {
	t.Helper()

	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	serverKey := key.NewMachine()
	clientKey := key.NewMachine()

	done := make(chan struct{})
	go func() {
		_, _ = controlbase.Server(t.Context(), c2, serverKey, nil)
		close(done)
	}()
	initn, err := tsproto.Initiator(clientKey, serverKey.Public(), version)
	require.NoError(t, err)
	_, err = c1.Write(initn.Header)
	require.NoError(t, err)
	client, err := initn.Complete(t.Context(), c1)
	require.NoError(t, err)
	<-done
	return client
}

// fakeUpstreamConn builds an upstreamConn backed by a live H2 bridge (serving srv) and
// a real Noise inner conn, registered as a handler stream so teardown runs normally.
func fakeUpstreamConn(t *testing.T, h *Handler, host string, version uint16, srv http.Handler) *upstreamConn {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		(&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: srv})
	}()
	var d net.Dialer
	upConn, err := d.DialContext(t.Context(), "tcp", ln.Addr().String())
	require.NoError(t, err)
	bridge, err := tsproto.NewH2Bridge(upConn)
	require.NoError(t, err)

	streamID := upConn.LocalAddr().String()
	return &upstreamConn{
		streamID:     streamID,
		inner:        pairedNoiseConn(t, version),
		bridge:       bridge,
		serverPub:    key.NewMachine().Public(),
		serverLegacy: key.NewMachine().Public(),
		addr:         host,
	}
}

// fakeUpstream wraps fakeUpstreamConn as a pooled sharedUpstream keyed by id. refs
// starts at 1 to mirror production, where the owning tunnel always holds a ref.
func fakeUpstream(t *testing.T, h *Handler, id key.MachinePublic, host string, version uint16, srv http.Handler) *sharedUpstream {
	t.Helper()
	return &sharedUpstream{key: poolKey{id: id, host: host, version: version}, uc: fakeUpstreamConn(t, h, host, version, srv), refs: 1}
}

func okSrv() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func TestGetOrCreateUpstream(t *testing.T) {
	t.Parallel()

	cfg, err := defaultControlConfig()
	require.NoError(t, err)
	ver := uint16(tsproto.CurrentCapabilityVersion)
	mk := key.NewMachine()

	dialCounter := func(h *Handler, calls *int32) {
		h.dialFn = func(_ context.Context, host string, _ key.MachinePrivate, version uint16) (*upstreamConn, error) {
			atomic.AddInt32(calls, 1)
			return fakeUpstreamConn(t, h, host, version, okSrv()), nil
		}
	}

	// concurrent callers for one identity share a single dial, so a connection storm
	// never opens two upstream Noise sessions for the same machine key
	t.Run("single_flight", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		var calls int32
		release := make(chan struct{})
		h.dialFn = func(_ context.Context, host string, _ key.MachinePrivate, version uint16) (*upstreamConn, error) {
			atomic.AddInt32(&calls, 1)
			<-release // hold the dial open so every caller contends
			return fakeUpstreamConn(t, h, host, version, okSrv()), nil
		}

		const n = 8
		results := make(chan *sharedUpstream, n)
		for range n {
			go func() {
				u, gerr := h.getOrCreateUpstream(t.Context(), "ctrl.example", mk, ver, "")
				assert.NoError(t, gerr)
				results <- u
			}()
		}

		require.Eventually(t, func() bool { return atomic.LoadInt32(&calls) == 1 }, time.Second, time.Millisecond)
		close(release)

		first := <-results
		for range n - 1 {
			assert.Same(t, first, <-results)
		}
		assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
		h.mu.Lock()
		assert.Equal(t, n, first.refs)
		h.mu.Unlock()
	})

	// a distinct session discriminator opens its own upstream conn (per_client isolation)
	t.Run("distinct_sessions_dial_separately", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		var calls int32
		dialCounter(h, &calls)
		u1, err := h.getOrCreateUpstream(t.Context(), "ctrl.example", mk, ver, "clientA")
		require.NoError(t, err)
		u2, err := h.getOrCreateUpstream(t.Context(), "ctrl.example", mk, ver, "clientB")
		require.NoError(t, err)
		assert.NotSame(t, u1, u2)
		assert.Equal(t, int32(2), atomic.LoadInt32(&calls))
	})

	// an empty session coalesces onto the shared upstream
	t.Run("empty_session_coalesces", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		var calls int32
		dialCounter(h, &calls)
		u1, err := h.getOrCreateUpstream(t.Context(), "ctrl.example", mk, ver, "")
		require.NoError(t, err)
		u2, err := h.getOrCreateUpstream(t.Context(), "ctrl.example", mk, ver, "")
		require.NoError(t, err)
		assert.Same(t, u1, u2)
		assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
	})
}

func TestUpstreamPoolRefcount(t *testing.T) {
	t.Parallel()

	cfg, err := defaultControlConfig()
	require.NoError(t, err)
	ver := uint16(tsproto.CurrentCapabilityVersion)

	t.Run("release_then_reacquire_keeps_conn", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		u := fakeUpstream(t, h, key.NewMachine().Public(), "ctrl.example", ver, okSrv())
		u.refs = 1
		h.upstreams[u.key] = u

		h.releaseUpstream(u) // refs -> 0: schedules idle close, conn stays live
		h.mu.Lock()
		assert.Equal(t, 0, u.refs)
		assert.NotNil(t, u.idleTimer)
		assert.False(t, u.closed)
		assert.Same(t, u, h.upstreams[u.key])
		h.acquireLocked(u) // re-dial arrives within the grace window
		h.mu.Unlock()

		assert.Equal(t, 1, u.refs)
		assert.Nil(t, u.idleTimer)
		assert.False(t, u.closed)
		assert.True(t, u.uc.bridge.Usable())
	})

	t.Run("two_holders_one_release_stays_open", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		u := fakeUpstream(t, h, key.NewMachine().Public(), "ctrl.example", ver, okSrv())
		u.refs = 2
		h.upstreams[u.key] = u

		h.releaseUpstream(u)
		assert.Equal(t, 1, u.refs)
		assert.Nil(t, u.idleTimer)
		assert.False(t, u.closed)
		assert.True(t, u.uc.bridge.Usable())
	})

	t.Run("idle_close_tears_down", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		u := fakeUpstream(t, h, key.NewMachine().Public(), "ctrl.example", ver, okSrv())
		u.refs = 1
		h.upstreams[u.key] = u

		h.releaseUpstream(u)
		h.idleCloseUpstream(u) // fire the grace timer synchronously

		h.mu.Lock()
		assert.True(t, u.closed)
		assert.Nil(t, h.upstreams[u.key])
		h.mu.Unlock()
		assert.False(t, u.uc.bridge.Usable())
	})

	t.Run("evict_removes_and_closes", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		u := fakeUpstream(t, h, key.NewMachine().Public(), "ctrl.example", ver, okSrv())
		u.refs = 1
		h.upstreams[u.key] = u

		h.evictUpstream(u, "test")
		h.mu.Lock()
		assert.True(t, u.closed)
		assert.Nil(t, h.upstreams[u.key])
		h.mu.Unlock()
		assert.False(t, u.uc.bridge.Usable())

		h.evictUpstream(u, "test") // idempotent
		h.releaseUpstream(u)       // holder release after eviction is a no-op
	})
}

func TestPoolSession(t *testing.T) {
	t.Parallel()

	shared := &Handler{cfg: ControlConfig{UpstreamPoolMode: PoolModeShared}}
	assert.Empty(t, shared.poolSession("clientA"))
	assert.Empty(t, shared.freshPoolSession())

	perClient := &Handler{cfg: ControlConfig{UpstreamPoolMode: PoolModePerClient}}
	assert.Equal(t, "clientA", perClient.poolSession("clientA"))
	// fresh sessions are unique per call so each fresh tunnel is isolated
	first := perClient.freshPoolSession()
	second := perClient.freshPoolSession()
	assert.NotEqual(t, first, second)

	// dedicated sessions are always unique and non-empty, even in shared mode
	for _, h := range []*Handler{shared, perClient} {
		a, b := h.dedicatedPoolSession(), h.dedicatedPoolSession()
		assert.True(t, strings.HasPrefix(a, "dedicated-"))
		assert.NotEqual(t, a, b)
	}
}
