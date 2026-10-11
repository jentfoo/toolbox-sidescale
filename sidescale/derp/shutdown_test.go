//go:build unix

package derp

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/derp"
	"tailscale.com/types/key"

	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
)

// drainConn is a net.Conn standing in for a tunnel's streams: Close signals closed so the
// test can assert force-closure, and a waiter can mirror the tunnel goroutine's unwind.
type drainConn struct {
	net.Conn // nil; only Close is exercised on the drain path
	closed   chan struct{}
	once     sync.Once
}

func newDrainConn() *drainConn { return &drainConn{closed: make(chan struct{})} }

func (c *drainConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// wasClosed reports whether Close ran, without blocking.
func (c *drainConn) wasClosed() bool {
	select {
	case <-c.closed:
		return true
	default:
		return false
	}
}

func TestHandlerShutdown(t *testing.T) {
	t.Parallel()

	// newDrainHandler returns a bare handler; no conn, router, or relay unless terminate.
	newDrainHandler := func(terminate bool) *Handler {
		var h Handler
		h.baseCtx = context.Background()
		h.cfg = &DerpConfig{DerpHosts: []string{"derp.test"}, RelayMode: RelayModeRelay}
		if terminate {
			h.cfg.RelayMode = RelayModeTerminate
			h.relay = newSyntheticRelay(&h)
		}
		h.tunnels = map[string]*activeTunnel{}
		h.tunnelHosts = map[string]string{}
		return &h
	}

	// addStubTunnel registers a relay tunnel whose force-close closes both conns and
	// whose goroutine then unwinds through deregisterTunnel, mirroring runTunnel.
	addStubTunnel := func(h *Handler, id string) (*activeTunnel, *drainConn, *drainConn) {
		t.Helper()

		client, upstream := newDrainConn(), newDrainConn()
		at := &activeTunnel{
			flowID:     id,
			forceClose: func() { _ = client.Close(); _ = upstream.Close() },
			tornDown:   make(chan struct{}),
		}
		h.registerTunnel(id, at)
		go func() {
			<-client.closed // unblocked by the drain's force-close
			h.deregisterTunnel(at)
		}()
		return at, client, upstream
	}

	t.Run("drains_tracked_tunnels", func(t *testing.T) {
		h := newDrainHandler(false)
		at1, client1, up1 := addStubTunnel(h, "f1")
		at2, _, _ := addStubTunnel(h, "f2")

		assert.Zero(t, h.Shutdown(5)) // waits for both unwinds before returning

		select { // deregistration closed each tunnel's signal
		case <-at1.tornDown:
		default:
			t.Fatal("f1 not torn down")
		}
		select {
		case <-at2.tornDown:
		default:
			t.Fatal("f2 not torn down")
		}
		assert.Nil(t, h.getTunnel("f1"))
		assert.True(t, client1.wasClosed())
		assert.True(t, up1.wasClosed()) // the upstream half is force-closed too
	})

	t.Run("counts_open_tunnels_on_expiry", func(t *testing.T) {
		h := newDrainHandler(false)
		at := &activeTunnel{flowID: "f1", forceClose: func() {}, tornDown: make(chan struct{})}
		h.registerTunnel("f1", at) // no unwind goroutine: teardown never runs

		assert.Equal(t, 1, h.Shutdown(0)) // zero window expires at once
	})

	t.Run("empties_relay_registry", func(t *testing.T) {
		h := newDrainHandler(true)
		client := newDrainConn()
		c := h.relay.register(key.NewNode().Public(), newFrameConn(client), "tun1", false)

		assert.Zero(t, h.Shutdown(0))

		assert.Nil(t, h.relay.byTunnelID("tun1"))
		h.relay.mu.Lock()
		_, ok := h.relay.byKey[c.clientKey]
		h.relay.mu.Unlock()
		assert.False(t, ok)
		assert.True(t, client.wasClosed())

		// the unwinding conn's own remove is a no-op after closeAll
		h.relay.remove(context.Background(), c)
	})

	t.Run("refuses_upstream_dials_when_draining", func(t *testing.T) {
		h := newDrainHandler(false)
		h.beginDrain()

		_, err := h.openUpstream(context.Background(), "derp.test", key.NewNode(), &derp.ClientInfo{})
		require.ErrorIs(t, err, adapter.ErrShuttingDown)
	})
}
