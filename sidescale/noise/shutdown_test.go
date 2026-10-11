//go:build unix

package noise

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"

	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
)

// drainConn is a net.Conn standing in for a tunnel's conns: Close signals closed so the
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

	// newDrainHandler returns a bare handler with live maps; no conn, router, or pool.
	newDrainHandler := func() *Handler {
		var h Handler
		h.baseCtx = context.Background()
		h.tunnels = map[string]*activeTunnel{}
		h.upstreams = map[poolKey]*sharedUpstream{}
		return &h
	}

	// addStubTunnel registers a tunnel whose client conn is closed by the drain and
	// whose goroutine then unwinds through deregisterTunnel, mirroring runTunnel.
	addStubTunnel := func(h *Handler, id string) (*activeTunnel, *drainConn) {
		t.Helper()

		client := newDrainConn()
		at := &activeTunnel{flowID: id, client: client, tornDown: make(chan struct{})}
		h.registerTunnel(id, at)
		go func() {
			<-client.closed // unblocked by the drain's force-close
			h.deregisterTunnel(at)
		}()
		return at, client
	}

	t.Run("drains_tracked_tunnels", func(t *testing.T) {
		h := newDrainHandler()
		at1, client1 := addStubTunnel(h, "f1")
		at2, client2 := addStubTunnel(h, "f2")

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
		assert.Nil(t, h.getTunnel("f2"))
		assert.True(t, client1.wasClosed())
		assert.True(t, client2.wasClosed())
	})

	t.Run("counts_open_tunnels_on_expiry", func(t *testing.T) {
		h := newDrainHandler()
		at := &activeTunnel{flowID: "f1", client: newDrainConn(), tornDown: make(chan struct{})}
		h.registerTunnel("f1", at) // no unwind goroutine: teardown never runs

		assert.Equal(t, 1, h.Shutdown(0)) // zero window expires at once
	})

	t.Run("closes_pooled_upstreams", func(t *testing.T) {
		h := newDrainHandler()
		u := &sharedUpstream{key: poolKey{id: key.NewMachine().Public(), host: "ctrl.example"}, refs: 1}
		h.upstreams[u.key] = u

		assert.Zero(t, h.Shutdown(0))

		h.mu.Lock()
		_, ok := h.upstreams[u.key]
		h.mu.Unlock()
		assert.False(t, ok)
		assert.True(t, u.closed)
	})

	t.Run("refuses_upstream_dials_when_draining", func(t *testing.T) {
		h := newDrainHandler()
		h.beginDrain()

		_, err := h.getOrCreateUpstream(context.Background(), "ctrl.example", key.NewMachine(), 0, "")
		require.ErrorIs(t, err, adapter.ErrShuttingDown)
	})
}
