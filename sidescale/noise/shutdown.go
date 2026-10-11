package noise

import (
	"context"
	"time"

	"github.com/go-analyze/bulk"
)

// Shutdown drains the surface within sectool's drain_seconds window: active tunnels are
// force-closed, unwind through their own teardown (completing envelope flows), and new
// work is refused. Returns the count of tunnels still open when the window closed; a
// wedged tunnel cannot stall shutdown past it.
func (h *Handler) Shutdown(drainSeconds int) int {
	h.beginDrain()

	// snapshot first: teardown deregisters from the live map while we wait
	live := h.liveTunnels()
	for _, at := range live {
		closeTunnelNow(at)
	}
	h.drainUpstreams()

	ctx, cancel := context.WithTimeout(h.baseCtx, time.Duration(drainSeconds)*time.Second)
	defer cancel()
	var left int
	for _, at := range live {
		select {
		case <-at.tornDown:
		case <-ctx.Done():
			left++
		}
	}
	return left
}

// closeTunnelNow force-closes at's conns to start its unwind: teardown then completes
// the envelope, releases the upstream ref, and deregisters it (closing tornDown).
func closeTunnelNow(at *activeTunnel) {
	if at.client != nil { // fresh replay/injection tunnels have no client half
		_ = at.client.Close()
	}
	if _, bridge := at.current(); bridge != nil {
		_ = bridge.Close()
	}
}

// drainUpstreams closes every pooled upstream conn, established or dialing. A dial still
// in flight has no conn yet; its getOrCreateUpstream observes the closed flag and discards
// the fresh conn when it lands.
func (h *Handler) drainUpstreams() {
	h.mu.Lock()
	live := bulk.MapValuesSlice(h.upstreams)
	for _, u := range live {
		u.closed = true
		if u.idleTimer != nil {
			u.idleTimer.Stop()
			u.idleTimer = nil
		}
		delete(h.upstreams, u.key)
	}
	h.mu.Unlock()
	for _, u := range live {
		if u.uc != nil { // a dial-in-flight entry has no conn yet
			u.uc.close() // outside h.mu: uc.close tears the upstream stream down
		}
	}
}

// liveTunnels returns the registered tunnels. The snapshot isolates the drain from
// teardown mutating the underlying map.
func (h *Handler) liveTunnels() []*activeTunnel {
	h.mu.Lock()
	defer h.mu.Unlock()

	return bulk.MapValuesSlice(h.tunnels)
}

// beginDrain latches the surface into shutdown: new tunnels and upstream dials are
// refused from here on. One-way; a draining handler is torn down with its session.
func (h *Handler) beginDrain() {
	h.mu.Lock()
	h.draining = true
	h.mu.Unlock()
}

// Draining reports whether a shutdown drain has begun.
func (h *Handler) Draining() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	return h.draining
}
