package derp

import (
	"context"
	"time"

	"github.com/go-analyze/bulk"
)

// Shutdown drains the surface within sectool's drain_seconds window: active tunnels and
// terminate-mode relay clients are force-closed, unwind through their own teardown
// (completing envelope flows), and new work is refused. Returns the count of tracked
// tunnels still open when the window closed; a wedged conn cannot stall shutdown past it.
func (h *Handler) Shutdown(drainSeconds int) int {
	h.beginDrain()

	// snapshot first: teardown deregisters from the live map while we wait
	live := h.liveTunnels()
	for _, at := range live {
		at.forceClose()
	}
	if h.relay != nil { // terminate mode: force-close every synthetic-relay client
		h.relay.closeAll()
	}

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
