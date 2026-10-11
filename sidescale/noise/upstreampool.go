package noise

import (
	"context"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"tailscale.com/types/key"

	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
)

// upstreamIdleGrace bounds how long a pooled upstream lingers after its last release,
// so a fast client re-dial reuses the live conn rather than rebuilding it.
const upstreamIdleGrace = 30 * time.Second

// poolKey identifies a shared upstream conn; tunnels matching all four fields share it.
type poolKey struct {
	id      key.MachinePublic
	host    string
	version uint16
	session string // see poolSession: "" in shared mode, per-client token in per_client mode
}

// sharedUpstream is a refcounted upstream conn shared by every tunnel with the same
// poolKey, torn down only after the last holder releases and an idle grace elapses.
type sharedUpstream struct {
	key       poolKey
	uc        *upstreamConn
	refs      int
	idleTimer *time.Timer
	closed    bool
	ready     chan struct{} // open while dialing, nil once resolved
	dialErr   error         // dial failure, observed by coalesced waiters
	// dialCanceled marks a dial whose dialer's ctx canceled; waiters with a live ctx
	// re-dial under their own instead of inheriting the failure
	dialCanceled bool
	waiters      atomic.Int32 // parked waiter count; coalesced-dial observability
}

// poolSession returns the pool discriminator for a client-facing tunnel: empty in
// shared mode (all tunnels coalesce onto one upstream), or the per-client token in
// per_client mode (each client gets its own upstream Noise session).
func (h *Handler) poolSession(clientKey string) string {
	if h.cfg.UpstreamPoolMode == PoolModePerClient {
		return clientKey
	}
	return ""
}

// freshPoolSession returns the pool discriminator for a fresh replay/injection tunnel:
// empty in shared mode, or a unique per_client token so each fresh tunnel is isolated.
func (h *Handler) freshPoolSession() string {
	if h.cfg.UpstreamPoolMode == PoolModePerClient {
		return h.dedicatedPoolSession()
	}
	return ""
}

// dedicatedPoolSession returns a globally-unique pool discriminator so a fresh tunnel never
// coalesces onto a shared upstream, even in shared mode (one-shot register replays).
func (h *Handler) dedicatedPoolSession() string {
	return "dedicated-" + strconv.FormatUint(h.freshSeq.Add(1), 10)
}

// getOrCreateUpstream returns the pooled upstream for (machineKey, host, version,
// session) with the caller's ref held, dialing one only when none is live. Concurrent
// callers for the same key coalesce onto a single dial; a dial canceled only by its
// dialer's own context is retried by waiters whose contexts are still live.
func (h *Handler) getOrCreateUpstream(ctx context.Context, host string, machineKey key.MachinePrivate, version uint16, session string) (*sharedUpstream, error) {
	k := poolKey{id: machineKey.Public(), host: host, version: version, session: session}
	for {
		h.mu.Lock()
		if h.draining { // shutdown drain: no new upstream dials
			h.mu.Unlock()
			return nil, adapter.ErrShuttingDown
		}
		if u := h.upstreams[k]; u != nil && !u.closed {
			if u.ready == nil { // established
				h.acquireLocked(u)
				h.mu.Unlock()
				return u, nil
			}
			// dial in flight: wait bounded by our own ctx, then loop to acquire or
			// observe its error
			ready := u.ready
			u.waiters.Add(1)
			h.mu.Unlock()
			select {
			case <-ready:
				u.waiters.Add(-1)
			case <-ctx.Done():
				// abandoned waiter; the in-flight dial still serves the others
				u.waiters.Add(-1)
				return nil, ctx.Err()
			}
			h.mu.Lock()
			dialErr, dialCanceled := u.dialErr, u.dialCanceled
			h.mu.Unlock()
			if dialErr != nil {
				if dialCanceled && ctx.Err() == nil {
					// only the dialer's ctx died and the entry is evicted: re-dial under ours
					continue
				}
				return nil, dialErr
			}
			continue
		}
		// become the sole dialer for this key
		u := &sharedUpstream{key: k, refs: 1, ready: make(chan struct{})}
		h.upstreams[k] = u
		h.mu.Unlock()

		// dial outside h.mu: the handshake reads inbound bytes the router delivers,
		// which must not block on h.mu
		uc, err := h.dialFn(ctx, host, machineKey, version)

		h.mu.Lock()
		ready := u.ready
		u.ready = nil
		if err != nil {
			u.dialErr = err
			// tag at the source from the dialer's ctx state: a hung upstream's deadline
			// or a real failure must not be re-dialed per coalesced waiter
			u.dialCanceled = errors.Is(ctx.Err(), context.Canceled)
			u.closed = true
			if h.upstreams[k] == u {
				delete(h.upstreams, k)
			}
			h.mu.Unlock()
			close(ready)
			return nil, err
		}
		if u.closed { // drained mid-dial: the fresh conn dies here rather than leaking
			h.mu.Unlock()
			close(ready)
			uc.close()
			return nil, adapter.ErrShuttingDown
		}
		u.uc = uc
		h.mu.Unlock()
		close(ready)
		_ = h.conn.Log("info", "upstream connected", map[string]any{
			adapter.FieldStream: uc.streamID, "upstream": uc.addr,
			"machine_key": adapter.KeyPrefix(k.id.String()), "pool_session": k.session,
		})
		return u, nil
	}
}

// tryAcquireUpstream bumps the ref on a tunnel's pooled upstream and returns a release cleanup,
// or ok=false when it was already torn down. A nil u yields a no-op cleanup.
func (h *Handler) tryAcquireUpstream(u *sharedUpstream) (func(), bool) {
	if u == nil {
		return func() {}, true
	}
	h.mu.Lock()
	if u.closed {
		h.mu.Unlock()
		return nil, false
	}
	h.acquireLocked(u)
	h.mu.Unlock()
	return func() { h.releaseUpstream(u) }, true
}

// acquireLocked bumps refs and cancels any pending idle close. Caller holds h.mu.
func (h *Handler) acquireLocked(u *sharedUpstream) {
	u.refs++
	if u.idleTimer != nil {
		u.idleTimer.Stop()
		u.idleTimer = nil
	}
}

// releaseUpstream drops one holder, scheduling an idle teardown once refs reach zero.
func (h *Handler) releaseUpstream(u *sharedUpstream) {
	h.mu.Lock()
	defer h.mu.Unlock()
	u.refs--
	if u.refs > 0 || u.closed {
		return
	}
	if u.idleTimer != nil {
		u.idleTimer.Stop()
	}
	u.idleTimer = time.AfterFunc(upstreamIdleGrace, func() { h.idleCloseUpstream(u) })
}

// idleCloseUpstream tears down the upstream if it is still idle when the grace timer fires.
func (h *Handler) idleCloseUpstream(u *sharedUpstream) {
	h.mu.Lock()
	if u.closed || u.refs > 0 {
		h.mu.Unlock()
		return
	}
	u.closed = true
	if h.upstreams[u.key] == u {
		delete(h.upstreams, u.key)
	}
	h.mu.Unlock()
	u.uc.close() // outside h.mu: uc.close tears the upstream stream down
}

// evictUpstream removes a dead upstream so the next getOrCreateUpstream dials a fresh one.
// reason names the failure that triggered the eviction. Safe with holders still active;
// their later releases become no-ops.
func (h *Handler) evictUpstream(u *sharedUpstream, reason string) {
	h.mu.Lock()
	if u.closed {
		h.mu.Unlock()
		return
	}
	u.closed = true
	if u.idleTimer != nil {
		u.idleTimer.Stop()
		u.idleTimer = nil
	}
	if h.upstreams[u.key] == u {
		delete(h.upstreams, u.key)
	}
	streamID, addr := u.uc.streamID, u.uc.addr // read under lock; uc is stable once dialed
	h.mu.Unlock()
	_ = h.conn.Log("warn", "upstream conn evicted (unusable)", map[string]any{
		adapter.FieldStream: streamID, "upstream": addr,
		"machine_key": adapter.KeyPrefix(u.key.id.String()), "pool_session": u.key.session, "reason": reason,
	})
	u.uc.close()
}
