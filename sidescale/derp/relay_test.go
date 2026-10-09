//go:build unix

package derp

import (
	"bytes"
	"context"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-analyze/bulk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/mem"
	"tailscale.com/derp"
	"tailscale.com/disco"
	"tailscale.com/types/key"

	"github.com/jentfoo/toolbox-sidescale/sidescale/derp/derpproto"
)

// recordConn is a net.Conn whose writes are captured for assertions. Reads return EOF
// (nothing drives frames back through it), and the remaining methods are no-op stubs.
type recordConn struct {
	mu     sync.Mutex
	writes bytes.Buffer
}

func (c *recordConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes.Write(p)
}

func (*recordConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (*recordConn) Close() error                     { return nil }
func (*recordConn) LocalAddr() net.Addr              { return nil }
func (*recordConn) RemoteAddr() net.Addr             { return nil }
func (*recordConn) SetDeadline(time.Time) error      { return nil }
func (*recordConn) SetReadDeadline(time.Time) error  { return nil }
func (*recordConn) SetWriteDeadline(time.Time) error { return nil }

// capturedFrame is a decoded frame captured by a recordConn.
type capturedFrame struct {
	typ     derpproto.FrameType
	payload []byte
}

// frames decodes every complete frame the conn has captured.
func (c *recordConn) frames() []capturedFrame {
	c.mu.Lock()
	buf := bytes.Clone(c.writes.Bytes())
	c.mu.Unlock()
	var out []capturedFrame
	for len(buf) >= derpproto.FrameHeaderLen {
		n, ok, err := derpproto.SplitFrame(buf)
		if !ok || err != nil {
			break
		}
		t, _, _ := derpproto.FrameHeader(buf[:n])
		out = append(out, capturedFrame{t, derpproto.FramePayload(buf[:n])})
		buf = buf[n:]
	}
	return out
}

// framesOfType returns the frames rc captured of the given type.
func framesOfType(rc *recordConn, t derpproto.FrameType) []capturedFrame {
	return bulk.SliceFilter(func(f capturedFrame) bool { return f.typ == t }, rc.frames())
}

// hasFrame reports whether rc captured a frame of the given type.
func hasFrame(rc *recordConn, t derpproto.FrameType) bool {
	return slices.ContainsFunc(rc.frames(), func(f capturedFrame) bool { return f.typ == t })
}

// joinClient registers a non-mesh synthetic-relay client with a recording conn.
func joinClient(h *Handler, pub key.NodePublic, tunnelID string) (*recordConn, *relayClient) {
	return joinClientMesh(h, pub, tunnelID, false)
}

// joinClientMesh registers a synthetic-relay client with the given mesh flag.
func joinClientMesh(h *Handler, pub key.NodePublic, tunnelID string, mesh bool) (*recordConn, *relayClient) {
	rc := &recordConn{}
	c := h.relay.register(pub, newFrameConn(rc), tunnelID, mesh)
	return rc, c
}

// routePacket routes one SendPacket from src to dst, recording src as a sender for its dup set.
func routePacket(ctx context.Context, h *Handler, src *relayClient, dst key.NodePublic, data string) {
	h.relay.route(ctx, src, append(dst.AppendTo(nil), []byte(data)...))
}

func terminateHandler(t *testing.T, policy string) *Handler {
	t.Helper()
	return testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}, RelayMode: RelayModeTerminate, DupPolicy: policy}, newRecordingFlows(), stubRules{})
}

func TestSyntheticRelayRoute(t *testing.T) {
	t.Parallel()

	aPub := key.NewNode().Public()
	bPub := key.NewNode().Public()
	kPub := key.NewNode().Public()
	sPub := key.NewNode().Public()
	unknown := key.NewNode().Public()

	t.Run("send_delivered_as_recv", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}, RelayMode: RelayModeTerminate}, flows, stubRules{})
		_, aClient := joinClient(h, aPub, "tunA")
		rcB, _ := joinClient(h, bPub, "tunB")

		payload := append(bPub.AppendTo(nil), []byte("hello-peer")...)
		h.relay.route(t.Context(), aClient, payload)

		frames := rcB.frames()
		require.Len(t, frames, 1)
		assert.Equal(t, derpproto.FrameRecvPacket, frames[0].typ)
		src := key.NodePublicFromRaw32(mem.B(frames[0].payload[:key.NodePublicRawLen]))
		assert.Equal(t, aPub, src)
		assert.Equal(t, []byte("hello-peer"), frames[0].payload[key.NodePublicRawLen:])

		// captured on the recipient's tunnel as RECV_PACKET
		captured := flows.frameFlows()
		require.Len(t, captured, 1)
		assert.Equal(t, "tunB", captured[0].ParentFlowID)
		assert.Equal(t, "RECV_PACKET", captured[0].Response.Method)
	})

	t.Run("disco_dst_peer_gone", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}, RelayMode: RelayModeTerminate}, flows, stubRules{})
		rcA, aClient := joinClient(h, aPub, "tunA")

		discoMsg := append([]byte(disco.Magic), bytes.Repeat([]byte{0}, 56)...)
		payload := append(bPub.AppendTo(nil), discoMsg...)
		h.relay.route(t.Context(), aClient, payload)

		frames := rcA.frames()
		require.Len(t, frames, 1)
		assert.Equal(t, derpproto.FramePeerGone, frames[0].typ)
		assert.Equal(t, byte(derp.PeerGoneReasonNotHere), frames[0].payload[key.NodePublicRawLen])

		// the originated PeerGone is also captured on the sender's tunnel
		captured := flows.frameFlows()
		require.Len(t, captured, 1)
		assert.Equal(t, "tunA", captured[0].ParentFlowID)
		assert.Equal(t, "PEER_GONE", captured[0].Response.Method)
	})

	t.Run("unregistered_dst_non_disco_dropped", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}, RelayMode: RelayModeTerminate}, flows, stubRules{})
		rcA, aClient := joinClient(h, aPub, "tunA")

		payload := append(bPub.AppendTo(nil), []byte("plain-not-disco")...)
		h.relay.route(t.Context(), aClient, payload)

		assert.Empty(t, rcA.frames())
	})

	t.Run("disconnect_synthesizes_peer_gone", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}, RelayMode: RelayModeTerminate}, flows, stubRules{})
		_, aClient := joinClient(h, aPub, "tunA")
		rcB, _ := joinClient(h, bPub, "tunB")

		// B receives from A, so B is told when A leaves
		h.relay.route(t.Context(), aClient, append(bPub.AppendTo(nil), []byte("x")...))
		rcB.mu.Lock()
		rcB.writes.Reset()
		rcB.mu.Unlock()

		h.relay.remove(t.Context(), aClient)

		frames := rcB.frames()
		require.Len(t, frames, 1)
		assert.Equal(t, derpproto.FramePeerGone, frames[0].typ)
		assert.Equal(t, byte(derp.PeerGoneReasonDisconnected), frames[0].payload[key.NodePublicRawLen])
		gone := key.NodePublicFromRaw32(mem.B(frames[0].payload[:key.NodePublicRawLen]))
		assert.Equal(t, aPub, gone)

		// registry cleaned up
		h.relay.mu.Lock()
		_, stillA := h.relay.byKey[aPub]
		h.relay.mu.Unlock()
		assert.False(t, stillA)
	})

	t.Run("dup_key_newest_active", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyLastWriter)
		rc1, _ := joinClient(h, kPub, "tun1")
		rc2, _ := joinClient(h, kPub, "tun2")
		_, sender := joinClient(h, sPub, "tunS")

		routePacket(t.Context(), h, sender, kPub, "hi")
		assert.True(t, hasFrame(rc2, derpproto.FrameRecvPacket))
		assert.False(t, hasFrame(rc1, derpproto.FrameRecvPacket))
	})

	t.Run("last_writer_becomes_active", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyLastWriter)
		rc1, c1 := joinClient(h, kPub, "tun1")
		rc2, _ := joinClient(h, kPub, "tun2") // newest, active on connect
		_, sender := joinClient(h, sPub, "tunS")

		routePacket(t.Context(), h, c1, unknown, "x") // c1 speaks, becomes active
		routePacket(t.Context(), h, sender, kPub, "hi")
		assert.True(t, hasFrame(rc1, derpproto.FrameRecvPacket))
		assert.False(t, hasFrame(rc2, derpproto.FrameRecvPacket))
	})

	t.Run("active_drop_promotes_survivor", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyLastWriter)
		rc1, _ := joinClient(h, kPub, "tun1")
		_, c2 := joinClient(h, kPub, "tun2") // active
		_, sender := joinClient(h, sPub, "tunS")

		h.relay.remove(t.Context(), c2)
		routePacket(t.Context(), h, sender, kPub, "hi")
		assert.True(t, hasFrame(rc1, derpproto.FrameRecvPacket))
	})

	t.Run("active_drop_promotes_recent_sender", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyLastWriter)
		rc1, c1 := joinClient(h, kPub, "tun1")
		rc2, _ := joinClient(h, kPub, "tun2")
		_, c3 := joinClient(h, kPub, "tun3") // active, never sends
		_, sender := joinClient(h, sPub, "tunS")

		routePacket(t.Context(), h, c1, unknown, "x") // c1 is the last sender
		h.relay.remove(t.Context(), c3)               // departing active, three survivors
		routePacket(t.Context(), h, sender, kPub, "hi")
		assert.True(t, hasFrame(rc1, derpproto.FrameRecvPacket))
		assert.False(t, hasFrame(rc2, derpproto.FrameRecvPacket))
	})

	t.Run("active_drop_silent_set_promotes_newest", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyLastWriter)
		rc1, _ := joinClient(h, kPub, "tun1")
		rc2, _ := joinClient(h, kPub, "tun2")
		_, c3 := joinClient(h, kPub, "tun3") // active
		_, sender := joinClient(h, sPub, "tunS")

		h.relay.remove(t.Context(), c3) // nobody ever sent, fall back to connect order
		routePacket(t.Context(), h, sender, kPub, "hi")
		assert.True(t, hasFrame(rc2, derpproto.FrameRecvPacket))
		assert.False(t, hasFrame(rc1, derpproto.FrameRecvPacket))
	})

	t.Run("old_conn_teardown_no_spurious_gone", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyLastWriter)
		_, c1 := joinClient(h, kPub, "tun1")
		rc2, c2 := joinClient(h, kPub, "tun2") // active
		rcP, _ := joinClient(h, sPub, "tunP")

		routePacket(t.Context(), h, c2, sPub, "seen") // P received from K
		h.relay.remove(t.Context(), c1)               // old connection tears down

		assert.False(t, hasFrame(rcP, derpproto.FramePeerGone))
		assert.Same(t, c2, h.relay.byTunnelID("tun2"))

		_, sender := joinClient(h, key.NewNode().Public(), "tunS")
		routePacket(t.Context(), h, sender, kPub, "hi")
		assert.True(t, hasFrame(rc2, derpproto.FrameRecvPacket))
	})

	t.Run("last_conn_departure_announces_gone", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyLastWriter)
		_, c1 := joinClient(h, kPub, "tun1")
		_, c2 := joinClient(h, kPub, "tun2")
		rcP, _ := joinClient(h, sPub, "tunP")

		routePacket(t.Context(), h, c2, sPub, "seen") // P received from K
		h.relay.remove(t.Context(), c1)
		assert.False(t, hasFrame(rcP, derpproto.FramePeerGone)) // K still present
		h.relay.remove(t.Context(), c2)

		gone := framesOfType(rcP, derpproto.FramePeerGone)
		require.Len(t, gone, 1)
		assert.Equal(t, byte(derp.PeerGoneReasonDisconnected), gone[0].payload[key.NodePublicRawLen])
	})

	t.Run("disable_fighters_interleaved_sends", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyDisableFighters)
		rc1, c1 := joinClient(h, kPub, "tun1")
		rc2, c2 := joinClient(h, kPub, "tun2")
		_, sender := joinClient(h, sPub, "tunS")

		routePacket(t.Context(), h, c1, unknown, "a") // interleaved: c1, c2, c1 => fighting
		routePacket(t.Context(), h, c2, unknown, "b")
		routePacket(t.Context(), h, c1, unknown, "c")

		routePacket(t.Context(), h, sender, kPub, "hi")
		assert.False(t, hasFrame(rc1, derpproto.FrameRecvPacket))
		assert.False(t, hasFrame(rc2, derpproto.FrameRecvPacket))
	})

	t.Run("disable_fighters_same_conn_repeats", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyDisableFighters)
		rc1, c1 := joinClient(h, kPub, "tun1")
		rc2, _ := joinClient(h, kPub, "tun2") // newest, active under disable_fighters
		_, sender := joinClient(h, sPub, "tunS")

		routePacket(t.Context(), h, c1, unknown, "a")
		routePacket(t.Context(), h, c1, unknown, "b") // same speaker, no fight => set stays enabled
		routePacket(t.Context(), h, sender, kPub, "hi")
		assert.True(t, hasFrame(rc2, derpproto.FrameRecvPacket))
		assert.False(t, hasFrame(rc1, derpproto.FrameRecvPacket))
	})

	t.Run("disable_fighters_collapse_reenables", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyDisableFighters)
		rc1, c1 := joinClient(h, kPub, "tun1")
		_, c2 := joinClient(h, kPub, "tun2")
		_, sender := joinClient(h, sPub, "tunS")

		routePacket(t.Context(), h, c1, unknown, "a") // trigger fight => disabled
		routePacket(t.Context(), h, c2, unknown, "b")
		routePacket(t.Context(), h, c1, unknown, "c")

		h.relay.remove(t.Context(), c2) // collapse to one, re-enable
		routePacket(t.Context(), h, sender, kPub, "hi")
		assert.True(t, hasFrame(rc1, derpproto.FrameRecvPacket))
	})

	t.Run("disable_fighters_active_drop_promotes", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyDisableFighters)
		rc1, c1 := joinClient(h, kPub, "tun1")
		rc2, _ := joinClient(h, kPub, "tun2")
		_, c3 := joinClient(h, kPub, "tun3") // active
		_, sender := joinClient(h, sPub, "tunS")

		routePacket(t.Context(), h, c1, unknown, "x") // c1 is the last sender
		h.relay.remove(t.Context(), c3)
		routePacket(t.Context(), h, sender, kPub, "hi")
		assert.True(t, hasFrame(rc1, derpproto.FrameRecvPacket))
		assert.False(t, hasFrame(rc2, derpproto.FrameRecvPacket))
	})

	t.Run("disable_fighters_promotion_skips_disabled", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyDisableFighters)
		rc1, c1 := joinClient(h, kPub, "tun1")
		rc2, c2 := joinClient(h, kPub, "tun2")
		_, c3 := joinClient(h, kPub, "tun3")
		_, sender := joinClient(h, sPub, "tunS")

		// c3 sends twice without a fight, then c1 repeats after c2: all three disabled
		routePacket(t.Context(), h, c3, unknown, "a")
		routePacket(t.Context(), h, c3, unknown, "b")
		routePacket(t.Context(), h, c1, unknown, "c")
		routePacket(t.Context(), h, c2, unknown, "d")
		routePacket(t.Context(), h, c1, unknown, "e")

		h.relay.remove(t.Context(), c3) // departing active, survivors all disabled
		routePacket(t.Context(), h, sender, kPub, "hi")
		assert.False(t, hasFrame(rc1, derpproto.FrameRecvPacket))
		assert.False(t, hasFrame(rc2, derpproto.FrameRecvPacket)) // set stays disabled, stays dark
	})

	t.Run("disable_fighters_disco_dropped_silently", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyDisableFighters)
		_, c1 := joinClient(h, kPub, "tun1")
		_, c2 := joinClient(h, kPub, "tun2")
		rcS, sender := joinClient(h, sPub, "tunS")

		routePacket(t.Context(), h, c1, unknown, "a") // disable the K set
		routePacket(t.Context(), h, c2, unknown, "b")
		routePacket(t.Context(), h, c1, unknown, "c")

		discoMsg := append([]byte(disco.Magic), bytes.Repeat([]byte{0}, 56)...)
		h.relay.route(t.Context(), sender, append(kPub.AppendTo(nil), discoMsg...))
		assert.False(t, hasFrame(rcS, derpproto.FramePeerGone)) // disabled set != absent key
	})
}

// dupSetSnapshot returns a key's live-conn count and cloned sendHistory under the relay mutex.
func dupSetSnapshot(t *testing.T, h *Handler, k key.NodePublic) (conns int, hist []*relayClient) {
	t.Helper()
	h.relay.mu.Lock()
	defer h.relay.mu.Unlock()

	cs := h.relay.byKey[k]
	require.NotNil(t, cs)
	return len(cs.conns), slices.Clone(cs.sendHistory)
}

func TestSyntheticRelaySendHistory(t *testing.T) {
	t.Parallel()

	kPub := key.NewNode().Public()
	unknown := key.NewNode().Public()

	t.Run("removed_conn_trimmed_from_history", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyDisableFighters)
		_, c1 := joinClient(h, kPub, "tun1")
		_, c2 := joinClient(h, kPub, "tun2")
		joinClient(h, kPub, "tun3") // silent survivor
		_, c4 := joinClient(h, kPub, "tun4")

		routePacket(t.Context(), h, c1, unknown, "a") // history [c1, c2]
		routePacket(t.Context(), h, c2, unknown, "b")

		h.relay.remove(t.Context(), c4) // silent conn departs with three survivors
		conns, hist := dupSetSnapshot(t, h, kPub)
		assert.Equal(t, 3, conns)
		require.Len(t, hist, 2)
		assert.Same(t, c1, hist[0])
		assert.Same(t, c2, hist[1])

		h.relay.remove(t.Context(), c2) // a recorded sender departs with two survivors
		conns, hist = dupSetSnapshot(t, h, kPub)
		assert.Equal(t, 2, conns)
		require.Len(t, hist, 1)
		assert.Same(t, c1, hist[0])
	})

	t.Run("repeat_sender_not_duplicated", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyDisableFighters)
		_, c1 := joinClient(h, kPub, "tun1")
		_, c2 := joinClient(h, kPub, "tun2")

		routePacket(t.Context(), h, c1, unknown, "a") // history [c1]
		routePacket(t.Context(), h, c2, unknown, "b") // history [c1, c2]
		routePacket(t.Context(), h, c1, unknown, "c") // interleaved => fighting

		conns, hist := dupSetSnapshot(t, h, kPub)
		assert.Equal(t, 2, conns)
		require.Len(t, hist, 2) // moved to end, not appended a second time
		assert.Same(t, c2, hist[0])
		assert.Same(t, c1, hist[1])
		assert.True(t, c1.disabled) // fight detection unaffected by the dedupe
		assert.True(t, c2.disabled)
	})

	t.Run("recorded_under_last_writer", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyLastWriter)
		_, c1 := joinClient(h, kPub, "tun1")
		_, c2 := joinClient(h, kPub, "tun2")
		joinClient(h, kPub, "tun3") // silent

		routePacket(t.Context(), h, c2, unknown, "a")
		routePacket(t.Context(), h, c1, unknown, "b")
		routePacket(t.Context(), h, c1, unknown, "c") // repeat, moved not duplicated

		conns, hist := dupSetSnapshot(t, h, kPub)
		assert.Equal(t, 3, conns)
		require.Len(t, hist, 2) // only senders recorded
		assert.Same(t, c2, hist[0])
		assert.Same(t, c1, hist[1])
	})

	t.Run("churn_bounded_by_live_conns", func(t *testing.T) {
		h := terminateHandler(t, DupPolicyDisableFighters)
		joinClient(h, kPub, "tunP1") // persistent pair never speaks
		joinClient(h, kPub, "tunP2")

		const rounds = 50
		for i := range rounds {
			_, c := joinClient(h, kPub, "tunC"+strconv.Itoa(i))
			routePacket(t.Context(), h, c, unknown, "x") // sole send by the short-lived conn

			conns, hist := dupSetSnapshot(t, h, kPub)
			assert.LessOrEqual(t, len(hist), conns) // bounded while the churn conn is live
			h.relay.remove(t.Context(), c)

			conns, hist = dupSetSnapshot(t, h, kPub)
			require.Equal(t, 2, conns)
			assert.False(t, slices.Contains(hist, c)) // departed sender never lingers
		}

		_, hist := dupSetSnapshot(t, h, kPub)
		assert.Empty(t, hist) // only the silent pair remains; nothing recorded
	})
}

// feedConn is a recordConn that also serves preset bytes on Read, for driving terminateLoop.
type feedConn struct {
	recordConn
	rd *bytes.Reader
}

func (c *feedConn) Read(p []byte) (int, error) { return c.rd.Read(p) }

func TestTerminateLoop(t *testing.T) {
	t.Parallel()

	sPub := key.NewNode().Public()
	pPub := key.NewNode().Public()
	h := terminateHandler(t, DupPolicyLastWriter)
	rcP, _ := joinClient(h, pPub, "tunP")

	frame := derpproto.EncodeFrame(derpproto.FrameSendPacket, append(pPub.AppendTo(nil), []byte("hi")...))
	feed := &feedConn{rd: bytes.NewReader(frame)}
	sender := h.relay.register(sPub, newFrameConn(feed), "tunS", false)
	h.terminateLoop(t.Context(), "tunS", sender)

	recv := framesOfType(rcP, derpproto.FrameRecvPacket)
	require.Len(t, recv, 1)
	src := key.NodePublicFromRaw32(mem.B(recv[0].payload[:key.NodePublicRawLen]))
	assert.Equal(t, sPub, src)
	assert.Equal(t, []byte("hi"), recv[0].payload[key.NodePublicRawLen:])
}
