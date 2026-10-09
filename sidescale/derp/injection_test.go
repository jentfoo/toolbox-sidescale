//go:build unix

package derp

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp/derpproto"
)

// injectArgs marshals an injection request to raw JSON.
func injectArgs(ir injectionRequest) json.RawMessage {
	b, _ := json.Marshal(ir)
	return b
}

// injectToClient registers a relay tunnel "tun", sends ir through the derp_inject tool,
// and returns the recorded flows plus the single frame its client received.
func injectToClient(t *testing.T, ir injectionRequest) (*recordingFlows, capturedFrame) {
	t.Helper()

	flows := newRecordingFlows()
	h := testHandler(t, relayConfig(), flows, stubRules{})
	clientRC, _, _ := registerRelayTunnel(h, "tun", false)

	ir.TunnelID = "tun"
	res, err := h.OnInvokeTool(wire.InvokeToolParams{Name: InjectToolName, Arguments: injectArgs(ir)})
	require.NoError(t, err)
	assert.False(t, res.IsError)

	frames := clientRC.frames()
	require.Len(t, frames, 1)
	return flows, frames[0]
}

func TestInjectFrame(t *testing.T) {
	t.Parallel()

	peer := key.NewNode().Public()
	src := key.NewNode().Public()
	packet := []byte("relayed-bytes")

	t.Run("server_to_client", func(t *testing.T) {
		t.Run("recv_packet_spoofed_src", func(t *testing.T) {
			flows, fr := injectToClient(t, injectionRequest{Frame: "RECV_PACKET", SrcKey: src.String(), Body: base64.StdEncoding.EncodeToString(packet)})
			assert.Equal(t, derpproto.FrameRecvPacket, fr.typ)
			assert.Equal(t, append(src.AppendTo(nil), packet...), fr.payload)

			produced := flows.frameFlows()
			require.Len(t, produced, 1)
			assert.Equal(t, true, produced[0].Annotations[adapter.AnnInjected])
		})

		t.Run("peer_gone", func(t *testing.T) {
			_, fr := injectToClient(t, injectionRequest{Frame: "PEER_GONE", PeerKey: peer.String(), Reason: 2})
			assert.Equal(t, derpproto.FramePeerGone, fr.typ)
			require.Len(t, fr.payload, key.NodePublicRawLen+1)
			assert.Equal(t, peer.AppendTo(nil), fr.payload[:key.NodePublicRawLen])
			assert.Equal(t, byte(2), fr.payload[key.NodePublicRawLen])
		})

		t.Run("peer_present_flags_tail", func(t *testing.T) {
			_, fr := injectToClient(t, injectionRequest{Frame: "PEER_PRESENT", PeerKey: peer.String(), Flags: 1})
			assert.Equal(t, derpproto.FramePeerPresent, fr.typ)
			// modern tail with a zero ip/port and flags at key+18
			require.Len(t, fr.payload, key.NodePublicRawLen+20)
			assert.Equal(t, peer.AppendTo(nil), fr.payload[:key.NodePublicRawLen])
			assert.Equal(t, make([]byte, 18), fr.payload[key.NodePublicRawLen:key.NodePublicRawLen+18])
			assert.Equal(t, byte(1), fr.payload[key.NodePublicRawLen+18])
		})

		t.Run("peer_present_full_tail", func(t *testing.T) {
			ir := injectionRequest{Frame: "PEER_PRESENT", PeerKey: peer.String(), Flags: 9, IPPort: "1.2.3.4:4433", AppName: "prober"}
			_, fr := injectToClient(t, ir)
			assert.Equal(t, derpproto.FramePeerPresent, fr.typ)
			// key + v6-mapped ip + port + flags + nameLen + name
			require.Len(t, fr.payload, key.NodePublicRawLen+20+len(ir.AppName))
			ip := netip.AddrFrom16([16]byte(fr.payload[key.NodePublicRawLen : key.NodePublicRawLen+16])).Unmap()
			assert.Equal(t, netip.MustParseAddr("1.2.3.4"), ip)
			tail := fr.payload[key.NodePublicRawLen:]
			assert.Equal(t, uint16(4433), binary.BigEndian.Uint16(tail[16:]))
			assert.Equal(t, byte(9), tail[18])
			assert.Equal(t, byte(len(ir.AppName)), tail[19])
			assert.Equal(t, ir.AppName, string(tail[20:]))
		})

		t.Run("peer_present_bare_key", func(t *testing.T) {
			_, fr := injectToClient(t, injectionRequest{Frame: "PEER_PRESENT", PeerKey: peer.String()})
			assert.Equal(t, derpproto.FramePeerPresent, fr.typ)
			// legacy form every real client parses as a no-flags announcement
			assert.Equal(t, peer.AppendTo(nil), fr.payload)
		})

		t.Run("health", func(t *testing.T) {
			_, fr := injectToClient(t, injectionRequest{Frame: "HEALTH", Body: "degraded"})
			assert.Equal(t, derpproto.FrameHealth, fr.typ)
			assert.Equal(t, []byte("degraded"), fr.payload)
		})

		t.Run("restarting", func(t *testing.T) {
			_, fr := injectToClient(t, injectionRequest{Frame: "RESTARTING", ReconnectMs: 1000, TryForMs: 5000})
			assert.Equal(t, derpproto.FrameRestarting, fr.typ)
			require.Len(t, fr.payload, 8)
			assert.Equal(t, uint32(1000), binary.BigEndian.Uint32(fr.payload[:4]))
			assert.Equal(t, uint32(5000), binary.BigEndian.Uint32(fr.payload[4:8]))
		})

		t.Run("pong", func(t *testing.T) {
			_, fr := injectToClient(t, injectionRequest{Frame: "PONG", Body: base64.StdEncoding.EncodeToString([]byte("12345678"))})
			assert.Equal(t, derpproto.FramePong, fr.typ)
			assert.Equal(t, []byte("12345678"), fr.payload)
		})

		t.Run("invalid_flags_rejected", func(t *testing.T) {
			h := testHandler(t, relayConfig(), newRecordingFlows(), stubRules{})
			registerRelayTunnel(h, "tun", false)

			ir := injectionRequest{TunnelID: "tun", Frame: "PEER_PRESENT", PeerKey: peer.String(), Flags: 0x1ff}
			res, err := h.OnInvokeTool(wire.InvokeToolParams{Name: InjectToolName, Arguments: injectArgs(ir)})
			require.NoError(t, err)
			assert.True(t, res.IsError)
		})

		t.Run("invalid_ip_port_rejected", func(t *testing.T) {
			h := testHandler(t, relayConfig(), newRecordingFlows(), stubRules{})
			registerRelayTunnel(h, "tun", false)

			ir := injectionRequest{TunnelID: "tun", Frame: "PEER_PRESENT", PeerKey: peer.String(), IPPort: "1.2.3.4"}
			res, err := h.OnInvokeTool(wire.InvokeToolParams{Name: InjectToolName, Arguments: injectArgs(ir)})
			require.NoError(t, err)
			assert.True(t, res.IsError)
		})

		t.Run("oversize_app_name_rejected", func(t *testing.T) {
			h := testHandler(t, relayConfig(), newRecordingFlows(), stubRules{})
			registerRelayTunnel(h, "tun", false)

			ir := injectionRequest{TunnelID: "tun", Frame: "PEER_PRESENT", PeerKey: peer.String(), AppName: strings.Repeat("a", 256)}
			res, err := h.OnInvokeTool(wire.InvokeToolParams{Name: InjectToolName, Arguments: injectArgs(ir)})
			require.NoError(t, err)
			assert.True(t, res.IsError)
		})
	})

	t.Run("client_to_server", func(t *testing.T) {
		t.Run("send_packet", func(t *testing.T) {
			flows := newRecordingFlows()
			h := testHandler(t, relayConfig(), flows, stubRules{})
			_, upstreamRC, _ := registerRelayTunnel(h, "tun", false)
			dst := key.NewNode().Public()
			packet := []byte("payload")

			ir := injectionRequest{TunnelID: "tun", Frame: "SEND_PACKET", DstKey: dst.String(), Body: base64.StdEncoding.EncodeToString(packet)}
			_, err := h.injectFrame(t.Context(), ir)
			require.NoError(t, err)

			frames := upstreamRC.frames()
			require.Len(t, frames, 1)
			assert.Equal(t, derpproto.FrameSendPacket, frames[0].typ)
			assert.Equal(t, append(dst.AppendTo(nil), packet...), frames[0].payload)
		})

		t.Run("note_preferred", func(t *testing.T) {
			flows := newRecordingFlows()
			h := testHandler(t, relayConfig(), flows, stubRules{})
			_, upstreamRC, _ := registerRelayTunnel(h, "tun", false)

			ir := injectionRequest{TunnelID: "tun", Frame: "NOTE_PREFERRED", Home: true}
			_, err := h.injectFrame(t.Context(), ir)
			require.NoError(t, err)

			frames := upstreamRC.frames()
			require.Len(t, frames, 1)
			assert.Equal(t, derpproto.FrameNotePreferred, frames[0].typ)
			assert.Equal(t, []byte{1}, frames[0].payload)
		})
	})

	t.Run("ping", func(t *testing.T) {
		h := testHandler(t, relayConfig(), newRecordingFlows(), stubRules{})
		clientRC, _, _ := registerRelayTunnel(h, "tun", false)

		ir := injectionRequest{TunnelID: "tun", Frame: "PING", Body: base64.StdEncoding.EncodeToString([]byte("abcdefgh"))}
		_, err := h.injectFrame(t.Context(), ir)
		require.NoError(t, err)

		frames := clientRC.frames()
		require.Len(t, frames, 1)
		assert.Equal(t, derpproto.FramePing, frames[0].typ)
		assert.Equal(t, []byte("abcdefgh"), frames[0].payload)
	})

	t.Run("hex_type", func(t *testing.T) {
		h := testHandler(t, relayConfig(), newRecordingFlows(), stubRules{})
		clientRC, _, _ := registerRelayTunnel(h, "tun", false)

		ir := injectionRequest{TunnelID: "tun", Frame: "0x99", Direction: adapter.DirServerToClient, Body: base64.StdEncoding.EncodeToString([]byte("raw"))}
		_, err := h.injectFrame(t.Context(), ir)
		require.NoError(t, err)

		frames := clientRC.frames()
		require.Len(t, frames, 1)
		assert.Equal(t, derpproto.FrameType(0x99), frames[0].typ)
		assert.Equal(t, []byte("raw"), frames[0].payload)
	})

	t.Run("invalid_key", func(t *testing.T) {
		h := testHandler(t, relayConfig(), newRecordingFlows(), stubRules{})
		registerRelayTunnel(h, "tun", false)

		ir := injectionRequest{TunnelID: "tun", Frame: "PEER_GONE", PeerKey: "not-a-key", Reason: 1}
		_, err := h.injectFrame(t.Context(), ir)
		assert.Error(t, err)
	})

	t.Run("mesh_gating", func(t *testing.T) {
		meshPeer := key.NewNode().Public()

		t.Run("rejected_without_mesh", func(t *testing.T) {
			h := testHandler(t, relayConfig(), newRecordingFlows(), stubRules{})
			registerRelayTunnel(h, "tun", false)
			ir := injectionRequest{TunnelID: "tun", Frame: "CLOSE_PEER", PeerKey: meshPeer.String()}
			_, err := h.injectFrame(t.Context(), ir)
			assert.Error(t, err)
		})

		t.Run("accepted_with_mesh", func(t *testing.T) {
			h := testHandler(t, relayConfig(), newRecordingFlows(), stubRules{})
			_, upstreamRC, _ := registerRelayTunnel(h, "tun", true)
			ir := injectionRequest{TunnelID: "tun", Frame: "CLOSE_PEER", PeerKey: meshPeer.String()}
			_, err := h.injectFrame(t.Context(), ir)
			require.NoError(t, err)
			frames := upstreamRC.frames()
			require.Len(t, frames, 1)
			assert.Equal(t, derpproto.FrameClosePeer, frames[0].typ)
		})
	})

	t.Run("terminate", func(t *testing.T) {
		aPub, bPub := key.NewNode().Public(), key.NewNode().Public()

		t.Run("targets_named_client", func(t *testing.T) {
			h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}, RelayMode: RelayModeTerminate}, newRecordingFlows(), stubRules{})
			rcA, _ := joinClient(h, aPub, "tunA")
			rcB, _ := joinClient(h, bPub, "tunB")

			ir := injectionRequest{TunnelID: "tunB", Frame: "HEALTH", Body: "hi-b"}
			_, err := h.injectFrame(t.Context(), ir)
			require.NoError(t, err)

			assert.Empty(t, rcA.frames())
			frames := rcB.frames()
			require.Len(t, frames, 1)
			assert.Equal(t, derpproto.FrameHealth, frames[0].typ)
		})

		t.Run("unknown_tunnel_rejects", func(t *testing.T) {
			h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}, RelayMode: RelayModeTerminate}, newRecordingFlows(), stubRules{})
			ir := injectionRequest{TunnelID: "nope", Frame: "HEALTH", Body: "x"}
			_, err := h.injectFrame(t.Context(), ir)
			assert.Error(t, err)
		})
	})
}
