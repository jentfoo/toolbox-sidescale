//go:build unix

package derp

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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

func TestInjectFrame(t *testing.T) {
	t.Parallel()

	t.Run("server_to_client", func(t *testing.T) {
		peer := key.NewNode().Public()
		src := key.NewNode().Public()
		packet := []byte("relayed-bytes")

		cases := []struct {
			name    string
			req     injectionRequest
			wantTyp derpproto.FrameType
			assert  func(t *testing.T, payload []byte)
		}{
			{
				name:    "recv_packet_spoofed_src",
				req:     injectionRequest{Frame: "RECV_PACKET", SrcKey: src.String(), Body: base64.StdEncoding.EncodeToString(packet)},
				wantTyp: derpproto.FrameRecvPacket,
				assert: func(t *testing.T, payload []byte) {
					t.Helper()
					assert.Equal(t, append(src.AppendTo(nil), packet...), payload)
				},
			},
			{
				name:    "peer_gone",
				req:     injectionRequest{Frame: "PEER_GONE", PeerKey: peer.String(), Reason: 2},
				wantTyp: derpproto.FramePeerGone,
				assert: func(t *testing.T, payload []byte) {
					t.Helper()
					assert.Equal(t, peer.AppendTo(nil), payload[:key.NodePublicRawLen])
					assert.Equal(t, byte(2), payload[key.NodePublicRawLen])
				},
			},
			{
				name:    "peer_present",
				req:     injectionRequest{Frame: "PEER_PRESENT", PeerKey: peer.String(), Flags: 1},
				wantTyp: derpproto.FramePeerPresent,
				assert: func(t *testing.T, payload []byte) {
					t.Helper()
					assert.Equal(t, peer.AppendTo(nil), payload[:key.NodePublicRawLen])
					assert.Equal(t, byte(1), payload[key.NodePublicRawLen])
				},
			},
			{
				name:    "health",
				req:     injectionRequest{Frame: "HEALTH", Body: "degraded"},
				wantTyp: derpproto.FrameHealth,
				assert: func(t *testing.T, payload []byte) {
					t.Helper()
					assert.Equal(t, []byte("degraded"), payload)
				},
			},
			{
				name:    "restarting",
				req:     injectionRequest{Frame: "RESTARTING", ReconnectMs: 1000, TryForMs: 5000},
				wantTyp: derpproto.FrameRestarting,
				assert: func(t *testing.T, payload []byte) {
					t.Helper()
					require.Len(t, payload, 8)
					assert.Equal(t, uint32(1000), binary.BigEndian.Uint32(payload[:4]))
					assert.Equal(t, uint32(5000), binary.BigEndian.Uint32(payload[4:8]))
				},
			},
			{
				name:    "pong",
				req:     injectionRequest{Frame: "PONG", Body: base64.StdEncoding.EncodeToString([]byte("12345678"))},
				wantTyp: derpproto.FramePong,
				assert: func(t *testing.T, payload []byte) {
					t.Helper()
					assert.Equal(t, []byte("12345678"), payload)
				},
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				flows := newRecordingFlows()
				h := testHandler(t, relayConfig(), flows, stubRules{})
				clientRC, _, _ := registerRelayTunnel(h, "tun", false)
				tc.req.TunnelID = "tun"

				res, err := h.OnInvokeTool(wire.InvokeToolParams{Name: InjectToolName, Arguments: injectArgs(tc.req)})
				require.NoError(t, err)
				assert.False(t, res.IsError)

				frames := clientRC.frames()
				require.Len(t, frames, 1)
				assert.Equal(t, tc.wantTyp, frames[0].typ)
				tc.assert(t, frames[0].payload)

				produced := flows.frameFlows()
				require.Len(t, produced, 1)
				assert.Equal(t, true, produced[0].Annotations[adapter.AnnInjected])
			})
		}
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
		peer := key.NewNode().Public()

		t.Run("rejected_without_mesh", func(t *testing.T) {
			h := testHandler(t, relayConfig(), newRecordingFlows(), stubRules{})
			registerRelayTunnel(h, "tun", false)
			ir := injectionRequest{TunnelID: "tun", Frame: "CLOSE_PEER", PeerKey: peer.String()}
			_, err := h.injectFrame(t.Context(), ir)
			assert.Error(t, err)
		})

		t.Run("accepted_with_mesh", func(t *testing.T) {
			h := testHandler(t, relayConfig(), newRecordingFlows(), stubRules{})
			_, upstreamRC, _ := registerRelayTunnel(h, "tun", true)
			ir := injectionRequest{TunnelID: "tun", Frame: "CLOSE_PEER", PeerKey: peer.String()}
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
