//go:build unix

package derp

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/disco"
	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp/derpproto"
)

func TestDecodeFrameClassification(t *testing.T) {
	t.Parallel()

	dst := key.NewNode().Public()
	// disco needs len >= Magic + keyLen(32) + nonceLen(24)
	discoPayload := append([]byte(disco.Magic), bytes.Repeat([]byte{0}, 56)...)

	t.Run("send_packet_disco", func(t *testing.T) {
		payload := append(dst.AppendTo(nil), discoPayload...)
		f := decodeFrame(derpproto.FrameSendPacket, payload)
		assert.Equal(t, discoPayload, f.bodyRaw)
		assert.Equal(t, dst.String(), headerValue(f.headers, "X-Derp-Dst-Key"))
		assert.Equal(t, "true", headerValue(f.headers, "X-Derp-Disco"))
		assert.Nil(t, f.body)
	})

	t.Run("send_packet_non_disco", func(t *testing.T) {
		payload := append(dst.AppendTo(nil), []byte("not-disco-bytes")...)
		f := decodeFrame(derpproto.FrameSendPacket, payload)
		assert.Equal(t, "false", headerValue(f.headers, "X-Derp-Disco"))
		assert.Equal(t, "15", headerValue(f.headers, "X-Derp-Packet-Len"))
	})

	t.Run("peer_gone", func(t *testing.T) {
		payload := append(dst.AppendTo(nil), 0x01)
		f := decodeFrame(derpproto.FramePeerGone, payload)
		assert.Equal(t, dst.String(), headerValue(f.headers, "X-Derp-Peer-Key"))
		assert.Equal(t, "1", headerValue(f.headers, "X-Derp-Peer-Gone-Reason"))
	})

	t.Run("health_body", func(t *testing.T) {
		f := decodeFrame(derpproto.FrameHealth, []byte("overloaded"))
		assert.Equal(t, []byte("overloaded"), f.body)
		assert.Nil(t, f.bodyRaw)
	})

	t.Run("note_preferred", func(t *testing.T) {
		f := decodeFrame(derpproto.FrameNotePreferred, []byte{1})
		assert.Equal(t, "true", headerValue(f.headers, "X-Derp-Home"))
	})

	t.Run("restarting", func(t *testing.T) {
		payload := []byte{0, 0, 0x27, 0x10, 0, 0, 0x03, 0xe8} // 10000ms, 1000ms
		f := decodeFrame(derpproto.FrameRestarting, payload)
		assert.Equal(t, "10000", headerValue(f.headers, "X-Derp-Reconnect-Ms"))
		assert.Equal(t, "1000", headerValue(f.headers, "X-Derp-Try-For-Ms"))
	})

	t.Run("unknown_passthrough", func(t *testing.T) {
		f := decodeFrame(derpproto.FrameType(0x7f), []byte("opaque"))
		assert.Equal(t, []byte("opaque"), f.bodyRaw)
	})
}

func TestEncodePayloadRoundTrip(t *testing.T) {
	t.Parallel()

	src := key.NewNode().Public()
	dst := key.NewNode().Public()

	cases := []struct {
		name    string
		typ     derpproto.FrameType
		payload []byte
	}{
		{"send_packet", derpproto.FrameSendPacket, append(dst.AppendTo(nil), []byte("payload")...)},
		{"recv_packet", derpproto.FrameRecvPacket, append(src.AppendTo(nil), []byte("payload")...)},
		{"forward_packet", derpproto.FrameForwardPacket, append(append(src.AppendTo(nil), dst.AppendTo(nil)...), []byte("p")...)},
		{"peer_gone", derpproto.FramePeerGone, append(dst.AppendTo(nil), 0x01)},
		{"close_peer", derpproto.FrameClosePeer, dst.AppendTo(nil)},
		{"note_preferred", derpproto.FrameNotePreferred, []byte{1}},
		{"ping", derpproto.FramePing, []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{"restarting", derpproto.FrameRestarting, []byte{0, 0, 0x27, 0x10, 0, 0, 0x03, 0xe8}},
		{"health", derpproto.FrameHealth, []byte("text")},
		{"unknown", derpproto.FrameType(0x7f), []byte("opaque")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := decodeFrame(tc.typ, tc.payload)
			assert.Equal(t, tc.payload, encodePayload(f))
		})
	}
}

func TestDecodeFrameShortPayload(t *testing.T) {
	t.Parallel()

	peer := key.NewNode().Public()

	t.Run("legacy_peer_gone", func(t *testing.T) {
		payload := peer.AppendTo(nil) // 32-byte key only, no reason byte
		f := decodeFrame(derpproto.FramePeerGone, payload)
		_, hasKey := headerLookup(f.headers, "X-Derp-Peer-Key")
		assert.False(t, hasKey)
		assert.Equal(t, base64.StdEncoding.EncodeToString(payload), headerValue(f.headers, "X-Derp-Raw-Payload"))
	})

	t.Run("short_packet_whole_payload", func(t *testing.T) {
		f := decodeFrame(derpproto.FrameSendPacket, []byte("tiny"))
		assert.Equal(t, []byte("tiny"), f.bodyRaw)
		_, hasKey := headerLookup(f.headers, "X-Derp-Dst-Key")
		assert.False(t, hasKey)
	})

	t.Run("short_peer_present", func(t *testing.T) {
		f := decodeFrame(derpproto.FramePeerPresent, []byte("short-tail"))
		_, hasKey := headerLookup(f.headers, "X-Derp-Peer-Key")
		assert.False(t, hasKey)
		assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("short-tail")), headerValue(f.headers, "X-Derp-Raw-Payload"))
	})

	t.Run("short_close_peer", func(t *testing.T) {
		f := decodeFrame(derpproto.FrameClosePeer, []byte("short"))
		assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("short")), headerValue(f.headers, "X-Derp-Raw-Payload"))
	})

	t.Run("short_restarting", func(t *testing.T) {
		payload := []byte{0, 0, 0x27, 0x10} // reconnect only, no try-for
		f := decodeFrame(derpproto.FrameRestarting, payload)
		_, hasReconnect := headerLookup(f.headers, "X-Derp-Reconnect-Ms")
		assert.False(t, hasReconnect)
		assert.Equal(t, base64.StdEncoding.EncodeToString(payload), headerValue(f.headers, "X-Derp-Raw-Payload"))
	})

	t.Run("empty_peer_gone_header_present", func(t *testing.T) {
		// an empty payload encodes to an empty value, which must stay distinct from absence
		f := decodeFrame(derpproto.FramePeerGone, nil)
		_, hasRaw := headerLookup(f.headers, "X-Derp-Raw-Payload")
		assert.True(t, hasRaw)
	})
}

func TestEncodePayloadShortFrameRoundTrip(t *testing.T) {
	t.Parallel()

	peer := key.NewNode().Public()
	cases := []struct {
		name    string
		typ     derpproto.FrameType
		payload []byte
	}{
		{"legacy_peer_gone", derpproto.FramePeerGone, peer.AppendTo(nil)},
		{"empty_peer_gone", derpproto.FramePeerGone, []byte{}},
		{"short_send_packet", derpproto.FrameSendPacket, []byte("sub-key-len")},
		{"empty_send_packet", derpproto.FrameSendPacket, []byte{}},
		{"short_recv_packet", derpproto.FrameRecvPacket, []byte("sub")},
		{"short_forward_packet", derpproto.FrameForwardPacket, []byte("sub-two-keys")},
		{"short_peer_present", derpproto.FramePeerPresent, []byte("short-tail")},
		{"short_close_peer", derpproto.FrameClosePeer, []byte("short")},
		{"short_restarting", derpproto.FrameRestarting, []byte{0, 0, 0x27, 0x10}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// round-trip through the flow message, the shape a replay actually receives
			msg := frameMessage(tc.typ, decodeFrame(tc.typ, tc.payload))
			assert.Equal(t, tc.payload, encodePayload(frameFromMessage(msg, tc.typ)))
		})
	}
}

func TestEncodePayloadEditedShortFrame(t *testing.T) {
	t.Parallel()

	peer := key.NewNode().Public()

	t.Run("peer_gone_typed_headers_win", func(t *testing.T) {
		// operator edits an undecodable capture to typed headers: rebuild is header-driven
		f := decodeFrame(derpproto.FramePeerGone, peer.AppendTo(nil))
		f.headers = append(f.headers,
			wire.Header{Name: "X-Derp-Peer-Key", Value: peer.String()},
			wire.Header{Name: "X-Derp-Peer-Gone-Reason", Value: "2"},
		)
		assert.Equal(t, append(peer.AppendTo(nil), 0x02), encodePayload(f))
	})

	t.Run("restarting_single_duration_header_wins", func(t *testing.T) {
		f := decodeFrame(derpproto.FrameRestarting, []byte{0, 0, 0x27, 0x10})
		f.headers = append(f.headers, wire.Header{Name: "X-Derp-Try-For-Ms", Value: "1000"})
		assert.Equal(t, []byte{0, 0, 0, 0, 0, 0, 0x03, 0xe8}, encodePayload(f))
	})

	t.Run("packet_key_header_added_rebuilds", func(t *testing.T) {
		f := decodeFrame(derpproto.FrameSendPacket, []byte("sub"))
		f.headers = append(f.headers, wire.Header{Name: "X-Derp-Dst-Key", Value: peer.String()})
		assert.Equal(t, append(peer.AppendTo(nil), []byte("sub")...), encodePayload(f))
	})

	t.Run("malformed_raw_header_falls_back", func(t *testing.T) {
		f := frameFields{typ: derpproto.FramePeerGone, headers: []wire.Header{
			{Name: "X-Derp-Raw-Payload", Value: "not-base64!"},
		}}
		assert.Equal(t, bytes.Repeat([]byte{0}, key.NodePublicRawLen+1), encodePayload(f))
	})
}

func TestCaptureFrame(t *testing.T) {
	t.Parallel()

	src := key.NewNode().Public()

	t.Run("packet_no_rule_forwarded_verbatim", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}}, flows, stubRules{})
		frame := derpproto.EncodeFrame(derpproto.FrameRecvPacket, append(src.AppendTo(nil), []byte("packet")...))

		out, err := h.captureFrame(t.Context(), "tun1", frame, adapter.DirServerToClient)
		require.NoError(t, err)
		assert.Equal(t, frame, out)

		captured := flows.frameFlows()
		require.Len(t, captured, 1)
		assert.Equal(t, adapter.DirServerToClient, captured[0].Direction)
		assert.Equal(t, "tun1", captured[0].ParentFlowID)
		require.NotNil(t, captured[0].Response)
		assert.Equal(t, "RECV_PACKET", captured[0].Response.Method)
		assert.Equal(t, "/derp/recv_packet", captured[0].Response.Path)
		assert.Equal(t, []byte("packet"), captured[0].Response.BodyRaw)
		require.NotNil(t, captured[0].Response.BodyCodec)
		assert.Equal(t, src.String(), captured[0].Response.Headers.Get("X-Derp-Src-Key"))
	})

	t.Run("health_rule_emits_mutated_flow", func(t *testing.T) {
		flows := newRecordingFlows()
		rules := stubRules{rules: []wire.Rule{{RuleID: "r1", Type: wire.RuleTypeResponseBody, Find: "old", Replace: "new"}}}
		h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}}, flows, rules)
		frame := derpproto.EncodeFrame(derpproto.FrameHealth, []byte("old-problem"))

		out, err := h.captureFrame(t.Context(), "tun1", frame, adapter.DirServerToClient)
		require.NoError(t, err)
		assert.Contains(t, string(out), "new-problem")

		// only the mutated flow is emitted, mirroring the native proxy
		captured := flows.frameFlows()
		require.Len(t, captured, 1)
		assert.Contains(t, string(captured[0].Response.Body), "new-problem")
	})

	t.Run("client_to_server_uses_request_rule", func(t *testing.T) {
		flows := newRecordingFlows()
		// a response_body rule must NOT fire on a client->server frame
		rules := stubRules{rules: []wire.Rule{{RuleID: "r1", Type: wire.RuleTypeResponseBody, Find: "old", Replace: "new"}}}
		h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}}, flows, rules)
		frame := derpproto.EncodeFrame(derpproto.FrameHealth, []byte("old"))

		out, err := h.captureFrame(t.Context(), "tun1", frame, adapter.DirClientToServer)
		require.NoError(t, err)
		assert.Equal(t, frame, out) // unchanged: wrong rule side
		require.Len(t, flows.frameFlows(), 1)
	})
}

func TestCaptureHandshakeFrame(t *testing.T) {
	t.Parallel()

	flows := newRecordingFlows()
	h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}}, flows, stubRules{})
	nodePub := key.NewNode().Public()
	box := []byte("rawbox")
	info := []byte(`{"version":2}`)

	require.NoError(t, h.captureHandshakeFrame(t.Context(), "tun1", derpproto.FrameClientInfo, nodePub, box, info, adapter.DirClientToServer))

	captured := flows.frameFlows()
	require.Len(t, captured, 1)
	require.NotNil(t, captured[0].Request)
	assert.Equal(t, "CLIENT_INFO", captured[0].Request.Method)
	assert.Equal(t, info, captured[0].Request.Body)
	assert.Equal(t, nodePub.String(), captured[0].Request.Headers.Get("X-Derp-Node-Key"))
	assert.Equal(t, base64.StdEncoding.EncodeToString(box), captured[0].Request.Headers.Get("X-Derp-Box"))
}
