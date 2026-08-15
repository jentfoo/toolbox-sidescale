//go:build unix

package derp

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/derp"
	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp/derpproto"
)

// relayKeys bundles the private halves behind a test tunnel for box-open assertions.
type relayKeys struct {
	clientPriv         key.NodePrivate
	nodeKey            key.NodePrivate
	upstreamServerPriv key.NodePrivate
}

// registerRelayTunnel wires an activeTunnel with recording client/upstream conns and
// known re-seal keys, returning the conns and keys.
func registerRelayTunnel(h *Handler, flowID string, mesh bool) (clientRC, upstreamRC *recordConn, keys relayKeys) {
	clientRC, upstreamRC = &recordConn{}, &recordConn{}
	keys = relayKeys{clientPriv: key.NewNode(), nodeKey: key.NewNode(), upstreamServerPriv: key.NewNode()}
	h.registerTunnel(flowID, &activeTunnel{
		flowID:      flowID,
		clientKey:   keys.clientPriv.Public(),
		clientFr:    newFrameConn(clientRC),
		upstreamF:   newFrameConn(upstreamRC),
		nodeKey:     keys.nodeKey,
		upstreamPub: keys.upstreamServerPriv.Public(),
		mesh:        mesh,
		host:        "derp.test",
	})
	return
}

func relayConfig() *DerpConfig {
	return &DerpConfig{DerpHosts: []string{"derp.test"}, RelayMode: RelayModeRelay}
}

func TestOnSidecarSendReplay(t *testing.T) {
	t.Parallel()

	t.Run("send_packet_verbatim", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, relayConfig(), flows, stubRules{})
		_, upstreamRC, _ := registerRelayTunnel(h, "tun", false)
		dst := key.NewNode().Public()
		payload := []byte("opaque-packet")

		src := &wire.Flow{
			Direction:    adapter.DirClientToServer,
			ParentFlowID: "tun",
			Request: &wire.FlowMessage{
				Method:    "SEND_PACKET",
				Headers:   []wire.Header{{Name: "X-Derp-Dst-Key", Value: dst.String()}},
				BodyRaw:   payload,
				BodyCodec: packetCodec,
			},
		}
		res, err := h.OnSidecarSend(wire.SidecarSendParams{FlowID: "srcFrame", Flow: src})
		require.NoError(t, err)
		require.Len(t, res.NewFlowIDs, 1)

		frames := upstreamRC.frames()
		require.Len(t, frames, 1)
		assert.Equal(t, derpproto.FrameSendPacket, frames[0].typ)
		assert.Equal(t, append(dst.AppendTo(nil), payload...), frames[0].payload)

		produced := flows.frameFlows()
		require.Len(t, produced, 1)
		// replay parents to the source flow so sectool files it into replay history
		assert.Equal(t, "srcFrame", produced[0].ParentFlowID)
	})

	t.Run("client_info_reseal", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, relayConfig(), flows, stubRules{})
		_, upstreamRC, keys := registerRelayTunnel(h, "tun", false)
		ci, err := json.Marshal(&derp.ClientInfo{Version: derpproto.ProtocolVersion, CanAckPings: true})
		require.NoError(t, err)

		src := &wire.Flow{
			Direction:    adapter.DirClientToServer,
			ParentFlowID: "tun",
			Request:      &wire.FlowMessage{Method: "CLIENT_INFO", Body: ci},
		}
		_, err = h.OnSidecarSend(wire.SidecarSendParams{Flow: src})
		require.NoError(t, err)

		frames := upstreamRC.frames()
		require.Len(t, frames, 1)
		pub, info, err := derpproto.OpenClientInfo(keys.upstreamServerPriv, frames[0].payload)
		require.NoError(t, err)
		assert.Equal(t, keys.nodeKey.Public(), pub)
		assert.True(t, info.CanAckPings)
	})

	t.Run("server_info_reseal", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, relayConfig(), flows, stubRules{})
		clientRC, _, keys := registerRelayTunnel(h, "tun", false)
		si, err := json.Marshal(&derp.ServerInfo{Version: derpproto.ProtocolVersion})
		require.NoError(t, err)

		src := &wire.Flow{
			Direction:    adapter.DirServerToClient,
			ParentFlowID: "tun",
			Response:     &wire.FlowMessage{Method: "SERVER_INFO", Body: si},
		}
		_, err = h.OnSidecarSend(wire.SidecarSendParams{Flow: src})
		require.NoError(t, err)

		frames := clientRC.frames()
		require.Len(t, frames, 1)
		info, err := derpproto.OpenServerInfo(keys.clientPriv, h.serverKey.Public(), frames[0].payload)
		require.NoError(t, err)
		assert.Equal(t, derpproto.ProtocolVersion, info.Version)
	})

	t.Run("packet_body_mutation", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, relayConfig(), flows, stubRules{})
		_, upstreamRC, _ := registerRelayTunnel(h, "tun", false)
		dst := key.NewNode().Public()

		src := &wire.Flow{
			Direction:    adapter.DirClientToServer,
			ParentFlowID: "tun",
			Request: &wire.FlowMessage{
				Method:    "SEND_PACKET",
				Headers:   []wire.Header{{Name: "X-Derp-Dst-Key", Value: dst.String()}},
				BodyRaw:   []byte("original"),
				BodyCodec: packetCodec,
			},
		}
		muts := []wire.Mutation{{Op: "body", Value: "mutated-payload"}}
		_, err := h.OnSidecarSend(wire.SidecarSendParams{Flow: src, Mutations: muts})
		require.NoError(t, err)

		frames := upstreamRC.frames()
		require.Len(t, frames, 1)
		assert.Equal(t, append(dst.AppendTo(nil), []byte("mutated-payload")...), frames[0].payload)
	})

	t.Run("node_key_mutation_annotated", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, relayConfig(), flows, stubRules{})
		_, upstreamRC, keys := registerRelayTunnel(h, "tun", false)
		ci, err := json.Marshal(&derp.ClientInfo{Version: derpproto.ProtocolVersion})
		require.NoError(t, err)
		foreign := key.NewNode().Public()

		src := &wire.Flow{
			Direction:    adapter.DirClientToServer,
			ParentFlowID: "tun",
			Request:      &wire.FlowMessage{Method: "CLIENT_INFO", Body: ci},
		}
		muts := []wire.Mutation{{Op: "set_header", Name: "X-Derp-Node-Key", Value: foreign.String()}}
		_, err = h.OnSidecarSend(wire.SidecarSendParams{Flow: src, Mutations: muts})
		require.NoError(t, err)

		// still sealed with the held node key
		frames := upstreamRC.frames()
		require.Len(t, frames, 1)
		pub, _, err := derpproto.OpenClientInfo(keys.upstreamServerPriv, frames[0].payload)
		require.NoError(t, err)
		assert.Equal(t, keys.nodeKey.Public(), pub)

		produced := flows.frameFlows()
		require.Len(t, produced, 1)
		assert.Equal(t, "derp_node_key", produced[0].Annotations["binding"])
	})

	t.Run("peer_present_tail_roundtrip", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, relayConfig(), flows, stubRules{})
		clientRC, _, _ := registerRelayTunnel(h, "tun", false)
		peer := key.NewNode().Public()
		tail := []byte{10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xab, 0xcd, 0x01} // ip/port/flags
		payload := append(peer.AppendTo(nil), tail...)

		// a captured PEER_PRESENT carries the peer key plus the opaque tail (base64) as headers;
		// building it by hand keeps the round-trip independent of the capture decoder
		msg := &wire.FlowMessage{
			Method: "PEER_PRESENT",
			Headers: []wire.Header{
				{Name: "X-Derp-Peer-Key", Value: peer.String()},
				{Name: "X-Derp-Peer-Present-Tail", Value: base64.StdEncoding.EncodeToString(tail)},
			},
		}

		src := &wire.Flow{Direction: adapter.DirServerToClient, ParentFlowID: "tun", Response: msg}
		_, err := h.OnSidecarSend(wire.SidecarSendParams{Flow: src})
		require.NoError(t, err)

		frames := clientRC.frames()
		require.Len(t, frames, 1)
		assert.Equal(t, derpproto.FramePeerPresent, frames[0].typ)
		assert.Equal(t, payload, frames[0].payload)
	})

	t.Run("torn_down_rejects", func(t *testing.T) {
		h := testHandler(t, relayConfig(), newRecordingFlows(), stubRules{})
		src := &wire.Flow{
			Direction:    adapter.DirServerToClient,
			ParentFlowID: "gone",
			Response:     &wire.FlowMessage{Method: "HEALTH", Body: []byte("x")},
		}
		_, err := h.OnSidecarSend(wire.SidecarSendParams{Flow: src})
		require.ErrorContains(t, err, "gone")
	})

	t.Run("terminate_client_to_server_rejects", func(t *testing.T) {
		h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}, RelayMode: RelayModeTerminate}, newRecordingFlows(), stubRules{})
		joinClient(h, key.NewNode().Public(), "tun")
		src := &wire.Flow{
			Direction:    adapter.DirClientToServer,
			ParentFlowID: "tun",
			Request:      &wire.FlowMessage{Method: "SEND_PACKET", Headers: []wire.Header{{Name: "X-Derp-Dst-Key", Value: key.NewNode().Public().String()}}},
		}
		_, err := h.OnSidecarSend(wire.SidecarSendParams{Flow: src})
		require.ErrorContains(t, err, "no upstream under terminate mode")
	})
}
