package derpproto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/derp"
	"tailscale.com/types/key"
)

func TestSplitFrame(t *testing.T) {
	t.Parallel()

	zeroLen := EncodeFrame(FrameKeepAlive, nil)           // 5-byte header, empty payload
	full := EncodeFrame(FrameServerInfo, []byte("hello")) // 10 bytes total

	oversize := make([]byte, FrameHeaderLen)
	oversize[0] = byte(FrameSendPacket)
	// declared length one over the cap
	oversize[1], oversize[2], oversize[3], oversize[4] = 0x00, 0x10, 0x00, 0x01

	tests := []struct {
		name    string
		buf     []byte
		wantN   int
		wantOK  bool
		wantErr bool
	}{
		{"empty", nil, 0, false, false},
		{"short_header", []byte{0x02, 0x00, 0x00}, 0, false, false},
		{"zero_len_frame", zeroLen, FrameHeaderLen, true, false},
		{"partial_payload", full[:8], 0, false, false},
		{"exact_frame", full, len(full), true, false},
		{"trailing_bytes", append(append([]byte{}, full...), 0xAA, 0xBB), len(full), true, false},
		{"oversized", oversize, 0, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, ok, err := SplitFrame(tt.buf)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantN, n)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFrameHeader(t *testing.T) {
	t.Parallel()

	frame := EncodeFrame(FramePeerGone, make([]byte, 33))

	typ, n, ok := FrameHeader(frame)
	require.True(t, ok)
	assert.Equal(t, FramePeerGone, typ)
	assert.Equal(t, 33, n)

	_, _, ok = FrameHeader([]byte{0x08, 0x00})
	assert.False(t, ok)
}

func TestFrameTypeByName(t *testing.T) {
	t.Parallel()

	typ, ok := FrameTypeByName("RECV_PACKET")
	require.True(t, ok)
	assert.Equal(t, FrameRecvPacket, typ)

	_, ok = FrameTypeByName("NOPE")
	assert.False(t, ok)
}

func TestEncodeFrame(t *testing.T) {
	t.Parallel()

	payload := []byte("payload-bytes")
	frame := EncodeFrame(FrameHealth, payload)

	typ, n, ok := FrameHeader(frame)
	require.True(t, ok)
	assert.Equal(t, FrameHealth, typ)
	assert.Equal(t, len(payload), n)
	assert.Equal(t, payload, FramePayload(frame))
}

func TestServerKeyPayload(t *testing.T) {
	t.Parallel()

	serverPub := key.NewNode().Public()

	got, err := ParseServerKey(ServerKeyPayload(serverPub))
	require.NoError(t, err)
	assert.Equal(t, serverPub, got)

	_, err = ParseServerKey([]byte("too-short"))
	require.Error(t, err)

	bad := ServerKeyPayload(serverPub)
	bad[0] ^= 0xff
	_, err = ParseServerKey(bad)
	assert.Error(t, err)
}

func TestClientInfoRoundTrip(t *testing.T) {
	t.Parallel()

	clientPriv := key.NewNode()
	serverPriv := key.NewNode()
	info := &derp.ClientInfo{Version: ProtocolVersion, CanAckPings: true}

	payload, err := ClientInfoPayload(clientPriv, serverPriv.Public(), info)
	require.NoError(t, err)

	gotPub, gotInfo, err := OpenClientInfo(serverPriv, payload)
	require.NoError(t, err)
	assert.Equal(t, clientPriv.Public(), gotPub)
	assert.True(t, info.Equal(gotInfo))

	t.Run("wrong_server_key", func(t *testing.T) {
		_, _, err := OpenClientInfo(key.NewNode(), payload)
		assert.Error(t, err)
	})
	t.Run("short_payload", func(t *testing.T) {
		_, _, err := OpenClientInfo(serverPriv, payload[:KeyLen-1])
		assert.Error(t, err)
	})
}

func TestServerInfoRoundTrip(t *testing.T) {
	t.Parallel()

	serverPriv := key.NewNode()
	clientPriv := key.NewNode()
	info := &derp.ServerInfo{Version: ProtocolVersion}

	payload, err := ServerInfoPayload(serverPriv, clientPriv.Public(), info)
	require.NoError(t, err)

	got, err := OpenServerInfo(clientPriv, serverPriv.Public(), payload)
	require.NoError(t, err)
	assert.Equal(t, info.Version, got.Version)

	_, err = OpenServerInfo(key.NewNode(), serverPriv.Public(), payload)
	assert.Error(t, err)
}
