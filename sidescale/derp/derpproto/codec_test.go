package derpproto

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
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

// peerPresentPayload builds a FramePeerPresent payload exactly as tailscale's
// derpserver sendPeerPresent writes it (v1.104.0).
func peerPresentPayload(peer key.NodePublic, ipPort netip.AddrPort, flags byte, appName string) []byte {
	out := make([]byte, KeyLen+20+len(appName))
	copy(out, peer.AppendTo(nil))
	a16 := ipPort.Addr().As16()
	copy(out[KeyLen:], a16[:])
	binary.BigEndian.PutUint16(out[KeyLen+16:KeyLen+18], ipPort.Port())
	out[KeyLen+18] = flags
	out[KeyLen+19] = byte(len(appName))
	copy(out[KeyLen+20:], appName)
	return out
}

func TestParsePeerPresentTail(t *testing.T) {
	t.Parallel()

	ipPort := netip.MustParseAddrPort("1.2.3.4:4433")
	tail, err := BuildPeerPresentTail(ipPort, 0x09, "prober")
	require.NoError(t, err)

	t.Run("modern_tail", func(t *testing.T) {
		got := ParsePeerPresentTail(tail)
		assert.True(t, got.HasIPPort)
		assert.Equal(t, ipPort, got.IPPort)
		assert.True(t, got.HasFlags)
		assert.Equal(t, byte(0x09), got.Flags)
		assert.True(t, got.HasAppName)
		assert.Equal(t, "prober", got.AppName)
	})

	t.Run("empty_tail", func(t *testing.T) {
		got := ParsePeerPresentTail(nil)
		assert.False(t, got.HasIPPort)
		assert.False(t, got.HasFlags)
		assert.False(t, got.HasAppName)
	})

	t.Run("ip_port_only", func(t *testing.T) {
		got := ParsePeerPresentTail(tail[:18])
		assert.True(t, got.HasIPPort)
		assert.Equal(t, ipPort, got.IPPort)
		assert.False(t, got.HasFlags)
		assert.False(t, got.HasAppName)
	})

	t.Run("flags_no_name", func(t *testing.T) {
		got := ParsePeerPresentTail(tail[:19])
		assert.True(t, got.HasIPPort)
		assert.True(t, got.HasFlags)
		assert.Equal(t, byte(0x09), got.Flags)
		assert.False(t, got.HasAppName)
	})

	t.Run("truncated_app_name", func(t *testing.T) {
		// name length claims 6 bytes, only 2 present
		got := ParsePeerPresentTail(append(slices.Clone(tail[:20]), 'a', 'b'))
		assert.True(t, got.HasIPPort)
		assert.True(t, got.HasFlags)
		assert.False(t, got.HasAppName)
	})
}

func TestBuildPeerPresentTail(t *testing.T) {
	t.Parallel()

	peer := key.NewNode().Public()
	ipPort := netip.MustParseAddrPort("1.2.3.4:4433")

	t.Run("matches_reference_server", func(t *testing.T) {
		tail, err := BuildPeerPresentTail(ipPort, 0x09, "prober")
		require.NoError(t, err)
		// must match tailscale's derpserver sendPeerPresent byte-for-byte
		assert.Equal(t, peerPresentPayload(peer, ipPort, 0x09, "prober")[KeyLen:], tail)
	})

	t.Run("zero_ip_port_defaults", func(t *testing.T) {
		tail, err := BuildPeerPresentTail(netip.AddrPort{}, 0x01, "")
		require.NoError(t, err)
		// matches the reference server writing a zero AddrPort and empty name
		assert.Equal(t, peerPresentPayload(peer, netip.AddrPort{}, 0x01, "")[KeyLen:], tail)
	})

	t.Run("ipv6", func(t *testing.T) {
		v6 := netip.MustParseAddrPort("[2001:db8::1]:443")
		tail, err := BuildPeerPresentTail(v6, 0x02, "x")
		require.NoError(t, err)

		got := ParsePeerPresentTail(tail)
		assert.True(t, got.HasIPPort)
		assert.Equal(t, v6, got.IPPort)
	})

	t.Run("oversize_app_name_rejected", func(t *testing.T) {
		_, err := BuildPeerPresentTail(netip.AddrPort{}, 0, strings.Repeat("a", 256))
		require.Error(t, err)
	})
}
