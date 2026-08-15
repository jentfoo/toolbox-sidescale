//go:build unix

package derp

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/derp"
	"tailscale.com/types/key"

	"github.com/jentfoo/toolbox-sidescale/sidescale/derp/derpproto"
)

func TestUpstreamDial(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		hosts     []string
		overrides map[string]string
		wantHost  string
		wantPort  int
		wantTLS   bool
	}{
		{"default_443_tls", []string{"derp.test"}, nil, "derp.test", 443, true},
		{"configured_port_no_override", []string{"derp.test:3340"}, nil, "derp.test", 3340, true},
		{"override_wins_over_configured", []string{"derp.test:3340"}, map[string]string{"derp.test": "http://1.2.3.4:9340"}, "1.2.3.4", 9340, false},
		{"override_url_http", []string{"derp.test"}, map[string]string{"derp.test": "http://1.2.3.4:8080"}, "1.2.3.4", 8080, false},
		{"override_hostport_tls", []string{"derp.test"}, map[string]string{"derp.test": "1.2.3.4:8443"}, "1.2.3.4", 8443, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := &Handler{cfg: &DerpConfig{DerpHosts: tc.hosts, UpstreamOverrides: tc.overrides}}
			host, port, useTLS := h.upstreamDial("derp.test")
			assert.Equal(t, tc.wantHost, host)
			assert.Equal(t, tc.wantPort, port)
			assert.Equal(t, tc.wantTLS, useTLS)
		})
	}
}

// byteConn is a minimal net.Conn over a fixed reader, for frameConn tests.
type byteConn struct {
	net.Conn
	r io.Reader
}

func (c byteConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c byteConn) Write(p []byte) (int, error) { return len(p), nil }

func TestFrameConnReassembly(t *testing.T) {
	t.Parallel()

	t.Run("splits_multiple_frames", func(t *testing.T) {
		f1 := derpproto.EncodeFrame(derpproto.FrameHealth, []byte("one"))
		f2 := derpproto.EncodeFrame(derpproto.FramePeerGone, bytes.Repeat([]byte{0}, key.NodePublicRawLen+1))
		fc := newFrameConn(byteConn{r: bytes.NewReader(append(f1, f2...))})

		got1, err := fc.ReadFrame()
		require.NoError(t, err)
		assert.Equal(t, f1, got1)
		got2, err := fc.ReadFrame()
		require.NoError(t, err)
		assert.Equal(t, f2, got2)
		_, err = fc.ReadFrame()
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("oversize_frame_tears_down", func(t *testing.T) {
		var hdr [derpproto.FrameHeaderLen]byte
		hdr[0] = byte(derpproto.FrameHealth)
		binary.BigEndian.PutUint32(hdr[1:], derpproto.MaxFrameBytes+1)
		fc := newFrameConn(byteConn{r: bytes.NewReader(hdr[:])})

		_, err := fc.ReadFrame()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds max")
	})

	t.Run("prefix_preserved", func(t *testing.T) {
		frame := derpproto.EncodeFrame(derpproto.FrameHealth, []byte("hi"))
		fc := newFrameConn(byteConn{r: bytes.NewReader(nil)})
		fc.prefix(frame)
		got, err := fc.ReadFrame()
		require.NoError(t, err)
		assert.Equal(t, frame, got)
	})
}

func TestEmitTunnelEnvelope(t *testing.T) {
	t.Parallel()
	clientPub := key.NewNode().Public()
	upstreamPub := key.NewNode().Public()
	sidecarPub := key.NewNode().Public()

	t.Run("relay_carries_upstream_headers", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}}, flows, stubRules{})
		id, err := h.emitTunnelEnvelope(t.Context(), envelopeInfo{
			tunnelKey:    "s1",
			clientAddr:   "1.2.3.4:5",
			upstreamAddr: "derp.test:443",
			clientPub:    clientPub,
			clientInfo:   &derp.ClientInfo{Version: 2},
			serverInfo:   &derp.ServerInfo{Version: 2},
			upstreamPub:  upstreamPub,
			nodeKey:      sidecarPub,
			relayMode:    RelayModeRelay,
		})
		require.NoError(t, err)
		require.NotEmpty(t, id)

		fl, ok := flows.Get(id)
		require.True(t, ok)
		assert.Equal(t, tunnelProtocolTag, fl.ProtocolTag)
		require.NotNil(t, fl.Request)
		assert.Equal(t, "TUNNEL", fl.Request.Method)
		assert.Equal(t, "/sidescale.test/derp/tunnel/s1", fl.Request.Path)
		assert.Equal(t, RelayModeRelay, fl.Request.Headers.Get("X-Derp-Relay-Mode"))
		assert.Equal(t, h.serverKey.Public().String(), fl.Request.Headers.Get("X-Derp-Client-Facing-Server-Pubkey"))
		assert.Equal(t, upstreamPub.String(), fl.Request.Headers.Get("X-Derp-Server-Facing-Server-Pubkey"))
		assert.Equal(t, sidecarPub.String(), fl.Request.Headers.Get("X-Derp-Sidecar-Node-Pubkey"))
		assert.Equal(t, clientPub.String(), fl.Request.Headers.Get("X-Derp-Client-Node-Pubkey"))
		assert.Equal(t, "false", fl.Request.Headers.Get("X-Derp-Mesh"))
	})

	t.Run("terminate_omits_upstream_headers", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &DerpConfig{DerpHosts: []string{"derp.test"}, RelayMode: RelayModeTerminate}, flows, stubRules{})
		id, err := h.emitTunnelEnvelope(t.Context(), envelopeInfo{
			tunnelKey:  "s1",
			clientPub:  clientPub,
			clientInfo: &derp.ClientInfo{Version: 2},
			serverInfo: &derp.ServerInfo{Version: 2},
			relayMode:  RelayModeTerminate,
		})
		require.NoError(t, err)

		fl, ok := flows.Get(id)
		require.True(t, ok)
		assert.Equal(t, RelayModeTerminate, fl.Request.Headers.Get("X-Derp-Relay-Mode"))
		assert.Empty(t, fl.Request.Headers.Get("X-Derp-Server-Facing-Server-Pubkey"))
		assert.Empty(t, fl.Request.Headers.Get("X-Derp-Upstream-Addr"))
	})
}
