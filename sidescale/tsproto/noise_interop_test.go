package tsproto

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"tailscale.com/control/controlbase"
	"tailscale.com/types/key"
)

// TestNoiseInterop drives each wrapper through a full Noise IK handshake against the real
// controlbase reference peer, confirming the byte-event shim and version recovery.
func TestNoiseInterop(t *testing.T) {
	t.Parallel()

	const ver = uint16(CurrentCapabilityVersion)

	t.Run("initiator_vs_reference_server", func(t *testing.T) {
		c1, c2 := net.Pipe()
		t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
		serverKey := key.NewMachine()
		clientKey := key.NewMachine()

		serverCh := make(chan *controlbase.Conn, 1)
		serverErr := make(chan error, 1)
		go func() {
			sc, err := controlbase.Server(t.Context(), c2, serverKey, nil)
			serverErr <- err
			serverCh <- sc
		}()

		initn, err := Initiator(clientKey, serverKey.Public(), ver)
		require.NoError(t, err)
		v, err := InitiationVersion(initn.Header)
		require.NoError(t, err)
		assert.Equal(t, ver, v)
		_, err = c1.Write(initn.Header)
		require.NoError(t, err)

		client, err := initn.Complete(t.Context(), c1)
		require.NoError(t, err)
		require.NoError(t, <-serverErr)
		server := <-serverCh

		assert.Equal(t, server.HandshakeHash(), client.HandshakeHash())
		assert.Equal(t, serverKey.Public(), client.Peer())
		assert.Equal(t, clientKey.Public(), server.Peer())
		assertRoundTrip(t, client, server)
	})

	t.Run("responder_vs_reference_client", func(t *testing.T) {
		c1, c2 := net.Pipe()
		t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
		responderKey := key.NewMachine()
		clientKey := key.NewMachine()

		initHeader, cont, err := controlbase.ClientDeferred(clientKey, responderKey.Public(), ver)
		require.NoError(t, err)
		v, err := InitiationVersion(initHeader)
		require.NoError(t, err)
		assert.Equal(t, ver, v)

		respCh := make(chan *controlbase.Conn, 1)
		respErr := make(chan error, 1)
		go func() {
			rc, err := Responder(t.Context(), c2, responderKey, initHeader)
			respErr <- err
			respCh <- rc
		}()

		client, err := cont(t.Context(), c1)
		require.NoError(t, err)
		require.NoError(t, <-respErr)
		responder := <-respCh

		assert.Equal(t, client.HandshakeHash(), responder.HandshakeHash())
		assert.Equal(t, clientKey.Public(), responder.Peer())
		assert.Equal(t, responderKey.Public(), client.Peer())
		assertRoundTrip(t, client, responder)
	})
}

// assertRoundTrip writes on a and reads the same bytes on b,
// confirming the tunnel carries application data after the handshake.
func assertRoundTrip(t *testing.T, a, b *controlbase.Conn) {
	t.Helper()

	writeErr := make(chan error, 1)
	go func() {
		_, err := a.Write([]byte("ping"))
		writeErr <- err
	}()
	buf := make([]byte, 4)
	_, err := io.ReadFull(b, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))
	require.NoError(t, <-writeErr)
}
