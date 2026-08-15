//go:build unix

package noise

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"tailscale.com/types/key"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
)

func TestSetupKeySubstitution(t *testing.T) {
	t.Parallel()

	t.Run("responder_registers_substituted_key", func(t *testing.T) {
		cfg, err := defaultControlConfig() // substitute + responder defaults
		require.NoError(t, err)

		realKey := key.NewMachine().Public()
		core := newFakeCore()
		hostCfg := sidecar.Config{NativeHTTPSend: fakeKeyResponse(realKey)}
		h := testHandler(t, &cfg, newRecordingFlows(), core, stubRules{}, hostCfg)

		ks, err := setupKeySubstitution(t.Context(), h)
		require.NoError(t, err)
		require.NotNil(t, ks)
		assert.Equal(t, "resp1", ks.responderID)

		got, err := ks.realServerKey(t.Context())
		require.NoError(t, err)
		assert.Equal(t, realKey, got)

		var args struct {
			Origin string `json:"origin"`
			Path   string `json:"path"`
			Body   string `json:"body"`
		}
		require.NoError(t, json.Unmarshal(core.params("proxy_respond_add"), &args))
		assert.Equal(t, "https://"+defaultControlHost, args.Origin)
		assert.Equal(t, "/key", args.Path)
		assert.Contains(t, args.Body, h.responderKey.Public().String())
		assert.NotContains(t, args.Body, realKey.String())
	})

	t.Run("borrow_needs_no_substitution", func(t *testing.T) {
		cfg, err := defaultControlConfig()
		require.NoError(t, err)
		cfg.KeyStrategy = KeyStrategyBorrow

		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, sidecar.Config{})
		ks, err := setupKeySubstitution(t.Context(), h)
		require.NoError(t, err)
		assert.Nil(t, ks)
	})
}

func TestServeKey(t *testing.T) {
	t.Parallel()

	cfg, err := defaultControlConfig()
	require.NoError(t, err)
	cfg.KeySubstitution = KeySubSidecarTLS

	realKey := key.NewMachine().Public()
	hostCfg := sidecar.Config{NativeHTTPSend: fakeKeyResponse(realKey)}
	h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, hostCfg)
	ks, err := setupKeySubstitution(t.Context(), h)
	require.NoError(t, err)
	require.NotNil(t, ks)

	t.Run("serves_substituted_key", func(t *testing.T) {
		client := newMemConn([]byte("GET /key?v=1 HTTP/1.1\r\nHost: controlplane.tailscale.com\r\n\r\n"))
		ks.serveKey(t.Context(), client, "s1")

		out := client.written()
		assert.Contains(t, out, "200 OK")
		assert.Contains(t, out, h.responderKey.Public().String())
		assert.NotContains(t, out, realKey.String())
	})

	t.Run("rejects_non_key_request", func(t *testing.T) {
		client := newMemConn([]byte("POST /machine/register HTTP/1.1\r\nHost: controlplane.tailscale.com\r\nContent-Length: 0\r\n\r\n"))
		ks.serveKey(t.Context(), client, "s2")

		assert.Contains(t, client.written(), "421")
	})
}

// memConn is an in-memory net.Conn for driving stream handlers: Read serves the
// preloaded request then EOF, Write captures the handler's output.
type memConn struct {
	in  *bytes.Reader
	out bytes.Buffer
}

func newMemConn(in []byte) *memConn { return &memConn{in: bytes.NewReader(in)} }

func (c *memConn) written() string { return c.out.String() }

func (c *memConn) Read(p []byte) (int, error)       { return c.in.Read(p) }
func (c *memConn) Write(p []byte) (int, error)      { return c.out.Write(p) }
func (c *memConn) Close() error                     { return nil }
func (c *memConn) LocalAddr() net.Addr              { return nil }
func (c *memConn) RemoteAddr() net.Addr             { return nil }
func (c *memConn) SetDeadline(time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(time.Time) error { return nil }

func TestSubstitutePublicKey(t *testing.T) {
	t.Parallel()

	pub := key.NewMachine().Public()
	out, err := substitutePublicKey([]byte(`{"publicKey":"mkey:00","legacyPublicKey":"mkey:11"}`), pub)
	require.NoError(t, err)
	assert.Contains(t, string(out), pub.String())
	assert.Contains(t, string(out), "legacyPublicKey")
}
