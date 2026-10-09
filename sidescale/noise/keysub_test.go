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

		subs, err := setupKeySubstitution(t.Context(), h)
		require.NoError(t, err)
		ks, ok := subs[defaultControlHost]
		require.True(t, ok)
		label := "sidescale-keysub-" + defaultControlHost
		assert.Equal(t, label, ks.responderID)

		got, err := ks.realServerKey(t.Context())
		require.NoError(t, err)
		assert.Equal(t, realKey, got)

		var args struct {
			Host  string `json:"host"`
			Path  string `json:"path"`
			Label string `json:"label"`
			Body  string `json:"body"`
		}
		require.NoError(t, json.Unmarshal(core.params("proxy_respond_add"), &args))
		// host passes through verbatim (responders match by host, port/scheme-agnostic)
		assert.Equal(t, defaultControlHost, args.Host)
		assert.Equal(t, "/key", args.Path)
		assert.Equal(t, label, args.Label)
		assert.Contains(t, args.Body, h.responderKey.Public().String())
		assert.NotContains(t, args.Body, realKey.String())

		// replace-on-add: the stale entry is dropped under the same label first
		var del struct {
			ID string `json:"id"`
		}
		require.NoError(t, json.Unmarshal(core.params("proxy_respond_delete"), &del))
		assert.Equal(t, label, del.ID)
		calls := core.calls() // workflow init precedes the responder pair
		require.Len(t, calls, 3)
		assert.Equal(t, []string{"proxy_respond_delete", "proxy_respond_add"}, calls[1:])
	})

	t.Run("multi_host_substitutes_each", func(t *testing.T) {
		cfg, err := defaultControlConfig()
		require.NoError(t, err)
		cfg.ControlHosts = []string{"ctrl1.test:8443", "ctrl2.test", "CTRL1.Test"}

		key1, key2 := key.NewMachine().Public(), key.NewMachine().Public()
		core := newFakeCore()
		hostCfg := sidecar.Config{NativeHTTPSend: fakeKeyResponseByHost(map[string]key.MachinePublic{
			"ctrl1.test": key1,
			"ctrl2.test": key2,
		})}
		h := testHandler(t, &cfg, newRecordingFlows(), core, stubRules{}, hostCfg)

		subs, err := setupKeySubstitution(t.Context(), h)
		require.NoError(t, err)
		h.keysub = subs // Setup's assignment; the harness skips Setup
		// the ported and bare ctrl1 spellings share one entry
		require.Len(t, subs, 2)

		got1, err := subs["ctrl1.test"].realServerKey(t.Context())
		require.NoError(t, err)
		assert.Equal(t, key1, got1)
		got2, err := subs["ctrl2.test"].realServerKey(t.Context())
		require.NoError(t, err)
		assert.Equal(t, key2, got2)

		// lookup tolerates case and port forms arriving on the stream
		same, err := h.keysubFor("CTRL1.Test:8443").realServerKey(t.Context())
		require.NoError(t, err)
		assert.Equal(t, key1, same)

		// one responder per distinct host, labeled per host
		adds := core.allParams("proxy_respond_add")
		require.Len(t, adds, 2)
		labels := map[string]string{}
		for _, raw := range adds {
			var args struct {
				Host  string `json:"host"`
				Label string `json:"label"`
				Body  string `json:"body"`
			}
			require.NoError(t, json.Unmarshal(raw, &args))
			labels[args.Host] = args.Label
			assert.Contains(t, args.Body, h.responderKey.Public().String())
		}
		assert.Equal(t, map[string]string{
			"ctrl1.test": "sidescale-keysub-ctrl1.test",
			"ctrl2.test": "sidescale-keysub-ctrl2.test",
		}, labels)
	})

	t.Run("multi_host_fetch_failure_keeps_partial", func(t *testing.T) {
		cfg, err := defaultControlConfig()
		require.NoError(t, err)
		cfg.ControlHosts = []string{"ok.test", "down.test"}

		hostCfg := sidecar.Config{NativeHTTPSend: fakeKeyResponseByHost(map[string]key.MachinePublic{
			"ok.test": key.NewMachine().Public(), // down.test has no key: fetch fails
		})}
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, hostCfg)

		// the partially built state is returned with the error, so Setup can install it
		subs, err := setupKeySubstitution(t.Context(), h)
		require.Error(t, err)
		require.ErrorContains(t, err, "down.test")
		assert.Equal(t, map[string]*keySubstituter{"ok.test": subs["ok.test"]}, subs)
	})

	t.Run("multi_host_register_failure_keeps_responder", func(t *testing.T) {
		cfg, err := defaultControlConfig()
		require.NoError(t, err)
		cfg.ControlHosts = []string{"a.test", "b.test"}
		hostCfg := sidecar.Config{NativeHTTPSend: fakeKeyResponse(key.NewMachine().Public())}
		core := &failAddCore{fakeCore: newFakeCore(), failHost: "b.test"}
		h := testHandler(t, &cfg, newRecordingFlows(), core, stubRules{}, hostCfg)

		// a.test's responder registered before b.test's add failed: Close must still
		// deregister it via the returned partial map
		subs, err := setupKeySubstitution(t.Context(), h)
		require.Error(t, err)
		require.ErrorContains(t, err, "register /key responder")
		require.Len(t, subs, 2)
		assert.Equal(t, "sidescale-keysub-a.test", subs["a.test"].responderID)

		subs["a.test"].close(t.Context())
		var del struct {
			ID string `json:"id"`
		}
		last := core.params("proxy_respond_delete")
		require.NoError(t, json.Unmarshal(last, &del))
		assert.Equal(t, "sidescale-keysub-a.test", del.ID)
	})

	t.Run("borrow_needs_no_substitution", func(t *testing.T) {
		cfg, err := defaultControlConfig()
		require.NoError(t, err)
		cfg.KeyStrategy = KeyStrategyBorrow

		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, sidecar.Config{})
		subs, err := setupKeySubstitution(t.Context(), h)
		require.NoError(t, err)
		assert.Nil(t, subs)
	})

	t.Run("close_deletes_by_stable_label", func(t *testing.T) {
		cfg, err := defaultControlConfig()
		require.NoError(t, err)

		realKey := key.NewMachine().Public()
		core := newFakeCore()
		hostCfg := sidecar.Config{NativeHTTPSend: fakeKeyResponse(realKey)}
		h := testHandler(t, &cfg, newRecordingFlows(), core, stubRules{}, hostCfg)

		ks, err := setupKeySubstitution(t.Context(), h)
		require.NoError(t, err)
		require.NotNil(t, ks[defaultControlHost])

		ks[defaultControlHost].close(t.Context())
		var del struct {
			ID string `json:"id"`
		}
		require.NoError(t, json.Unmarshal(core.params("proxy_respond_delete"), &del))
		assert.Equal(t, "sidescale-keysub-"+defaultControlHost, del.ID)
	})

	t.Run("close_without_responder_noop", func(t *testing.T) {
		cfg, err := defaultControlConfig()
		require.NoError(t, err)
		cfg.KeySubstitution = KeySubSidecarTLS // registered, but no responder

		realKey := key.NewMachine().Public()
		core := newFakeCore()
		hostCfg := sidecar.Config{NativeHTTPSend: fakeKeyResponse(realKey)}
		h := testHandler(t, &cfg, newRecordingFlows(), core, stubRules{}, hostCfg)
		ks, err := setupKeySubstitution(t.Context(), h)
		require.NoError(t, err)
		require.NotNil(t, ks[defaultControlHost])

		ks[defaultControlHost].close(t.Context())
		assert.NotContains(t, core.calls(), "proxy_respond_delete")
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
	subs, err := setupKeySubstitution(t.Context(), h)
	require.NoError(t, err)
	ks, ok := subs[defaultControlHost]
	require.True(t, ok)

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
