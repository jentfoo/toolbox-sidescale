//go:build unix

package noise

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"

	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

func TestParseInjection(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		ir, err := parseInjection(json.RawMessage(`{"tunnel_id":"t1","endpoint":"/machine/map","method":"PATCH","body":{"Stream":true},"stream":true}`))
		require.NoError(t, err)
		assert.Equal(t, "t1", ir.TunnelID)
		assert.Equal(t, "/machine/map", ir.Endpoint)
		assert.Equal(t, "PATCH", ir.Method)
		assert.True(t, ir.Stream)
		assert.JSONEq(t, `{"Stream":true}`, string(ir.Body))
	})
	t.Run("empty", func(t *testing.T) {
		_, err := parseInjection(nil)
		require.ErrorContains(t, err, "empty injection payload")
	})
}

func TestEnsureStreamFlag(t *testing.T) {
	t.Parallel()

	out, err := ensureStreamFlag(json.RawMessage(`{"Hostinfo":{"OS":"linux"}}`))
	require.NoError(t, err)
	assert.JSONEq(t, `{"Hostinfo":{"OS":"linux"},"Stream":true}`, string(out))

	_, err = ensureStreamFlag(json.RawMessage(`"not-an-object"`))
	require.ErrorContains(t, err, "requires a JSON object body")
}

func TestInjectionMachineKey(t *testing.T) {
	t.Parallel()

	h := &Handler{}

	t.Run("empty_mints_fresh", func(t *testing.T) {
		a, err := h.injectionMachineKey("")
		require.NoError(t, err)
		b, err := h.injectionMachineKey("")
		require.NoError(t, err)
		assert.False(t, a.IsZero())
		assert.NotEqual(t, a.Public(), b.Public()) // distinct identity per originate
	})

	t.Run("as_machine_override", func(t *testing.T) {
		custom := key.NewMachine()
		text, err := custom.MarshalText()
		require.NoError(t, err)
		got, err := h.injectionMachineKey(string(text))
		require.NoError(t, err)
		assert.Equal(t, custom.Public(), got.Public())
	})

	t.Run("as_machine_invalid", func(t *testing.T) {
		_, err := h.injectionMachineKey("not-a-key")
		require.ErrorContains(t, err, "parse as_machine")
	})
}

func TestOnInvokeTool(t *testing.T) {
	t.Parallel()

	t.Run("unknown_tool", func(t *testing.T) {
		cfg, err := defaultControlConfig()
		require.NoError(t, err)
		h := &Handler{cfg: cfg}
		_, err = h.OnInvokeTool(wire.InvokeToolParams{Name: "nope"})
		require.ErrorContains(t, err, "unknown tool")
	})

	t.Run("reuse_tunnel_rides_live", func(t *testing.T) {
		cfg, err := defaultControlConfig()
		require.NoError(t, err)
		flows := newRecordingFlows()
		h := testHandler(t, &cfg, flows, noopCore{}, stubRules{}, scsidecar.Config{})

		fakeTunnel(t, h, "tunnelX", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, registerEndpoint, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"MachineAuthorized":true}`))
		}))

		args := json.RawMessage(`{"tunnel_id":"tunnelX","reuse_tunnel":true,"endpoint":"/machine/register","body":{"Hostinfo":{"OS":"linux"}}}`)
		res, err := h.OnInvokeTool(wire.InvokeToolParams{Name: InjectToolName, Arguments: args})
		require.NoError(t, err)
		require.False(t, res.IsError)

		var result struct {
			Summary    string   `json:"summary"`
			NewFlowIDs []string `json:"new_flow_ids"`
		}
		require.NoError(t, json.Unmarshal(res.Result, &result))
		assert.Contains(t, result.Summary, "live tunnel tunnelX")
		require.Len(t, result.NewFlowIDs, 1)

		produced, ok := flows.Get(result.NewFlowIDs[0])
		require.True(t, ok)
		// an originated flow has no source, so no parent
		assert.Empty(t, produced.ParentFlowID)
		assert.Equal(t, http.StatusOK, produced.Response.StatusCode)
		assert.Equal(t, true, produced.Annotations["injected"])
		assert.Equal(t, true, produced.Annotations["disturbs_live_node"])
	})

	t.Run("fresh_default_no_disturbance", func(t *testing.T) {
		cfg, err := defaultControlConfig()
		require.NoError(t, err)
		flows := newRecordingFlows()
		h := testHandler(t, &cfg, flows, noopCore{}, stubRules{}, scsidecar.Config{})

		// register a live tunnel that must NOT be touched without reuse_tunnel
		fakeTunnel(t, h, "tunnelX", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("live tunnel handler must not be invoked")
		}))
		h.dialFn = func(_ context.Context, host string, _ key.MachinePrivate, version uint16) (*upstreamConn, error) {
			return fakeUpstreamConn(t, h, host, version, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"MachineAuthorized":true}`))
			})), nil
		}

		args := json.RawMessage(`{"tunnel_id":"tunnelX","endpoint":"/machine/register","body":{"Hostinfo":{"OS":"linux"}}}`)
		res, err := h.OnInvokeTool(wire.InvokeToolParams{Name: InjectToolName, Arguments: args})
		require.NoError(t, err)
		require.False(t, res.IsError)

		var result struct {
			Summary    string   `json:"summary"`
			NewFlowIDs []string `json:"new_flow_ids"`
		}
		require.NoError(t, json.Unmarshal(res.Result, &result))
		assert.Contains(t, result.Summary, "a fresh tunnel") // tunnel_id ignored without reuse_tunnel
		require.Len(t, result.NewFlowIDs, 1)

		produced, ok := flows.Get(result.NewFlowIDs[0])
		require.True(t, ok)
		assert.Equal(t, true, produced.Annotations["injected"])
		assert.Nil(t, produced.Annotations["disturbs_live_node"]) // fresh tunnel, live client untouched
	})

	t.Run("streaming_map_non_blocking", func(t *testing.T) {
		cfg, err := defaultControlConfig()
		require.NoError(t, err)
		flows := newRecordingFlows()
		h := testHandler(t, &cfg, flows, noopCore{}, stubRules{}, scsidecar.Config{})

		fakeTunnel(t, h, "tunnelX", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			_, _ = w.Write(tsproto.EncodeMapResponseFrame([]byte(`{"Node":{"OS":"linux"}}`), true))
		}))

		// stream:true forces Stream in the body; the call returns the parent id without
		// blocking on the stream lifetime, and the chunk child is captured asynchronously
		args := json.RawMessage(`{"tunnel_id":"tunnelX","reuse_tunnel":true,"endpoint":"/machine/map","stream":true,"body":{}}`)
		res, err := h.OnInvokeTool(wire.InvokeToolParams{Name: InjectToolName, Arguments: args})
		require.NoError(t, err)
		require.False(t, res.IsError)

		var result struct {
			NewFlowIDs []string `json:"new_flow_ids"`
		}
		require.NoError(t, json.Unmarshal(res.Result, &result))
		require.Len(t, result.NewFlowIDs, 1)
		parentID := result.NewFlowIDs[0]

		require.Eventually(t, func() bool {
			return len(streamChildren(flows.list(), parentID)) == 1
		}, 2*time.Second, 10*time.Millisecond)
	})

	// as_version overrides the cleartext handshake capability version for a fresh tunnel
	// independently of the body Version, so a tester can drive the server's version floor
	t.Run("as_version_overrides_handshake", func(t *testing.T) {
		cfg, err := defaultControlConfig()
		require.NoError(t, err)
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})

		var gotVersion uint16
		h.dialFn = func(_ context.Context, host string, _ key.MachinePrivate, version uint16) (*upstreamConn, error) {
			gotVersion = version
			return fakeUpstreamConn(t, h, host, version, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("unsupported client version"))
			})), nil
		}

		// body carries Version:140; as_version:90 must win for the initiation handshake
		args := json.RawMessage(`{"endpoint":"/machine/register","as_version":90,"body":{"Version":140}}`)
		res, err := h.OnInvokeTool(wire.InvokeToolParams{Name: InjectToolName, Arguments: args})
		require.NoError(t, err)
		require.False(t, res.IsError)
		assert.Equal(t, uint16(90), gotVersion)
	})
}
