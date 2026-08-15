//go:build unix

package noise

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"

	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

// fakeTunnel registers an activeTunnel backed by a pooled fakeUpstream whose bridge
// answers via srv, so replay/injection can drive a real bridge.
func fakeTunnel(t *testing.T, h *Handler, flowID string, srv http.Handler) *activeTunnel {
	t.Helper()

	u := fakeUpstream(t, h, key.NewMachine().Public(), "ctrl.example", uint16(tsproto.CurrentCapabilityVersion), srv)
	at := &activeTunnel{
		up:           u,
		bridge:       u.uc.bridge,
		controlHost:  "ctrl.example",
		serverPub:    u.uc.serverPub,
		serverLegacy: u.uc.serverLegacy,
		machineKey:   key.NewMachine(),
		version:      uint16(tsproto.CurrentCapabilityVersion),
		flowID:       flowID,
	}
	h.registerTunnel(flowID, at)
	return at
}

func newTunnel(t *testing.T) *activeTunnel {
	t.Helper()

	return &activeTunnel{controlHost: "ctrl.example", serverPub: key.NewMachine().Public(), serverLegacy: key.NewMachine().Public(), machineKey: key.NewMachine()}
}

func TestRebind(t *testing.T) {
	t.Parallel()

	baseCfg, err := defaultControlConfig()
	require.NoError(t, err)

	// body carrying enterprise device-cert signature fields, stripped when no cert is configured
	sigBody := []byte(`{"Signature":"AQID","SignatureType":"signature-v2","DeviceCert":"BAUG"}`)

	t.Run("register_no_cert_strips_on_cross_tunnel", func(t *testing.T) {
		h := &Handler{cfg: baseCfg}
		req := &wire.FlowMessage{Path: registerEndpoint, Body: sigBody}
		ann, resign, err := h.rebind(registerEndpoint, req, newTunnel(t), true, nil)
		require.NoError(t, err)
		assert.True(t, resign)
		require.NotNil(t, ann)
		assert.Equal(t, "register_signature", ann["binding"])
	})

	t.Run("register_stock_cross_tunnel_noop", func(t *testing.T) {
		h := &Handler{cfg: baseCfg}
		req := &wire.FlowMessage{Path: registerEndpoint, Body: []byte(`{}`)}
		ann, resign, err := h.rebind(registerEndpoint, req, newTunnel(t), true, nil)
		require.NoError(t, err)
		assert.True(t, resign)
		assert.Nil(t, ann) // no signature fields present -> nothing stripped
	})

	t.Run("register_hostinfo_same_tunnel_no_rebind", func(t *testing.T) {
		h := &Handler{cfg: baseCfg}
		body := []byte(`{"Hostinfo":{"OS":"linux"}}`)
		req := &wire.FlowMessage{Path: registerEndpoint, Body: body}
		ann, resign, err := h.rebind(registerEndpoint, req, newTunnel(t), false, []wire.Mutation{{Op: "set_json", Name: "Hostinfo.OS", Value: "darwin"}})
		require.NoError(t, err)
		assert.False(t, resign)
		assert.Nil(t, ann)
		assert.Equal(t, body, req.Body) // untouched
	})

	t.Run("register_timestamp_triggers_rebind", func(t *testing.T) {
		h := &Handler{cfg: baseCfg}
		req := &wire.FlowMessage{Path: registerEndpoint, Body: sigBody}
		ann, resign, err := h.rebind(registerEndpoint, req, newTunnel(t), false, []wire.Mutation{{Op: "set_json", Name: "Timestamp", Value: "2020-01-01T00:00:00Z"}})
		require.NoError(t, err)
		assert.True(t, resign)
		require.NotNil(t, ann) // no cert configured -> strip
	})

	t.Run("register_nodekey_strips_tailnet_lock_sig", func(t *testing.T) {
		h := &Handler{cfg: baseCfg}
		req := &wire.FlowMessage{Path: registerEndpoint, Body: []byte(`{"NodeKeySignature":"sig"}`)}
		ann, resign, err := h.rebind(registerEndpoint, req, newTunnel(t), false, []wire.Mutation{{Op: "set_json", Name: "NodeKey", Value: "nodekey:x"}})
		require.NoError(t, err)
		assert.False(t, resign) // node-key-sig strip only, no device resign
		require.NotNil(t, ann)
		assert.Equal(t, nlBinding, ann["binding"])
		assert.NotContains(t, string(req.Body), "NodeKeySignature")
	})

	t.Run("register_nodekey_cross_tunnel_lists_both_strips", func(t *testing.T) {
		h := &Handler{cfg: baseCfg}
		req := &wire.FlowMessage{Path: registerEndpoint, Body: []byte(`{"NodeKeySignature":"sig","Signature":"AQID","SignatureType":"signature-v2","DeviceCert":"BAUG"}`)}
		ann, resign, err := h.rebind(registerEndpoint, req, newTunnel(t), true, []wire.Mutation{{Op: "set_json", Name: "NodeKey", Value: "nodekey:x"}})
		require.NoError(t, err)
		assert.True(t, resign)
		require.NotNil(t, ann)
		// both bindings stripped in one replay: listed distinctly, neither mislabeled
		strips, ok := ann[annStrippedBindings].([]map[string]any)
		require.True(t, ok)
		require.Len(t, strips, 2)
		got := make([]string, 0, len(strips))
		for _, s := range strips {
			got = append(got, s["binding"].(string))
		}
		assert.ElementsMatch(t, []string{nlBinding, "register_signature"}, got)
		// tailnet-lock signature value removed
		// resign's struct round-trip re-emits the key as null, so assert the value is gone rather than the key
		assert.NotContains(t, string(req.Body), `"sig"`)
	})

	t.Run("register_cert_resigns", func(t *testing.T) {
		certPath, keyPath := writeSignerFiles(t)
		cfg := baseCfg
		cfg.DeviceCertPath, cfg.DeviceKeyPath = certPath, keyPath
		signer, _, err := LoadBindingKeys(&cfg)
		require.NoError(t, err)
		h := &Handler{cfg: cfg, regSigner: signer}
		req := &wire.FlowMessage{Path: registerEndpoint, Body: []byte(`{}`)}
		ann, resign, err := h.rebind(registerEndpoint, req, newTunnel(t), true, nil)
		require.NoError(t, err)
		assert.True(t, resign)
		assert.Nil(t, ann) // signed, not stripped

		var rr tailcfg.RegisterRequest
		require.NoError(t, json.Unmarshal(req.Body, &rr))
		assert.Equal(t, tailcfg.SignatureV2, rr.SignatureType)
		assert.NotEmpty(t, rr.Signature)
	})

	t.Run("map_nodekey_no_hwkey_strips", func(t *testing.T) {
		h := &Handler{cfg: baseCfg}
		req := &wire.FlowMessage{Path: mapEndpoint, Body: []byte(`{"HardwareAttestationKeySignature":"AQID"}`)}
		ann, resign, err := h.rebind(mapEndpoint, req, newTunnel(t), false, []wire.Mutation{{Op: "set_json", Name: "NodeKey", Value: "nodekey:x"}})
		require.NoError(t, err)
		assert.True(t, resign)
		require.NotNil(t, ann)
		assert.Equal(t, "hardware_attestation", ann["binding"])
	})

	t.Run("map_cross_tunnel_resets_session", func(t *testing.T) {
		h := &Handler{cfg: baseCfg}
		req := &wire.FlowMessage{Path: mapEndpoint, Body: []byte(`{"MapSessionHandle":"h","MapSessionSeq":5}`)}
		ann, resign, err := h.rebind(mapEndpoint, req, newTunnel(t), true, nil)
		require.NoError(t, err)
		assert.False(t, resign) // session reset only, no attestation resign
		assert.Nil(t, ann)
		var mr tailcfg.MapRequest
		require.NoError(t, json.Unmarshal(req.Body, &mr))
		assert.Empty(t, mr.MapSessionHandle)
		assert.Zero(t, mr.MapSessionSeq)
	})
}

func TestBodyVersion(t *testing.T) {
	t.Parallel()

	cur := uint16(tsproto.CurrentCapabilityVersion)
	tests := []struct {
		name string
		body string
		want uint16
	}{
		{"explicit_version", `{"Version":140}`, 140},
		{"version_after_nodekey", `{"NodeKey":"x","Version":90}`, 90},
		{"missing_defaults_current", `{}`, cur},
		{"zero_defaults_current", `{"Version":0}`, cur},
		{"non_json_defaults_current", `not json`, cur},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, bodyVersion([]byte(tt.body)))
		})
	}
}

func TestIsStreamSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		flow *wire.Flow
		want bool
	}{
		{"stream_protocol_tag", &wire.Flow{ProtocolTag: streamProtocolTag}, true},
		{"map_stream_true", &wire.Flow{Request: &wire.FlowMessage{Path: mapEndpoint, Body: []byte(`{"Stream":true}`)}}, true},
		{"map_stream_false", &wire.Flow{Request: &wire.FlowMessage{Path: mapEndpoint, Body: []byte(`{"Stream":false}`)}}, false},
		{"register_never_stream", &wire.Flow{Request: &wire.FlowMessage{Path: registerEndpoint}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isStreamSource(tt.flow))
		})
	}
}

func TestReplay(t *testing.T) {
	t.Parallel()

	cfg, err := defaultControlConfig() // default shared pool mode
	require.NoError(t, err)

	t.Run("rejects_collapsed", func(t *testing.T) {
		h := &Handler{cfg: cfg}
		src := &wire.Flow{ProtocolTag: streamProtocolTag, Request: &wire.FlowMessage{Path: mapEndpoint}}
		_, err := h.replay(t.Context(), wire.SidecarSendParams{Flow: src, StreamStrategy: streamStrategyCollapsed})
		require.ErrorContains(t, err, "collapsed")
	})

	t.Run("reuse_active_tunnel", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &cfg, flows, noopCore{}, stubRules{}, scsidecar.Config{})

		// map is repeatable, so it reuses the source flow's live tunnel; register never does
		at := fakeTunnel(t, h, "tunnelX", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, mapEndpoint, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"MachineAuthorized":true}`))
		}))

		src := &wire.Flow{
			ProtocolTag:  controlProtocolTag,
			ParentFlowID: "tunnelX",
			Request:      &wire.FlowMessage{Method: http.MethodPost, Path: mapEndpoint, Headers: []wire.Header{{Name: ":method", Value: "POST"}, {Name: ":path", Value: mapEndpoint}}, Body: []byte(`{}`)},
		}
		res, err := h.replay(t.Context(), wire.SidecarSendParams{FlowID: "srcFlow", Flow: src})
		require.NoError(t, err)
		require.Len(t, res.NewFlowIDs, 1)
		require.NotNil(t, res.Response)
		assert.Equal(t, http.StatusOK, res.Response.StatusCode)
		assert.Contains(t, string(res.Response.Body), "MachineAuthorized")

		produced, ok := flows.Get(res.NewFlowIDs[0])
		require.True(t, ok)
		// replay parents to the source flow so sectool files it into replay history
		assert.Equal(t, "srcFlow", produced.ParentFlowID)

		// the reuse ref acquired for the send is released back to the owner's baseline
		h.mu.Lock()
		refs := at.up.refs
		h.mu.Unlock()
		assert.Equal(t, 1, refs)
	})

	t.Run("register_opens_dedicated", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		// live client tunnel; any request over it must fail the test
		at := fakeTunnel(t, h, "tunnelX", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("register must not reuse the live shared tunnel")
		}))
		liveUp := at.up

		var calls int32
		h.dialFn = func(_ context.Context, host string, _ key.MachinePrivate, version uint16) (*upstreamConn, error) {
			atomic.AddInt32(&calls, 1)
			return fakeUpstreamConn(t, h, host, version, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, registerEndpoint, r.URL.Path)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"MachineAuthorized":true}`))
			})), nil
		}

		src := &wire.Flow{
			ProtocolTag:  controlProtocolTag,
			ParentFlowID: "tunnelX",
			Request:      &wire.FlowMessage{Method: http.MethodPost, Path: registerEndpoint, Headers: []wire.Header{{Name: ":method", Value: "POST"}, {Name: ":path", Value: registerEndpoint}}, Body: []byte(`{}`)},
		}
		res, err := h.replay(t.Context(), wire.SidecarSendParams{FlowID: "srcFlow", Flow: src})
		require.NoError(t, err)
		require.NotNil(t, res.Response)
		assert.Equal(t, http.StatusOK, res.Response.StatusCode)
		assert.Contains(t, string(res.Response.Body), "MachineAuthorized")

		// a dedicated upstream was dialed; the live client's conn is untouched
		assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
		assert.Same(t, liveUp, at.up)
		h.mu.Lock()
		assert.Equal(t, 1, liveUp.refs)
		h.mu.Unlock()
	})

	t.Run("map_reuses_live_tunnel", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		at := fakeTunnel(t, h, "tunnelX", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, mapEndpoint, r.URL.Path)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}))
		h.dialFn = func(context.Context, string, key.MachinePrivate, uint16) (*upstreamConn, error) {
			t.Error("map replay must reuse the live tunnel, not dial")
			return nil, errors.New("unexpected dial")
		}

		src := &wire.Flow{
			ProtocolTag:  controlProtocolTag,
			ParentFlowID: "tunnelX",
			Request:      &wire.FlowMessage{Method: http.MethodPost, Path: mapEndpoint, Headers: []wire.Header{{Name: ":method", Value: "POST"}, {Name: ":path", Value: mapEndpoint}}, Body: []byte(`{}`)},
		}
		res, err := h.replay(t.Context(), wire.SidecarSendParams{Flow: src})
		require.NoError(t, err)
		require.NotNil(t, res.Response)
		assert.Equal(t, http.StatusOK, res.Response.StatusCode)
		h.mu.Lock()
		assert.Equal(t, 1, at.up.refs) // reuse ref released back to baseline
		h.mu.Unlock()
	})

	t.Run("preserves_query", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})

		gotQuery := make(chan string, 1)
		fakeTunnel(t, h, "tunnelX", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotQuery <- r.URL.RawQuery
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		}))

		// the captured query rides in :path (not FlowMessage.Query); it must survive replay
		src := &wire.Flow{
			ProtocolTag:  controlProtocolTag,
			ParentFlowID: "tunnelX",
			Request: &wire.FlowMessage{
				Method:  http.MethodPost,
				Path:    mapEndpoint,
				Headers: []wire.Header{{Name: ":method", Value: "POST"}, {Name: ":path", Value: mapEndpoint + "?foo=bar"}},
				Body:    []byte(`{}`),
			},
		}
		_, err := h.replay(t.Context(), wire.SidecarSendParams{Flow: src})
		require.NoError(t, err)
		assert.Equal(t, "foo=bar", <-gotQuery)
	})
}

func TestSelectTunnel(t *testing.T) {
	t.Parallel()

	cfg, err := defaultControlConfig()
	require.NoError(t, err)
	ver := uint16(tsproto.CurrentCapabilityVersion)

	t.Run("register_forces_dedicated_fresh", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		existing := fakeTunnel(t, h, "tunnelX", okSrv())
		h.dialFn = func(_ context.Context, host string, _ key.MachinePrivate, version uint16) (*upstreamConn, error) {
			return fakeUpstreamConn(t, h, host, version, okSrv()), nil
		}
		at, cleanup, cross, err := h.selectTunnel(t.Context(), "tunnelX", registerEndpoint, ver)
		require.NoError(t, err)
		t.Cleanup(cleanup)
		assert.True(t, cross)
		assert.NotSame(t, existing, at)
		assert.NotSame(t, existing.up, at.up)
		assert.True(t, strings.HasPrefix(at.session, "dedicated-"))
	})

	t.Run("map_reuses_existing", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})
		existing := fakeTunnel(t, h, "tunnelX", okSrv())
		at, cleanup, cross, err := h.selectTunnel(t.Context(), "tunnelX", mapEndpoint, ver)
		require.NoError(t, err)
		t.Cleanup(cleanup)
		assert.False(t, cross)
		assert.Same(t, existing, at)
	})

	t.Run("fresh_uses_request_version", func(t *testing.T) {
		h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})

		var gotVersion uint16
		h.dialFn = func(_ context.Context, host string, _ key.MachinePrivate, version uint16) (*upstreamConn, error) {
			gotVersion = version
			return fakeUpstreamConn(t, h, host, version, okSrv()), nil
		}
		at, cleanup, cross, err := h.selectTunnel(t.Context(), "no-such-tunnel", mapEndpoint, 140)
		require.NoError(t, err)
		t.Cleanup(cleanup)
		assert.True(t, cross)
		require.NotNil(t, at)
		assert.Equal(t, uint16(140), gotVersion)
	})
}

// writeSignerFiles writes a self-signed RSA cert and key to temp files.
func writeSignerFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sidescale-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}), 0o600))
	return certPath, keyPath
}

func TestSendFailed(t *testing.T) {
	t.Parallel()

	cfg, err := defaultControlConfig()
	require.NoError(t, err)
	h := testHandler(t, &cfg, newRecordingFlows(), noopCore{}, stubRules{}, scsidecar.Config{})

	t.Run("wraps_with_tunnel_context", func(t *testing.T) {
		at := newTunnel(t)
		at.flowID = "t1"
		err := h.sendFailed("replay", registerEndpoint, "forward upstream", at, false, io.EOF)
		require.Error(t, err)
		msg := err.Error()
		assert.Contains(t, msg, "replay")
		assert.Contains(t, msg, registerEndpoint)
		assert.Contains(t, msg, "t1")
		assert.Contains(t, msg, "forward upstream")
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("tolerates_nil_tunnel", func(t *testing.T) {
		err := h.sendFailed("replay", registerEndpoint, "select tunnel", nil, false, io.EOF)
		require.Error(t, err)
		assert.ErrorIs(t, err, io.EOF)
	})
}
