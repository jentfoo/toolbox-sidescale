//go:build unix

package noise

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-analyze/bulk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
	"github.com/jentfoo/toolbox-sidescale/sidescale/tsproto"
)

func controlFlows(flows []*types.Flow) []*types.Flow {
	return bulk.SliceFilter(func(f *types.Flow) bool {
		return f.ProtocolTag == controlProtocolTag
	}, flows)
}

func TestCaptureRequest(t *testing.T) {
	t.Parallel()

	cfg, err := defaultControlConfig()
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "https://controlplane.tailscale.com/machine/register", nil)
	body := []byte(`{"Hostinfo":{"OS":"linux"}}`)

	t.Run("no_rule_emits_single_flow", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &cfg, flows, noopCore{}, stubRules{}, scsidecar.Config{})

		fwdBody, _, err := h.captureRequest(t.Context(), "tunnel1", req, requestHeaders(req), body)
		require.NoError(t, err)
		assert.Equal(t, body, fwdBody)

		captured := controlFlows(flows.list())
		require.Len(t, captured, 1)
		assert.Equal(t, adapter.DirClientToServer, captured[0].Direction)
		assert.Equal(t, "tunnel1", captured[0].ParentFlowID)
		require.NotNil(t, captured[0].Request)
		assert.Equal(t, http.MethodPost, captured[0].Request.Method)
		assert.Equal(t, "/machine/register", captured[0].Request.Path)
		assert.Equal(t, body, captured[0].Request.Body)
	})

	t.Run("rule_emits_mutated_flow", func(t *testing.T) {
		flows := newRecordingFlows()
		rules := stubRules{rules: []wire.Rule{{RuleID: "r1", Type: "request_body", Find: "linux", Replace: "darwin"}}}
		h := testHandler(t, &cfg, flows, noopCore{}, rules, scsidecar.Config{})

		fwdBody, _, err := h.captureRequest(t.Context(), "tunnel1", req, requestHeaders(req), body)
		require.NoError(t, err)
		assert.Contains(t, string(fwdBody), "darwin")

		// only the mutated flow is emitted, mirroring the native proxy
		captured := controlFlows(flows.list())
		require.Len(t, captured, 1)
		assert.Contains(t, string(captured[0].Request.Body), "darwin")
	})

	t.Run("header_rule_preserves_pseudo_headers", func(t *testing.T) {
		flows := newRecordingFlows()
		rules := stubRules{rules: []wire.Rule{{RuleID: "h1", Type: "request_header", Find: "X-Old", Replace: "X-New"}}}
		h := testHandler(t, &cfg, flows, noopCore{}, rules, scsidecar.Config{})

		r := httptest.NewRequest(http.MethodPost, "https://controlplane.tailscale.com/machine/register", nil)
		r.Header.Set("X-Old", "v")
		_, fwdHeaders, err := h.captureRequest(t.Context(), "tunnel1", r, requestHeaders(r), body)
		require.NoError(t, err)

		// pseudo-headers must survive the header-rule render/parse round-trip
		assert.Equal(t, http.MethodPost, headerVal(fwdHeaders, ":method"))
		assert.Equal(t, "/machine/register", headerVal(fwdHeaders, ":path"))
		assert.Equal(t, "v", headerVal(fwdHeaders, "X-New"))

		// and the forwarded upstream request is well-formed (not GET /)
		up, err := buildUpstreamRequest(t.Context(), "controlplane.tailscale.com", fwdHeaders, body)
		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, up.Method)
		assert.Equal(t, "/machine/register", up.URL.Path)
	})
}

func headerVal(hdrs []wire.Header, name string) string {
	for _, h := range hdrs {
		if h.Name == name {
			return h.Value
		}
	}
	return ""
}

func TestCaptureResponse(t *testing.T) {
	t.Parallel()

	cfg, err := defaultControlConfig()
	require.NoError(t, err)

	flows := newRecordingFlows()
	h := testHandler(t, &cfg, flows, noopCore{}, stubRules{}, scsidecar.Config{})

	respBody := []byte(`{"MachineAuthorized":true}`)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(respBody)),
	}
	out, err := h.captureResponse(t.Context(), "tunnel1", resp)
	require.NoError(t, err)

	got, err := io.ReadAll(out.Body)
	require.NoError(t, err)
	assert.Equal(t, respBody, got)

	captured := controlFlows(flows.list())
	require.Len(t, captured, 1)
	assert.Equal(t, adapter.DirServerToClient, captured[0].Direction)
	require.NotNil(t, captured[0].Response)
	assert.Equal(t, 200, captured[0].Response.StatusCode)
	assert.Equal(t, respBody, captured[0].Response.Body)
}

func TestCaptureInnerStreamParent(t *testing.T) {
	t.Parallel()

	cfg, err := defaultControlConfig()
	require.NoError(t, err)

	mapFrame := tsproto.EncodeMapResponseFrame([]byte(`{"Node":{"Name":"a"}}`), true)
	streamReq := func() *http.Request {
		return httptest.NewRequest(http.MethodPost, "https://ctrl.example/machine/map", bytes.NewReader([]byte(`{"Stream":true}`)))
	}
	// stream flows whose structural parent is the tunnel are the parent-level flows (the
	// captured anchor and, on a header-rule hit, the mutated twin); chunk children hang
	// off the captured anchor's id instead.
	streamParents := func(flows []*types.Flow, tunnelID string) []*types.Flow {
		return bulk.SliceFilter(func(f *types.Flow) bool {
			return f.ProtocolTag == streamProtocolTag && f.ParentFlowID == tunnelID
		}, flows)
	}

	t.Run("no_rule_single_parent", func(t *testing.T) {
		flows := newRecordingFlows()
		h := testHandler(t, &cfg, flows, noopCore{}, stubRules{}, scsidecar.Config{})
		srv := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(mapFrame)
		})
		at := fakeTunnel(t, h, "tunnel1", srv)

		resp, err := h.captureInner(t.Context(), at)(streamReq())
		require.NoError(t, err)
		_, err = io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		parents := streamParents(flows.list(), "tunnel1")
		require.Len(t, parents, 1)
		assert.Empty(t, parents[0].Annotations["phase"])
	})

	t.Run("header_rule_mutates_parent", func(t *testing.T) {
		flows := newRecordingFlows()
		rules := stubRules{rules: []wire.Rule{{RuleID: "h1", Type: wire.RuleTypeResponseHeader, Find: "X-Upstream: old", Replace: "X-Upstream: new"}}}
		h := testHandler(t, &cfg, flows, noopCore{}, rules, scsidecar.Config{})
		srv := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Upstream", "old")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(mapFrame)
		})
		at := fakeTunnel(t, h, "tunnel1", srv)

		resp, err := h.captureInner(t.Context(), at)(streamReq())
		require.NoError(t, err)
		_, err = io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		// forwarded response carries the mutated header
		assert.Equal(t, "new", resp.Header.Get("X-Upstream"))

		// only the mutated anchor parent is emitted, completed on stream close
		parents := streamParents(flows.list(), "tunnel1")
		require.Len(t, parents, 1)
		assert.Equal(t, "new", parents[0].Response.Headers.Get("X-Upstream"))
		assert.True(t, flows.wasCompleted(parents[0].FlowID))
	})
}

func TestRequestHeaders(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "https://ctrl.example/machine/map", nil)
	req.Header.Set("X-Test", "v")
	hdrs := requestHeaders(req)

	byName := map[string]string{}
	for _, h := range hdrs {
		byName[h.Name] = h.Value
	}
	assert.Equal(t, http.MethodPost, byName[":method"])
	assert.Equal(t, "/machine/map", byName[":path"])
	assert.Equal(t, "ctrl.example", byName[":authority"])
	assert.Equal(t, "https", byName[":scheme"])
	assert.Equal(t, "v", byName["X-Test"])
}

func TestBuildUpstreamRequest(t *testing.T) {
	t.Parallel()

	headers := []wire.Header{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/machine/register"},
		{Name: ":authority", Value: "ignored"},
		{Name: "Connection", Value: "keep-alive"},
		{Name: "X-Keep", Value: "yes"},
	}
	req, err := buildUpstreamRequest(t.Context(), "controlplane.tailscale.com", headers, []byte("body"))
	require.NoError(t, err)
	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "https://controlplane.tailscale.com/machine/register", req.URL.String())
	assert.Empty(t, req.Header.Get("Connection")) // hop-by-hop dropped
	assert.Empty(t, req.Header.Get(":authority")) // pseudo dropped
	assert.Equal(t, "yes", req.Header.Get("X-Keep"))
}
