//go:build unix

package derp

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/derp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/types/key"
)

// TestFreshUpstreamEnvelopeNotCaptured drives openFreshUpstream (relay, real derpserver)
// with a capture filter that excludes everything: the envelope must come back uncaptured
// (empty id), cleanup must not complete a junk flow, and nothing may be stored under "".
func TestFreshUpstreamEnvelopeNotCaptured(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	t.Parallel()

	serverPriv := key.NewNode()
	srv := derpserver.New(serverPriv, func(string, ...any) {})
	t.Cleanup(func() { _ = srv.Close() })
	ts := httptest.NewServer(derpserver.Handler(srv))
	t.Cleanup(ts.Close)

	flows := captureNone{newRecordingFlows()}
	cfg := &DerpConfig{
		DerpHosts:         []string{"derp.test"},
		UpstreamOverrides: map[string]string{"derp.test": ts.URL},
	}
	h := testHandler(t, cfg, flows, stubRules{})

	tgt, err := h.openFreshUpstream(t.Context(), "derp.test")
	require.NoError(t, err)
	require.NotNil(t, tgt.cleanup)
	assert.Empty(t, tgt.flowID) // filter excluded the envelope: no id exists

	tgt.cleanup()
	// host-side dial-audit flows may store, but the envelope itself must be excluded:
	// nothing tunnel-tagged, and no junk completion under the empty id
	for _, f := range flows.list() {
		assert.NotEqual(t, tunnelProtocolTag, f.ProtocolTag)
	}
	assert.Empty(t, flows.completedSnapshot())
}

// TestUpstreamHandshakeAgainstRealServer drives the sidecar's relay-mode upstream half
// (openUpstream: dial, GET /derp upgrade, read real FrameServerKey, seal + send
// FrameClientInfo, read + decrypt FrameServerInfo) against a real derpserver mounted on
// a plain-HTTP httptest server. It confirms the sidecar's DERP client handshake
// interoperates with upstream Tailscale code end to end.
func TestUpstreamHandshakeAgainstRealServer(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}
	t.Parallel()

	serverPriv := key.NewNode()
	srv := derpserver.New(serverPriv, func(string, ...any) {})
	t.Cleanup(func() { _ = srv.Close() })
	ts := httptest.NewServer(derpserver.Handler(srv))
	t.Cleanup(ts.Close)

	flows := newRecordingFlows()
	cfg := &DerpConfig{
		DerpHosts:         []string{"derp.test"},
		UpstreamOverrides: map[string]string{"derp.test": ts.URL}, // http://127.0.0.1:port -> plain TCP
	}
	h := testHandler(t, cfg, flows, stubRules{})

	nodeKey := key.NewNode()
	clientInfo := &derp.ClientInfo{Version: 2, CanAckPings: true}

	up, err := h.openUpstream(t.Context(), "derp.test", nodeKey, clientInfo)
	require.NoError(t, err)
	t.Cleanup(func() { up.close() })

	// the greeting carried the real server key, and the server opened our sealed
	// FrameClientInfo (else it would not have returned a ServerInfo)
	assert.Equal(t, serverPriv.Public(), up.serverPub)
	require.NotNil(t, up.serverInfo)
	assert.Equal(t, 2, up.serverInfo.Version)
	assert.NotEmpty(t, up.serverInfoBox)
}
