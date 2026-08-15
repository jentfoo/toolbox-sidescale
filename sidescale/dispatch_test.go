package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp"
	"github.com/jentfoo/toolbox-sidescale/sidescale/noise"
)

func TestDispatcherRouteOpen(t *testing.T) {
	t.Parallel()

	nh := &noise.Handler{}
	dh := &derp.Handler{}

	newDisp := func(t *testing.T, derpCfg *derp.DerpConfig, keySub string) *dispatcher {
		t.Helper()

		cfg, err := LoadConfig("")
		require.NoError(t, err)
		cfg.Control.KeySubstitution = keySub
		cfg.Derp = derpCfg
		var handler *derp.Handler
		if derpCfg != nil {
			handler = dh
		}
		return newDispatcher(nil, nil, cfg, nh, handler)
	}

	controlHost := "controlplane.tailscale.com"
	relay := &derp.DerpConfig{DerpHosts: []string{"derp1.tailscale.com"}, RelayMode: derp.RelayModeRelay}
	terminate := &derp.DerpConfig{DerpHosts: []string{"derp.test"}, RelayMode: derp.RelayModeTerminate}
	terminatePorted := &derp.DerpConfig{DerpHosts: []string{"derp.test:3340"}, RelayMode: derp.RelayModeTerminate}

	tests := []struct {
		name    string
		derpCfg *derp.DerpConfig
		keySub  string
		params  wire.StreamOpenParams
		want    streamSurface
	}{
		{"ts2021_to_noise", nil, noise.KeySubResponder, wire.StreamOpenParams{Path: "/ts2021"}, nh},
		{"derp_path_nil_derp", nil, noise.KeySubResponder, wire.StreamOpenParams{Path: "/derp"}, nil},
		{"derp_path_relay", relay, noise.KeySubResponder, wire.StreamOpenParams{Path: "/derp"}, dh},
		{"ts2021_with_derp", relay, noise.KeySubResponder, wire.StreamOpenParams{Path: "/ts2021"}, nh},
		{"terminate_host_match", terminate, noise.KeySubResponder, wire.StreamOpenParams{Host: "derp.test"}, dh},
		{"terminate_ported_host_match", terminatePorted, noise.KeySubResponder, wire.StreamOpenParams{Host: "derp.test"}, dh},
		{"terminate_host_miss", terminate, noise.KeySubResponder, wire.StreamOpenParams{Host: "other.test"}, nil},
		{"sidecar_tls_control_host", nil, noise.KeySubSidecarTLS, wire.StreamOpenParams{Host: controlHost}, nh},
		{"empty_no_match", nil, noise.KeySubResponder, wire.StreamOpenParams{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := newDisp(t, tt.derpCfg, tt.keySub)
			assert.Equal(t, tt.want, d.routeOpen(tt.params))
		})
	}
}

func TestDispatcherOnSidecarSend(t *testing.T) {
	t.Parallel()

	// a FlowID-only send (sectool sink miss, no inlined Flow) can't be routed or replayed
	// by either surface, so the dispatcher rejects it with a clear error
	t.Run("flow_id_only_rejected", func(t *testing.T) {
		d := &dispatcher{}
		_, err := d.OnSidecarSend(wire.SidecarSendParams{FlowID: "f1"})
		require.ErrorContains(t, err, "not inlined")
	})
}

func TestDispatcherOnInvokeTool(t *testing.T) {
	t.Parallel()

	t.Run("derp_tool_routes_to_handler", func(t *testing.T) {
		d := &dispatcher{derp: &derp.Handler{}}
		// routed to the derp handler: an unset handler would return the unknown-tool error
		_, err := d.OnInvokeTool(wire.InvokeToolParams{Name: derp.InjectToolName})
		require.NoError(t, err)
	})

	t.Run("derp_tool_without_handler_declined", func(t *testing.T) {
		d := &dispatcher{}
		_, err := d.OnInvokeTool(wire.InvokeToolParams{Name: derp.InjectToolName})
		require.ErrorContains(t, err, "unknown tool")
	})

	t.Run("unknown_tool_declined", func(t *testing.T) {
		d := &dispatcher{}
		_, err := d.OnInvokeTool(wire.InvokeToolParams{Name: "mystery"})
		require.ErrorContains(t, err, "unknown tool")
	})
}

func TestDerpShapedSend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params wire.SidecarSendParams
		want   bool
	}{
		{"frame_payload", wire.SidecarSendParams{Payload: []byte(`{"frame":"RECV_PACKET"}`)}, true},
		{"frame_target", wire.SidecarSendParams{Target: []byte(`{"frame":"HEALTH"}`)}, true},
		{"endpoint_payload", wire.SidecarSendParams{Payload: []byte(`{"endpoint":"/machine/map"}`)}, false},
		{"empty", wire.SidecarSendParams{}, false},
		{"empty_frame", wire.SidecarSendParams{Payload: []byte(`{"frame":""}`)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, derpShapedSend(tt.params))
		})
	}
}
