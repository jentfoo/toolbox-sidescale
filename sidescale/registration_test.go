//go:build unix

package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-appsec/toolbox/sectool/service/proxy/protocol"
	scsidecar "github.com/go-appsec/toolbox/sectool/service/proxy/protocol/sidecar"
	"github.com/go-appsec/toolbox/sectool/service/proxy/types"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp"
	"github.com/jentfoo/toolbox-sidescale/sidescale/noise"
)

const testInstanceID = "00000000-0000-4000-8000-000000000001"

// startHost brings up a standalone sidecar host on socket with no-op backends. The
// listener is returned so a test can drop the host mid-run (t.Cleanup closes it).
func startHost(t *testing.T, socket string) (*scsidecar.Listener, *scsidecar.Manager, string) {
	t.Helper()
	cfg := scsidecar.Config{Socket: socket}
	mgr := scsidecar.NewManager(cfg, &protocol.Registry{}, noopFlowSink{}, noopCore{}, noopRules{})
	lst, err := scsidecar.NewListener(t.Context(), cfg, mgr)
	require.NoError(t, err)
	go func() { _ = lst.Serve() }()
	t.Cleanup(func() { _ = lst.Close(context.Background()) })
	return lst, mgr, socket
}

func TestRegistration(t *testing.T) {
	t.Parallel()
	cfg, err := LoadConfig("")
	require.NoError(t, err)

	t.Run("accepts_declared_capabilities", func(t *testing.T) {
		_, mgr, socket := startHost(t, filepath.Join(t.TempDir(), "sidecar.sock"))
		conn, err := sidecar.Dial(t.Context(), socket, buildRegistration(cfg, testInstanceID))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		assert.Equal(t, 1, mgr.Count())
		rec, ok := mgr.Get(cfg.Name)
		require.True(t, ok)
		assert.Equal(t, testInstanceID, rec.InstanceID)
		require.Len(t, rec.Capabilities.UpgradeClaims, 1)
		assert.Equal(t, cfg.Control.ControlHosts[0], rec.Capabilities.UpgradeClaims[0].HostPattern)
		assert.Equal(t, "/ts2021", rec.Capabilities.UpgradeClaims[0].PathPattern)
	})

	t.Run("rejects_major_version_mismatch", func(t *testing.T) {
		_, _, socket := startHost(t, filepath.Join(t.TempDir(), "sidecar.sock"))
		reg := buildRegistration(cfg, testInstanceID)
		reg.ProtocolVersion = wire.ProtocolVersion{Major: wire.VersionMajor + 1}
		_, err := sidecar.Dial(t.Context(), socket, reg)
		assert.ErrorIs(t, err, sidecar.ErrVersionUnsupported)
	})

	t.Run("clean_close", func(t *testing.T) {
		_, mgr, socket := startHost(t, filepath.Join(t.TempDir(), "sidecar.sock"))
		conn, err := sidecar.Dial(t.Context(), socket, buildRegistration(cfg, testInstanceID))
		require.NoError(t, err)
		require.NoError(t, conn.Close())
		assert.Eventually(t, func() bool { return mgr.Count() == 0 }, 2*time.Second, 10*time.Millisecond)
	})
}

func TestBuildRegistration(t *testing.T) {
	t.Parallel()
	toolNames := func(tools []wire.MCPTool) []string {
		names := make([]string, len(tools))
		for i, tl := range tools {
			names[i] = tl.Name
		}
		return names
	}
	upgradePaths := func(claims []wire.UpgradeClaim) []string {
		paths := make([]string, len(claims))
		for i, c := range claims {
			paths[i] = c.PathPattern
		}
		return paths
	}

	t.Run("control_only", func(t *testing.T) {
		cfg, err := LoadConfig("")
		require.NoError(t, err)
		reg := buildRegistration(cfg, testInstanceID)
		assert.Equal(t, noise.Protocols(), reg.Protocols)
		assert.Equal(t, []string{"/ts2021"}, upgradePaths(reg.Capabilities.UpgradeClaims))
		assert.Empty(t, reg.Capabilities.EarlyClaims)
		assert.Equal(t, []string{noise.InjectToolName}, toolNames(reg.MCPTools))
	})

	t.Run("derp_relay", func(t *testing.T) {
		cfg, err := LoadConfig("")
		require.NoError(t, err)
		cfg.Derp = &derp.DerpConfig{DerpHosts: []string{"derp1.tailscale.com"}, RelayMode: derp.RelayModeRelay}
		cfg.Derp.ApplyDefaults()
		reg := buildRegistration(cfg, testInstanceID)

		assert.Equal(t, []string{"/ts2021", "/derp"}, upgradePaths(reg.Capabilities.UpgradeClaims))
		derpClaim := reg.Capabilities.UpgradeClaims[1]
		assert.Equal(t, "derp1.tailscale.com", derpClaim.HostPattern)
		assert.Equal(t, []string{"GET"}, derpClaim.MethodSet)
		assert.Equal(t, "http_101", derpClaim.UpgradeSignal)
		assert.Empty(t, reg.Capabilities.EarlyClaims)
		assert.Equal(t, []string{noise.InjectToolName, derp.InjectToolName}, toolNames(reg.MCPTools))
		assert.Contains(t, reg.Protocols, "tailscale.derp.frame")
	})

	t.Run("derp_terminate", func(t *testing.T) {
		cfg, err := LoadConfig("")
		require.NoError(t, err)
		cfg.Derp = &derp.DerpConfig{
			DerpHosts:    []string{"derp.test"},
			RelayMode:    derp.RelayModeTerminate,
			CertNameSANs: []string{"derp.test"},
		}
		cfg.Derp.ApplyDefaults()
		reg := buildRegistration(cfg, testInstanceID)

		assert.Equal(t, []string{"/ts2021"}, upgradePaths(reg.Capabilities.UpgradeClaims))
		require.Len(t, reg.Capabilities.EarlyClaims, 1)
		ec := reg.Capabilities.EarlyClaims[0]
		assert.Equal(t, "derp.test", ec.HostMatch)
		require.NotNil(t, ec.TLS)
		assert.True(t, ec.TLS.Terminate)
		assert.Equal(t, "derp.test", ec.TLS.SNIMatch)
		require.NotNil(t, ec.TLS.Cert)
		assert.Equal(t, []string{"derp.test"}, ec.TLS.Cert.DNSNames)
		assert.Equal(t, []string{noise.InjectToolName, derp.InjectToolName}, toolNames(reg.MCPTools))
	})

	t.Run("derp_relay_multi_host", func(t *testing.T) {
		cfg, err := LoadConfig("")
		require.NoError(t, err)
		cfg.Derp = &derp.DerpConfig{
			DerpHosts: []string{"derp1.example.com", "derp2.example.com"},
			RelayMode: derp.RelayModeRelay,
		}
		cfg.Derp.ApplyDefaults()
		reg := buildRegistration(cfg, testInstanceID)
		// one /derp upgrade claim per host, undeduplicated, alongside /ts2021
		assert.Equal(t, []string{"/ts2021", "/derp", "/derp"}, upgradePaths(reg.Capabilities.UpgradeClaims))
		assert.Equal(t, "derp1.example.com", reg.Capabilities.UpgradeClaims[1].HostPattern)
		assert.Equal(t, "derp2.example.com", reg.Capabilities.UpgradeClaims[2].HostPattern)
	})

	t.Run("derp_terminate_multi_host_ports", func(t *testing.T) {
		cfg, err := LoadConfig("")
		require.NoError(t, err)
		cfg.Derp = &derp.DerpConfig{
			DerpHosts: []string{"derp1.example.com", "derp2.example.com:3340"},
			RelayMode: derp.RelayModeTerminate,
		}
		cfg.Derp.ApplyDefaults()
		reg := buildRegistration(cfg, testInstanceID)

		require.Len(t, reg.Capabilities.EarlyClaims, 2)
		assert.Equal(t, "derp1.example.com", reg.Capabilities.EarlyClaims[0].HostMatch)
		assert.Equal(t, wire.PortRange{Low: 443, High: 443}, reg.Capabilities.EarlyClaims[0].PortRange)
		assert.Equal(t, "derp2.example.com", reg.Capabilities.EarlyClaims[1].HostMatch)
		assert.Equal(t, wire.PortRange{Low: 3340, High: 3340}, reg.Capabilities.EarlyClaims[1].PortRange)
	})

	t.Run("control_multi_host", func(t *testing.T) {
		cfg, err := LoadConfig("")
		require.NoError(t, err)
		cfg.Control.ControlHosts = []string{"ctrl1.example.com", "ctrl2.example.com:8443"}
		reg := buildRegistration(cfg, testInstanceID)

		// one /ts2021 upgrade claim per configured host
		require.Len(t, reg.Capabilities.UpgradeClaims, 2)
		assert.Equal(t, "ctrl1.example.com", reg.Capabilities.UpgradeClaims[0].HostPattern)
		assert.Equal(t, "ctrl2.example.com", reg.Capabilities.UpgradeClaims[1].HostPattern)
		for _, c := range reg.Capabilities.UpgradeClaims {
			assert.Equal(t, "/ts2021", c.PathPattern)
		}
		assert.Empty(t, reg.Capabilities.EarlyClaims)
	})

	t.Run("control_sidecar_tls_multi_host", func(t *testing.T) {
		cfg, err := LoadConfig("")
		require.NoError(t, err)
		cfg.Control.ControlHosts = []string{"ctrl1.example.com:8443", "ctrl2.example.com"}
		cfg.Control.KeySubstitution = noise.KeySubSidecarTLS
		reg := buildRegistration(cfg, testInstanceID)

		assert.Len(t, reg.Capabilities.UpgradeClaims, 2)
		require.Len(t, reg.Capabilities.EarlyClaims, 2) // one control TLS claim per host
		assert.Equal(t, "ctrl1.example.com", reg.Capabilities.EarlyClaims[0].HostMatch)
		assert.Equal(t, wire.PortRange{Low: 8443, High: 8443}, reg.Capabilities.EarlyClaims[0].PortRange)
		assert.Equal(t, "ctrl2.example.com", reg.Capabilities.EarlyClaims[1].HostMatch)
		assert.Equal(t, wire.PortRange{Low: 443, High: 443}, reg.Capabilities.EarlyClaims[1].PortRange)
		for _, ec := range reg.Capabilities.EarlyClaims {
			require.NotNil(t, ec.TLS)
			assert.Equal(t, ec.HostMatch, ec.TLS.SNIMatch)
		}

		// the per-host literal claims must compile host-side, i.e. register cleanly
		_, _, socket := startHost(t, filepath.Join(t.TempDir(), "sidecar.sock"))
		conn, err := sidecar.Dial(t.Context(), socket, reg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
	})

	t.Run("control_duplicate_hosts_dedup", func(t *testing.T) {
		cfg, err := LoadConfig("")
		require.NoError(t, err)
		cfg.Control.ControlHosts = []string{"ctrl1.example.com", "CTRL1.example.com:443", "ctrl2.example.com"}
		cfg.Control.KeySubstitution = noise.KeySubSidecarTLS
		reg := buildRegistration(cfg, testInstanceID)

		// one claim set per distinct host, not per config spelling
		require.Len(t, reg.Capabilities.UpgradeClaims, 2)
		require.Len(t, reg.Capabilities.EarlyClaims, 2)
		assert.Equal(t, "ctrl1.example.com", reg.Capabilities.UpgradeClaims[0].HostPattern)
		assert.Equal(t, "ctrl2.example.com", reg.Capabilities.UpgradeClaims[1].HostPattern)
	})

	// toolbox ffa8492 compiles plain-dot claim patterns as literals, so config hosts
	// must pass through verbatim: no local escaping, no wildcard handling
	t.Run("host_patterns_verbatim", func(t *testing.T) {
		cfg, err := LoadConfig("")
		require.NoError(t, err)
		cfg.Control.ControlHosts = []string{"Ctrl.Example.COM:8443"}
		cfg.Control.KeySubstitution = noise.KeySubSidecarTLS
		cfg.Derp = &derp.DerpConfig{
			DerpHosts: []string{"DERP1.Example.COM:3340", "DERP2.Example.COM"},
			RelayMode: derp.RelayModeRelay,
		}
		cfg.Derp.ApplyDefaults()
		reg := buildRegistration(cfg, testInstanceID)

		// hosts lowercase via addr.Parse, ports stripped, metacharacters untouched
		require.Len(t, reg.Capabilities.UpgradeClaims, 3)
		assert.Equal(t, "ctrl.example.com", reg.Capabilities.UpgradeClaims[0].HostPattern)
		assert.Equal(t, "derp1.example.com", reg.Capabilities.UpgradeClaims[1].HostPattern)
		assert.Equal(t, "derp2.example.com", reg.Capabilities.UpgradeClaims[2].HostPattern)
		for _, c := range reg.Capabilities.UpgradeClaims {
			assert.NotContains(t, c.HostPattern, `\\`)
			assert.NotContains(t, c.PathPattern, `\\`)
		}

		require.Len(t, reg.Capabilities.EarlyClaims, 1) // sidecar_tls control claim
		assert.Equal(t, "ctrl.example.com", reg.Capabilities.EarlyClaims[0].HostMatch)
		require.NotNil(t, reg.Capabilities.EarlyClaims[0].TLS)
		assert.Equal(t, "ctrl.example.com", reg.Capabilities.EarlyClaims[0].TLS.SNIMatch)

		// the literal-shaped claims must compile host-side, i.e. register cleanly
		_, _, socket := startHost(t, filepath.Join(t.TempDir(), "sidecar.sock"))
		conn, err := sidecar.Dial(t.Context(), socket, reg)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
	})
}

// scsidecar.FlowSink stub, no flows pushed
type noopFlowSink struct{}

func (noopFlowSink) Store(*types.Flow) string { return "" }
func (noopFlowSink) Complete(string, *types.Message, time.Time, map[string]any) bool {
	return false
}
func (noopFlowSink) SetInvokedBy(string, string) bool { return false }
func (noopFlowSink) Get(string) (*types.Flow, bool)   { return nil, false }
func (noopFlowSink) ShouldCapture(*types.Flow) bool   { return true }

// scsidecar.CoreService stub
type noopCore struct{}

func (noopCore) CoreInvoke(context.Context, string, json.RawMessage) (string, bool, error) {
	return "", false, nil
}

// non-empty so mcp_tools registration passes the core-tools-available gate
func (noopCore) CoreToolNames() []string { return []string{"proxy_poll", "flow_get"} }

// scsidecar.RuleSource stub
type noopRules struct{}

func (noopRules) RuleSnapshot(string) []wire.Rule { return nil }
