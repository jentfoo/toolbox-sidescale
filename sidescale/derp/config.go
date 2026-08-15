package derp

import (
	"errors"
	"fmt"
	"slices"

	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
)

// Client-facing DERP server key strategies.
const (
	ServerKeySubstitute = "substitute"
	ServerKeyBorrow     = "borrow"
)

// Relay modes: bridge a real upstream, or run a synthetic relay with no upstream.
const (
	RelayModeRelay     = "relay"
	RelayModeTerminate = "terminate"
)

// Duplicate-key policies for terminate-mode dup connections (mirrors real DERP dupPolicy).
const (
	DupPolicyLastWriter      = "last_writer"      // most recent sender receives
	DupPolicyDisableFighters = "disable_fighters" // interleaved senders disable the whole key
)

// DerpConfig is the derp: section of the sidescale config; its presence enables the DERP surface.
type DerpConfig struct {
	// host patterns to claim; "host:port" or bare host (default 443)
	DerpHosts         []string          `json:"derp_hosts,omitempty"`
	UpstreamOverrides map[string]string `json:"upstream_overrides,omitempty"`
	ServerKey         string            `json:"server_key,omitempty"`
	ServerKeypairPath string            `json:"server_keypair_path,omitempty"`
	NodeIdentity      string            `json:"node_identity,omitempty"`
	RelayMode         string            `json:"relay_mode,omitempty"`
	DupPolicy         string            `json:"dup_policy,omitempty"`
	MeshKey           string            `json:"mesh_key,omitempty"`
	CertNameSANs      []string          `json:"cert_name_sans,omitempty"`
}

// ApplyDefaults fills unset fields with their defaults.
func (c *DerpConfig) ApplyDefaults() {
	if c.ServerKey == "" {
		c.ServerKey = ServerKeySubstitute
	}
	if c.RelayMode == "" {
		c.RelayMode = RelayModeRelay
	}
	if c.NodeIdentity == "" {
		c.NodeIdentity = adapter.IdentityPerClient
	}
	if c.DupPolicy == "" {
		c.DupPolicy = DupPolicyLastWriter
	}
}

// Validate reports configuration errors after defaults are applied.
func (c *DerpConfig) Validate() error {
	if len(c.DerpHosts) == 0 {
		return errors.New("sidescale: derp requires derp_hosts")
	}
	if !slices.Contains([]string{ServerKeySubstitute, ServerKeyBorrow}, c.ServerKey) {
		return fmt.Errorf("sidescale: invalid derp server_key %q", c.ServerKey)
	} else if c.ServerKey == ServerKeyBorrow && c.ServerKeypairPath == "" {
		return errors.New("sidescale: derp server_key=borrow requires server_keypair_path")
	} else if !slices.Contains([]string{RelayModeRelay, RelayModeTerminate}, c.RelayMode) {
		return fmt.Errorf("sidescale: invalid derp relay_mode %q", c.RelayMode)
	} else if !slices.Contains([]string{DupPolicyLastWriter, DupPolicyDisableFighters}, c.DupPolicy) {
		// only affects terminate mode; relay mode has no synthetic relay
		return fmt.Errorf("sidescale: invalid derp dup_policy %q", c.DupPolicy)
	}
	// node_identity is the upstream client key, ignored under terminate (no upstream)
	if c.RelayMode != RelayModeTerminate && !adapter.ValidIdentity(c.NodeIdentity) {
		return fmt.Errorf("sidescale: invalid derp node_identity %q", c.NodeIdentity)
	}
	return nil
}
