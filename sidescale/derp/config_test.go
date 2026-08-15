package derp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDerpConfigValidate(t *testing.T) {
	t.Parallel()

	base := func() DerpConfig {
		c := DerpConfig{DerpHosts: []string{"derp1.tailscale.com"}}
		c.ApplyDefaults()
		return c
	}
	tests := []struct {
		name    string
		mutate  func(*DerpConfig)
		wantErr string // substring of the expected error, empty for valid configs
	}{
		{"defaults_ok", func(*DerpConfig) {}, ""},
		{"no_hosts", func(c *DerpConfig) { c.DerpHosts = nil }, "derp requires derp_hosts"},
		{"bad_server_key", func(c *DerpConfig) { c.ServerKey = "nope" }, "invalid derp server_key"},
		{"borrow_needs_path", func(c *DerpConfig) { c.ServerKey = ServerKeyBorrow }, "server_key=borrow requires server_keypair_path"},
		{"borrow_with_path", func(c *DerpConfig) { c.ServerKey = ServerKeyBorrow; c.ServerKeypairPath = "/k" }, ""},
		{"bad_relay_mode", func(c *DerpConfig) { c.RelayMode = "nope" }, "invalid derp relay_mode"},
		{"bad_node_identity", func(c *DerpConfig) { c.NodeIdentity = "weird" }, "invalid derp node_identity"},
		{"node_identity_ignored_terminate", func(c *DerpConfig) { c.RelayMode = RelayModeTerminate; c.NodeIdentity = "weird" }, ""},
		{"disable_fighters_ok", func(c *DerpConfig) { c.DupPolicy = DupPolicyDisableFighters }, ""},
		{"bad_dup_policy", func(c *DerpConfig) { c.DupPolicy = "nope" }, "invalid derp dup_policy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base()
			tt.mutate(&c)
			err := c.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}
