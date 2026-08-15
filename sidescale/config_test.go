package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jentfoo/toolbox-sidescale/sidescale/derp"
	"github.com/jentfoo/toolbox-sidescale/sidescale/noise"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "sidescale.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	t.Run("empty_is_control_only", func(t *testing.T) {
		cfg, err := LoadConfig("")
		require.NoError(t, err)
		assert.Equal(t, defaultName, cfg.Name)
		require.NotNil(t, cfg.Control)
		assert.Equal(t, noise.KeyStrategySubstitute, cfg.Control.KeyStrategy)
		assert.Nil(t, cfg.Derp)
	})

	t.Run("nested_sections_parsed", func(t *testing.T) {
		path := writeConfig(t, `{
			"name": "sc",
			"control": {"control_hosts": ["cp.example.com"], "key_strategy": "substitute"},
			"derp": {"derp_hosts": ["derp1.example.com"], "relay_mode": "relay"}
		}`)
		cfg, err := LoadConfig(path)
		require.NoError(t, err)
		assert.Equal(t, "sc", cfg.Name)
		assert.Equal(t, []string{"cp.example.com"}, cfg.Control.ControlHosts)
		require.NotNil(t, cfg.Derp)
		assert.Equal(t, []string{"derp1.example.com"}, cfg.Derp.DerpHosts)
		assert.Equal(t, derp.RelayModeRelay, cfg.Derp.RelayMode)
	})

	t.Run("derp_defaults_applied", func(t *testing.T) {
		path := writeConfig(t, `{"derp": {"derp_hosts": ["derp1.example.com"]}}`)
		cfg, err := LoadConfig(path)
		require.NoError(t, err)
		assert.Equal(t, derp.RelayModeRelay, cfg.Derp.RelayMode)
		assert.Equal(t, derp.ServerKeySubstitute, cfg.Derp.ServerKey)
	})

	t.Run("control_validation_error", func(t *testing.T) {
		path := writeConfig(t, `{"control": {"key_strategy": "bogus"}}`)
		_, err := LoadConfig(path)
		assert.ErrorContains(t, err, "invalid key_strategy")
	})

	t.Run("derp_validation_error", func(t *testing.T) {
		path := writeConfig(t, `{"derp": {"relay_mode": "relay"}}`) // no derp_hosts
		_, err := LoadConfig(path)
		assert.ErrorContains(t, err, "derp requires derp_hosts")
	})
}
