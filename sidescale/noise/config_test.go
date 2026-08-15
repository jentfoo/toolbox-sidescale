package noise

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
)

func TestControlConfigValidate(t *testing.T) {
	t.Parallel()

	defaulted := func() ControlConfig {
		var c ControlConfig
		c.ApplyDefaults()
		return c
	}

	t.Run("defaults_valid", func(t *testing.T) {
		c := defaulted()
		require.NoError(t, c.Validate())
		assert.Equal(t, KeyStrategySubstitute, c.KeyStrategy)
		assert.Equal(t, KeySubResponder, c.KeySubstitution)
		assert.Equal(t, UpstreamSchemeAuto, c.UpstreamScheme)
		assert.Equal(t, PoolModeShared, c.UpstreamPoolMode)
		assert.Equal(t, adapter.IdentityPerClient, c.MachineIdentity)
		assert.Equal(t, EarlyNoiseForward, c.EarlyNoise)
	})
	t.Run("invalid_scheme", func(t *testing.T) {
		c := defaulted()
		c.UpstreamScheme = "ftp"
		assert.ErrorContains(t, c.Validate(), "upstream_scheme")
	})
	t.Run("invalid_pool_mode", func(t *testing.T) {
		c := defaulted()
		c.UpstreamPoolMode = "nope"
		assert.ErrorContains(t, c.Validate(), "upstream_pool_mode")
	})
	t.Run("invalid_machine_identity", func(t *testing.T) {
		c := defaulted()
		c.MachineIdentity = "auto"
		assert.ErrorContains(t, c.Validate(), "machine_identity")
	})
	t.Run("invalid_early_noise", func(t *testing.T) {
		c := defaulted()
		c.EarlyNoise = "nope"
		assert.ErrorContains(t, c.Validate(), "early_noise")
	})
}
