//go:build unix

package noise

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
)

func TestNewMachineKeyProvider(t *testing.T) {
	t.Parallel()

	t.Run("pool_sticky_per_client", func(t *testing.T) {
		dir := t.TempDir()
		for i := 0; i < 2; i++ {
			k := key.NewMachine()
			text, err := k.MarshalText()
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("k%d.key", i)), text, 0o600))
		}
		provider, err := NewMachineKeyProvider(&ControlConfig{MachineIdentity: "pool:" + dir})
		require.NoError(t, err)

		a, err := provider("clientA")
		require.NoError(t, err)
		a2, err := provider("clientA")
		require.NoError(t, err)
		assert.Equal(t, a.Public(), a2.Public()) // same client -> stable key

		b, err := provider("clientB")
		require.NoError(t, err)
		assert.NotEqual(t, a.Public(), b.Public()) // distinct clients -> distinct pool keys

		c, err := provider("clientC")
		require.NoError(t, err)
		assert.NotEqual(t, a.Public(), c.Public()) // pool exhausted -> fresh minted key
		assert.NotEqual(t, b.Public(), c.Public())
	})

	t.Run("pool_empty", func(t *testing.T) {
		_, err := NewMachineKeyProvider(&ControlConfig{MachineIdentity: "pool:" + t.TempDir()})
		assert.ErrorContains(t, err, "has no keys")
	})

	t.Run("per_client_sticky", func(t *testing.T) {
		provider, err := NewMachineKeyProvider(&ControlConfig{MachineIdentity: "per_client"})
		require.NoError(t, err)
		a, err := provider("clientA")
		require.NoError(t, err)
		a2, err := provider("clientA")
		require.NoError(t, err)
		b, err := provider("clientB")
		require.NoError(t, err)
		assert.Equal(t, a.Public(), a2.Public())   // stable per client
		assert.NotEqual(t, a.Public(), b.Public()) // distinct clients -> distinct keys
	})

	t.Run("shared_stable", func(t *testing.T) {
		provider, err := NewMachineKeyProvider(&ControlConfig{MachineIdentity: "shared"})
		require.NoError(t, err)
		a, err := provider("clientA")
		require.NoError(t, err)
		b, err := provider("clientB")
		require.NoError(t, err)
		assert.Equal(t, a.Public(), b.Public()) // one key for all clients
	})
}

func writeMachineKey(t *testing.T, path string) key.MachinePrivate {
	t.Helper()

	k := key.NewMachine()
	text, err := k.MarshalText()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, text, 0o600))
	return k
}

func TestProvisionResponderKey(t *testing.T) {
	t.Parallel()

	t.Run("substitute_ephemeral", func(t *testing.T) {
		k1, err := ProvisionResponderKey(&ControlConfig{KeyStrategy: KeyStrategySubstitute})
		require.NoError(t, err)
		k2, err := ProvisionResponderKey(&ControlConfig{KeyStrategy: KeyStrategySubstitute})
		require.NoError(t, err)
		assert.NotEqual(t, k1.Public(), k2.Public()) // no path -> fresh key each call
	})

	t.Run("substitute_persistent", func(t *testing.T) {
		cfg := &ControlConfig{KeyStrategy: KeyStrategySubstitute, NoiseKeypairPath: filepath.Join(t.TempDir(), "noise.key")}
		k1, err := ProvisionResponderKey(cfg)
		require.NoError(t, err)
		k2, err := ProvisionResponderKey(cfg)
		require.NoError(t, err)
		assert.Equal(t, k1.Public(), k2.Public()) // load-or-create persists across calls
	})

	t.Run("borrow_loads_existing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "real.key")
		want := writeMachineKey(t, path)
		got, err := ProvisionResponderKey(&ControlConfig{KeyStrategy: KeyStrategyBorrow, NoiseKeypairPath: path})
		require.NoError(t, err)
		assert.Equal(t, want.Public(), got.Public())
	})

	t.Run("invalid_strategy", func(t *testing.T) {
		_, err := ProvisionResponderKey(&ControlConfig{KeyStrategy: "bogus"})
		assert.ErrorContains(t, err, "invalid key_strategy")
	})
}
