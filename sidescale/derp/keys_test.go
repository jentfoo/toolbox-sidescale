package derp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
)

func writeNodeKey(t *testing.T, path string) key.NodePrivate {
	t.Helper()

	k := key.NewNode()
	text, err := k.MarshalText()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, text, 0o600))
	return k
}

func TestNewNodeKeyProvider(t *testing.T) {
	t.Parallel()

	t.Run("shared_stable", func(t *testing.T) {
		p, err := NewNodeKeyProvider(&DerpConfig{NodeIdentity: "shared"})
		require.NoError(t, err)
		a, err := p("clientA")
		require.NoError(t, err)
		b, err := p("clientB")
		require.NoError(t, err)
		assert.True(t, a.Equal(b)) // one key for all clients
	})

	t.Run("path", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "node.key")
		want := writeNodeKey(t, file)
		p, err := NewNodeKeyProvider(&DerpConfig{NodeIdentity: "path:" + file})
		require.NoError(t, err)
		got, err := p("clientA")
		require.NoError(t, err)
		assert.True(t, want.Equal(got))
	})

	t.Run("pool_sticky_per_client", func(t *testing.T) {
		dir := t.TempDir()
		writeNodeKey(t, filepath.Join(dir, "a.key"))
		writeNodeKey(t, filepath.Join(dir, "b.key"))
		p, err := NewNodeKeyProvider(&DerpConfig{NodeIdentity: "pool:" + dir})
		require.NoError(t, err)
		a, err := p("clientA")
		require.NoError(t, err)
		a2, err := p("clientA")
		require.NoError(t, err)
		b, err := p("clientB")
		require.NoError(t, err)
		c, err := p("clientC")
		require.NoError(t, err)
		assert.True(t, a.Equal(a2)) // same client -> stable key
		assert.False(t, a.Equal(b)) // distinct clients -> distinct pool keys
		assert.False(t, a.Equal(c)) // pool exhausted -> fresh minted key
		assert.False(t, b.Equal(c))
	})

	t.Run("per_client_sticky", func(t *testing.T) {
		p, err := NewNodeKeyProvider(&DerpConfig{NodeIdentity: "per_client"})
		require.NoError(t, err)
		a, err := p("clientA")
		require.NoError(t, err)
		a2, err := p("clientA")
		require.NoError(t, err)
		b, err := p("clientB")
		require.NoError(t, err)
		assert.True(t, a.Equal(a2))
		assert.False(t, a.Equal(b))
	})

	t.Run("invalid", func(t *testing.T) {
		_, err := NewNodeKeyProvider(&DerpConfig{NodeIdentity: "weird"})
		assert.Error(t, err)
	})
}

func TestProvisionServerNodeKey(t *testing.T) {
	t.Parallel()

	t.Run("substitute_ephemeral", func(t *testing.T) {
		k, err := ProvisionServerNodeKey(&DerpConfig{ServerKey: ServerKeySubstitute})
		require.NoError(t, err)
		assert.False(t, k.IsZero())
		// ephemeral: no persistence, so a second provision yields a distinct key
		k2, err := ProvisionServerNodeKey(&DerpConfig{ServerKey: ServerKeySubstitute})
		require.NoError(t, err)
		assert.False(t, k.Equal(k2))
	})

	t.Run("substitute_persistent", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "server.key")
		cfg := &DerpConfig{ServerKey: ServerKeySubstitute, ServerKeypairPath: file}
		k1, err := ProvisionServerNodeKey(cfg)
		require.NoError(t, err)
		k2, err := ProvisionServerNodeKey(cfg)
		require.NoError(t, err)
		assert.True(t, k1.Equal(k2))
	})

	t.Run("borrow", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "real.key")
		want := writeNodeKey(t, file)
		got, err := ProvisionServerNodeKey(&DerpConfig{ServerKey: ServerKeyBorrow, ServerKeypairPath: file})
		require.NoError(t, err)
		assert.True(t, want.Equal(got))
	})
}
