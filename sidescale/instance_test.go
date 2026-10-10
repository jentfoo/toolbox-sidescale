//go:build unix

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStableInstanceID(t *testing.T) { // not parallel: Setenv
	t.Setenv("HOME", t.TempDir())

	id, err := stableInstanceID("alpha")
	require.NoError(t, err)
	_, err = uuid.Parse(id)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(os.Getenv("HOME"), ".sectool", "sidescale-alpha.instance"))
	require.NoError(t, err)
	assert.Equal(t, id, string(data))

	reused, err := stableInstanceID("alpha")
	require.NoError(t, err)
	assert.Equal(t, id, reused) // reconnect reattaches ownership
}

func TestLoadOrCreateInstanceID(t *testing.T) {
	t.Parallel()

	t.Run("mints_when_missing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".sectool", "sidescale-alpha.instance")

		id, err := loadOrCreateInstanceID(path)
		require.NoError(t, err)
		_, err = uuid.Parse(id) // sectool's register handler requires a parseable UUID
		require.NoError(t, err)

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, fs.FileMode(0o600), info.Mode().Perm())
	})

	t.Run("returns_existing_verbatim", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sidescale-alpha.instance")
		require.NoError(t, os.WriteFile(path, []byte("not a uuid"), 0o600))

		id, err := loadOrCreateInstanceID(path)
		require.NoError(t, err)
		assert.Equal(t, "not a uuid", id)

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "not a uuid", string(data)) // invalid values are not regenerated
	})

	t.Run("stable_across_calls", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sidescale-alpha.instance")

		id1, err := loadOrCreateInstanceID(path)
		require.NoError(t, err)
		id2, err := loadOrCreateInstanceID(path)
		require.NoError(t, err)
		assert.Equal(t, id1, id2)
	})

	t.Run("read_error_names_file", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), ".sectool")
		require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600)) // dir slot held by a file

		path := filepath.Join(blocker, "sidescale-alpha.instance")
		_, err := loadOrCreateInstanceID(path)
		require.Error(t, err)
		assert.ErrorContains(t, err, path) // the operator can find and fix the file
	})
}

func TestWriteFileAtomic(t *testing.T) {
	t.Parallel()

	t.Run("replaces_existing_content", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sidescale-alpha.instance")
		require.NoError(t, os.WriteFile(path, []byte("00000000-0000-4000-8000-000000000009"), 0o600))

		require.NoError(t, writeFileAtomic(path, []byte("short")))

		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, "short", string(data)) // no truncation or stale tail from the old file
	})

	t.Run("leaves_no_temp_files", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "sidescale-alpha.instance")

		require.NoError(t, writeFileAtomic(path, []byte("id")))

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "sidescale-alpha.instance", entries[0].Name())
	})

	t.Run("missing_dir_fails", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "sidescale-alpha.instance")

		err := writeFileAtomic(path, []byte("id"))
		require.Error(t, err)
	})
}
