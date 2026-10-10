package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

// stableInstanceID returns a UUID stable across restarts for this adapter name,
// persisted under ~/.sectool so reconnect reattaches ownership.
func stableInstanceID(name string) (string, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("sidescale: resolve instance id home dir: %w", err)
	}
	return loadOrCreateInstanceID(filepath.Join(dir, ".sectool", "sidescale-"+name+".instance"))
}

// loadOrCreateInstanceID returns the value persisted at path verbatim, or mints and
// persists a fresh UUID there when missing. Verbatim matters: purposeful invalid instance
// values are a supported testing mode, so the content is never trimmed or regenerated.
func loadOrCreateInstanceID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return string(data), nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("sidescale: read instance id file %s: %w", path, err)
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("sidescale: mint instance id: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("sidescale: create dir for instance id file %s: %w", path, err)
	}
	if err := writeFileAtomic(path, []byte(id.String())); err != nil {
		return "", fmt.Errorf("sidescale: persist instance id file %s: %w", path, err)
	}
	return id.String(), nil
}

// writeFileAtomic replaces path with data (mode 0600) via a same-directory temp file and
// rename, so an interrupted write never leaves truncated content.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once renamed into place
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
