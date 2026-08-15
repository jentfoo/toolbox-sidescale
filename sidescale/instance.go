package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

// stableInstanceID returns a UUID stable across restarts for this adapter name,
// persisted under ~/.sectool so reconnect reattaches ownership.
func stableInstanceID(name string) (string, error) {
	dir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, ".sectool", "sidescale-"+name+".instance")
	if data, err := os.ReadFile(path); err == nil {
		return string(data), nil
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id.String()), 0o600); err != nil {
		return "", fmt.Errorf("sidescale: persist instance id: %w", err)
	}
	return id.String(), nil
}
