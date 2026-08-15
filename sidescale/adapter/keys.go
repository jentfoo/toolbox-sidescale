package adapter

import (
	"encoding"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// PrivKey constrains a tailscale private key whose pointer round-trips via text.
type PrivKey[T any] interface {
	*T
	encoding.TextMarshaler
	encoding.TextUnmarshaler
}

// Load reads and parses a text-encoded private key from path. keyLabel names the key in error messages.
func Load[T any, PT PrivKey[T]](path, keyLabel string) (T, error) {
	var k T
	data, err := os.ReadFile(path)
	if err != nil {
		return k, fmt.Errorf("sidescale: read %s %s: %w", keyLabel, path, err)
	}
	if err := PT(&k).UnmarshalText(data); err != nil {
		return k, fmt.Errorf("sidescale: parse %s %s: %w", keyLabel, path, err)
	}
	return k, nil
}

// LoadOrCreate returns the key at path, minting and persisting a fresh one (0600) when the file is absent.
func LoadOrCreate[T any, PT PrivKey[T]](path, keyLabel string, newKey func() T) (T, error) {
	var zero T
	if _, err := os.Stat(path); err == nil {
		return Load[T, PT](path, keyLabel)
	} else if !os.IsNotExist(err) {
		return zero, fmt.Errorf("sidescale: stat %s %s: %w", keyLabel, path, err)
	}
	k := newKey()
	text, err := PT(&k).MarshalText()
	if err != nil {
		return zero, err
	}
	if err := os.WriteFile(path, text, 0o600); err != nil {
		return zero, fmt.Errorf("sidescale: write %s %s: %w", keyLabel, path, err)
	}
	return k, nil
}

// KeyPrefix shortens a key's string form (e.g. "mkey:abc123…") to its type tag plus a
// few leading hex, for low-noise log correlation without dumping the full key.
func KeyPrefix(s string) string {
	const n = 16
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Identity modes shared by every key provider (machine_identity, node_identity).
const (
	// IdentityShared presents one minted key for all clients.
	IdentityShared = "shared"
	// IdentityPerClient assigns each client its own stable minted key.
	IdentityPerClient = "per_client"

	identityPathPrefix = "path:"
	identityPoolPrefix = "pool:"
)

// ValidIdentity reports whether id is a recognized identity mode.
func ValidIdentity(id string) bool {
	switch {
	case id == IdentityShared, id == IdentityPerClient:
		return true
	case strings.HasPrefix(id, identityPathPrefix), strings.HasPrefix(id, identityPoolPrefix):
		return true
	default:
		return false
	}
}

// NewProvider returns a per-client key provider selected by identity: "shared" (or empty)
// mints one key reused by every client, "path:<file>" reuses a loaded key, "pool:<dir>"
// assigns the directory's keys stickily per client (minting fresh once exhausted), and
// "per_client" mints a fresh stable key per client. idLabel/keyLabel name the identity
// setting and key in error messages.
func NewProvider[T any, PT PrivKey[T]](identity, idLabel, keyLabel string, newKey func() T) (func(client string) (T, error), error) {
	switch {
	case identity == "" || identity == IdentityShared:
		k := newKey()
		return func(string) (T, error) { return k, nil }, nil
	case identity == IdentityPerClient:
		return newStickyProvider(nil, newKey), nil
	case strings.HasPrefix(identity, identityPoolPrefix):
		seed, err := loadPoolKeys[T, PT](strings.TrimPrefix(identity, identityPoolPrefix), idLabel, keyLabel)
		if err != nil {
			return nil, err
		}
		return newStickyProvider(seed, newKey), nil
	case strings.HasPrefix(identity, identityPathPrefix):
		k, err := Load[T, PT](strings.TrimPrefix(identity, identityPathPrefix), keyLabel)
		if err != nil {
			return nil, err
		}
		return func(string) (T, error) { return k, nil }, nil
	default:
		return nil, fmt.Errorf("sidescale: invalid %s %q", idLabel, identity)
	}
}

// newStickyProvider returns a provider that hands each client a stable key: the next
// unused seed key, or a freshly minted one once the seed is exhausted.
func newStickyProvider[T any](seed []T, newKey func() T) func(client string) (T, error) {
	byClient := make(map[string]T)
	var idx int
	var mu sync.Mutex
	return func(client string) (T, error) {
		mu.Lock()
		defer mu.Unlock()

		if k, ok := byClient[client]; ok {
			return k, nil
		}
		var k T
		if idx < len(seed) {
			k = seed[idx]
			idx++
		} else {
			k = newKey()
		}
		byClient[client] = k
		return k, nil
	}
}

// loadPoolKeys loads every non-directory key file in dir.
func loadPoolKeys[T any, PT PrivKey[T]](dir, idLabel, keyLabel string) ([]T, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("sidescale: read %s pool %s: %w", idLabel, dir, err)
	}
	var keys []T
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		k, err := Load[T, PT](filepath.Join(dir, e.Name()), keyLabel)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("sidescale: %s pool %s has no keys", idLabel, dir)
	}
	return keys, nil
}
