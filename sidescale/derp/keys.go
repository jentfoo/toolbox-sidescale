package derp

import (
	"fmt"

	"tailscale.com/types/key"

	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
)

// NewNodeKeyProvider returns the per-client upstream node-key provider selected by
// cfg.NodeIdentity ("shared", "path:<file>", "pool:<dir>", or "per_client").
func NewNodeKeyProvider(cfg *DerpConfig) (func(client string) (key.NodePrivate, error), error) {
	return adapter.NewProvider[key.NodePrivate](cfg.NodeIdentity, "derp node_identity", "derp node key", key.NewNode)
}

// ProvisionServerNodeKey returns the client-facing DERP server node private key per cfg.ServerKey.
func ProvisionServerNodeKey(cfg *DerpConfig) (key.NodePrivate, error) {
	switch cfg.ServerKey {
	case ServerKeySubstitute:
		if cfg.ServerKeypairPath == "" {
			return key.NewNode(), nil
		}
		return adapter.LoadOrCreate[key.NodePrivate](cfg.ServerKeypairPath, "derp node key", key.NewNode)
	case ServerKeyBorrow:
		return adapter.Load[key.NodePrivate](cfg.ServerKeypairPath, "derp node key")
	default:
		return key.NodePrivate{}, fmt.Errorf("sidescale: invalid derp server_key %q", cfg.ServerKey)
	}
}
