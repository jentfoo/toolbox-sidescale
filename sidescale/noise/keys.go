package noise

import (
	"fmt"

	"tailscale.com/types/key"

	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
)

// ProvisionResponderKey returns the client-facing Noise responder private key per the configured strategy.
func ProvisionResponderKey(cfg *ControlConfig) (key.MachinePrivate, error) {
	switch cfg.KeyStrategy {
	case KeyStrategySubstitute:
		if cfg.NoiseKeypairPath == "" {
			return key.NewMachine(), nil
		}
		return adapter.LoadOrCreate[key.MachinePrivate](cfg.NoiseKeypairPath, "noise key", key.NewMachine)
	case KeyStrategyBorrow:
		return adapter.Load[key.MachinePrivate](cfg.NoiseKeypairPath, "noise key")
	default:
		return key.MachinePrivate{}, fmt.Errorf("sidescale: invalid key_strategy %q", cfg.KeyStrategy)
	}
}

// NewMachineKeyProvider returns the per-client upstream machine-identity provider
// selected by cfg.MachineIdentity ("shared", "path:<file>", "pool:<dir>", or "per_client").
func NewMachineKeyProvider(cfg *ControlConfig) (func(client string) (key.MachinePrivate, error), error) {
	return adapter.NewProvider[key.MachinePrivate](cfg.MachineIdentity, "machine_identity", "noise key", key.NewMachine)
}
