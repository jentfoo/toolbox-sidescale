package noise

import (
	"errors"
	"fmt"
	"slices"

	"github.com/jentfoo/toolbox-sidescale/sidescale/adapter"
)

// Key strategies for the client-facing responder key.
const (
	KeyStrategySubstitute = "substitute"
	KeyStrategyBorrow     = "borrow"
)

// /key substitution mechanisms under the substitute strategy.
const (
	// KeySubResponder registers a canned /key response via the native proxy (host terminates TLS with its CA).
	KeySubResponder = "responder"
	// KeySubSidecarTLS terminates the /key TLS in the sidecar using a CA-signed leaf fetched from the proxy.
	KeySubSidecarTLS = "sidecar_tls"
)

// Upstream transport scheme for the ts2021/key dials.
const (
	// UpstreamSchemeAuto dials HTTPS on 443 (default), unless an upstream_overrides URL specifies otherwise.
	UpstreamSchemeAuto = "auto"
	// UpstreamSchemeHTTPS forces TLS upstream.
	UpstreamSchemeHTTPS = "https"
	// UpstreamSchemeHTTP forces plaintext upstream.
	UpstreamSchemeHTTP = "http"
)

// Upstream Noise-session pooling modes.
const (
	// PoolModeShared coalesces every tunnel with the same machine identity onto one upstream Noise session (default).
	PoolModeShared = "shared"
	// PoolModePerClient gives each client-facing tunnel its own upstream Noise session,
	// so the control server sees distinct concurrent sessions.
	PoolModePerClient = "per_client"
)

// EarlyNoise forwarding modes toward the client.
const (
	// EarlyNoiseForward relays the upstream EarlyNoise frame verbatim (default).
	EarlyNoiseForward = "forward"
	// EarlyNoiseSuppress drops the EarlyNoise frame entirely.
	EarlyNoiseSuppress = "suppress"
	// EarlyNoiseReplace substitutes a synthesized EarlyNoise frame with a fresh challenge.
	EarlyNoiseReplace = "replace"
)

const defaultControlHost = "controlplane.tailscale.com"

// ControlConfig is the control: section of the sidescale config (the Noise surface).
type ControlConfig struct {
	ControlHosts      []string          `json:"control_hosts,omitempty"`
	UpstreamOverrides map[string]string `json:"upstream_overrides,omitempty"`
	KeyStrategy       string            `json:"key_strategy,omitempty"`
	KeySubstitution   string            `json:"key_substitution,omitempty"`
	NoiseKeypairPath  string            `json:"noise_keypair_path,omitempty"`
	DeviceCertPath    string            `json:"device_cert_path,omitempty"`
	DeviceKeyPath     string            `json:"device_key_path,omitempty"`
	HWKeyPath         string            `json:"hw_key_path,omitempty"`
	MachineIdentity   string            `json:"machine_identity,omitempty"`
	UpstreamScheme    string            `json:"upstream_scheme,omitempty"`
	UpstreamPoolMode  string            `json:"upstream_pool_mode,omitempty"`
	EarlyNoise        string            `json:"early_noise,omitempty"`
}

// ApplyDefaults fills unset fields with their defaults.
func (c *ControlConfig) ApplyDefaults() {
	if len(c.ControlHosts) == 0 {
		c.ControlHosts = []string{defaultControlHost}
	}
	if c.KeyStrategy == "" {
		c.KeyStrategy = KeyStrategySubstitute
	}
	if c.KeySubstitution == "" {
		c.KeySubstitution = KeySubResponder
	}
	if c.MachineIdentity == "" {
		c.MachineIdentity = adapter.IdentityPerClient
	}
	if c.UpstreamScheme == "" {
		c.UpstreamScheme = UpstreamSchemeAuto
	}
	if c.UpstreamPoolMode == "" {
		c.UpstreamPoolMode = PoolModeShared
	}
	if c.EarlyNoise == "" {
		c.EarlyNoise = EarlyNoiseForward
	}
}

// Validate reports configuration errors after defaults are applied.
func (c *ControlConfig) Validate() error {
	if !slices.Contains([]string{KeyStrategySubstitute, KeyStrategyBorrow}, c.KeyStrategy) {
		return fmt.Errorf("sidescale: invalid key_strategy %q", c.KeyStrategy)
	} else if c.KeyStrategy == KeyStrategyBorrow && c.NoiseKeypairPath == "" {
		return errors.New("sidescale: key_strategy=borrow requires noise_keypair_path")
	} else if c.KeyStrategy == KeyStrategySubstitute && !slices.Contains([]string{KeySubResponder, KeySubSidecarTLS}, c.KeySubstitution) {
		return fmt.Errorf("sidescale: invalid key_substitution %q", c.KeySubstitution)
	} else if !slices.Contains([]string{UpstreamSchemeAuto, UpstreamSchemeHTTPS, UpstreamSchemeHTTP}, c.UpstreamScheme) {
		return fmt.Errorf("sidescale: invalid upstream_scheme %q", c.UpstreamScheme)
	} else if !slices.Contains([]string{PoolModeShared, PoolModePerClient}, c.UpstreamPoolMode) {
		return fmt.Errorf("sidescale: invalid upstream_pool_mode %q", c.UpstreamPoolMode)
	} else if !adapter.ValidIdentity(c.MachineIdentity) {
		return fmt.Errorf("sidescale: invalid machine_identity %q", c.MachineIdentity)
	} else if !slices.Contains([]string{EarlyNoiseForward, EarlyNoiseSuppress, EarlyNoiseReplace}, c.EarlyNoise) {
		return fmt.Errorf("sidescale: invalid early_noise %q", c.EarlyNoise)
	}
	return nil
}
