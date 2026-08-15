package tsproto

import "tailscale.com/tailcfg"

// Inner control-protocol message types, aliased to centralize the tailscale.com/tailcfg coupling.
type (
	RegisterRequest   = tailcfg.RegisterRequest
	RegisterResponse  = tailcfg.RegisterResponse
	MapRequest        = tailcfg.MapRequest
	MapResponse       = tailcfg.MapResponse
	EarlyNoise        = tailcfg.EarlyNoise
	CapabilityVersion = tailcfg.CapabilityVersion
)

// CurrentCapabilityVersion is the capability version of the pinned Tailscale upstream.
const CurrentCapabilityVersion = tailcfg.CurrentCapabilityVersion
