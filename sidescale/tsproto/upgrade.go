package tsproto

import "tailscale.com/control/controlhttp/controlhttpcommon"

// ts2021 control-protocol HTTP upgrade constants, re-exported so the tunnel and capture
// layers don't import controlhttpcommon directly.
const (
	// UpgradeProtocol is the Upgrade / Connection header token.
	UpgradeProtocol = controlhttpcommon.UpgradeHeaderValue
	// HandshakeHeaderName carries the base64 Noise initiation on the upgrade request.
	HandshakeHeaderName = controlhttpcommon.HandshakeHeaderName
)
