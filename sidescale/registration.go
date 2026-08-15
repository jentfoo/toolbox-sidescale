package main

import (
	"encoding/json"

	"github.com/go-appsec/toolbox/pkg/addr"
	"github.com/go-appsec/toolbox/sidecar"
	"github.com/go-appsec/toolbox/sidecar/wire"
	"github.com/jentfoo/toolbox-sidescale/sidescale/derp"
	"github.com/jentfoo/toolbox-sidescale/sidescale/noise"
)

// injectionTargetSchema is the payload the tailscale_inject tool / invoke_adapter accepts.
var injectionTargetSchema = json.RawMessage(`{
  "type": "object",
  "required": ["endpoint", "body"],
  "properties": {
    "tunnel_id": {"type": "string", "description": "flow_id of an active tunnel envelope to ride; only honored with reuse_tunnel"},
    "endpoint": {"type": "string", "description": "/machine/register, /machine/map, or a custom path"},
    "method": {"type": "string", "default": "POST"},
    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
    "body": {"description": "agent-supplied JSON request body"},
    "stream": {"type": "boolean", "default": false},
    "as_machine": {"type": "string", "description": "override the machine identity for this injection"},
    "as_version": {"type": "integer", "description": "override the cleartext handshake capability version for a fresh tunnel (independent of the body Version), to exercise the server version floor"},
    "reuse_tunnel": {"type": "boolean", "default": false, "description": "ride the live tunnel named by tunnel_id instead of a fresh one; WARNING: disturbs that client's map session"},
    "mutations": {"type": "array", "description": "mutation ops applied to the request before sending"}
  }
}`)

const injectToolDescription = "Originate a Tailscale control-plane request (register/map/custom endpoint) into a fresh Noise tunnel with a distinct identity (does not disturb live clients) and capture the response. Set reuse_tunnel with tunnel_id to ride a live client's tunnel instead (disturbs that client's map session). A streaming response (map with stream:true) returns the stream parent flow id; read the chunk children via flow_get/proxy_poll."

// buildRegistration builds the register handshake payload for cfg. instanceID must be
// a stable UUID so reconnect reattaches ownership.
func buildRegistration(cfg Config, instanceID string) sidecar.Registration {
	host, clientPort := addr.Parse(cfg.Control.ControlHosts[0], "https")
	caps := wire.Capabilities{
		UpgradeClaims: []wire.UpgradeClaim{{
			HostPattern:   host,
			PathPattern:   "/ts2021",
			UpgradeSignal: "http_101",
			MethodSet:     []string{"POST"},
		}},
		InjectionTargets: []wire.InjectionTarget{{TargetSchema: injectionTargetSchema}},
	}
	// sidecar_tls serves /key in the byte path: claim the host-terminated control
	// TLS connection so cleartext /key requests reach serveKey
	if cfg.Control.KeyStrategy == noise.KeyStrategySubstitute && cfg.Control.KeySubstitution == noise.KeySubSidecarTLS {
		caps.EarlyClaims = append(caps.EarlyClaims, wire.EarlyClaim{
			PortRange: wire.PortRange{Low: clientPort, High: clientPort},
			HostMatch: host,
			TLS:       &wire.TLSClaim{Terminate: true, SNIMatch: host},
		})
	}

	protocols := noise.Protocols()
	tools := []wire.MCPTool{{
		Name:        noise.InjectToolName,
		Description: injectToolDescription,
		InputSchema: injectionTargetSchema,
	}}

	if cfg.Derp != nil {
		addDerpClaims(&caps, cfg.Derp)
		protocols = append(protocols, derp.Protocols()...)
		caps.InjectionTargets = append(caps.InjectionTargets, wire.InjectionTarget{TargetSchema: derp.InjectionTargetSchema})
		tools = append(tools, wire.MCPTool{
			Name:        derp.InjectToolName,
			Description: derp.InjectToolDescription,
			InputSchema: derp.InjectionTargetSchema,
		})
	}

	return sidecar.Registration{
		Name:         cfg.Name,
		Protocols:    protocols,
		Capabilities: caps,
		MCPTools:     tools,
		InstanceID:   instanceID,
		Resume:       true,
	}
}

// addDerpClaims adds the DERP transport claims for cfg's hosts.
func addDerpClaims(caps *wire.Capabilities, cfg *derp.DerpConfig) {
	for _, h := range cfg.DerpHosts {
		host, port := addr.Parse(h, "https")
		if cfg.RelayMode == derp.RelayModeTerminate {
			claim := wire.EarlyClaim{
				PortRange: wire.PortRange{Low: port, High: port},
				HostMatch: host,
				TLS:       &wire.TLSClaim{Terminate: true, SNIMatch: host},
			}
			if len(cfg.CertNameSANs) > 0 {
				claim.TLS.Cert = &wire.TLSCertSpec{DNSNames: cfg.CertNameSANs}
			}
			caps.EarlyClaims = append(caps.EarlyClaims, claim)
			continue
		}
		caps.UpgradeClaims = append(caps.UpgradeClaims, wire.UpgradeClaim{
			HostPattern:   host,
			PathPattern:   "/derp",
			UpgradeSignal: "http_101",
			MethodSet:     []string{"GET"},
		})
	}
}
