# toolbox-sidescale

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/jentfoo/toolbox-sidescale/blob/main/LICENSE)
[![Tests - Main Push](https://github.com/jentfoo/toolbox-sidescale/actions/workflows/tests-main.yml/badge.svg)](https://github.com/jentfoo/toolbox-sidescale/actions/workflows/tests-main.yml)
[![Vibe-Scale 3.0(V2|U1|T1): Significant AI with gaps](https://img.shields.io/badge/Vibe--Scale%203.0(V2%7CU1%7CT1)-Significant%20AI%20with%20gaps-ffe066)](https://github.com/vibesdk/vibe-scale/blob/main/scale/vibe-3.md#v2-u1-t1-score-30--significant-ai-with-gaps)

**A Tailscale control-channel and DERP interception sidecar for [go-appsec/toolbox](https://github.com/go-appsec/toolbox).**

## Background

[go-appsec/toolbox](https://github.com/go-appsec/toolbox) provides `sectool`, an MCP-driven proxy for security testing. It sits in front of an application, captures each request and response as a *flow*, and exposes tools (`proxy_poll`, `flow_get`, `replay_send`, `proxy_rule_add`, `diff_flow`, and more) that an agent uses to inspect, mutate, and replay that traffic. Out of the box it understands HTTP.

A *sidecar* extends sectool to a protocol it does not natively speak. The sidecar terminates the protocol, turns its messages into the same HTTP-shaped flows sectool already works with, and forwards them upstream. Every sectool tool then applies to that protocol unchanged.

`sidescale` is the sidecar for Tailscale. Tailscale wraps its control traffic in an end-to-end encrypted Noise tunnel, so an ordinary proxy sees only opaque bytes. `sidescale` sits between a Tailscale client and the control server and terminates the Noise tunnel on both sides: to the client it acts as the control server, to the server it acts as a client. That puts the decrypted inner traffic in its hands, and each inner request and response lands in sectool as a normal flow you can capture, mutate, and replay.

One `sidescale` process covers two Tailscale surfaces:

- **Control channel** (`POST /ts2021`), always active.
- **DERP relay** (`GET /derp`), opt-in, enabled by adding a `derp:` section to the config.

It works against production Tailscale (`controlplane.tailscale.com`), a self-hosted coordinator such as Headscale, a Tailscale-deployed DERP server, or a local test setup. The binary is Linux-only because it links Tailscale's upstream packages.

## What it captures

### Control channel (Noise)

`sidescale` decrypts the inner HTTP/2 inside the Noise tunnel, so every `/machine/*` endpoint is captured as an HTTP-shaped flow. That includes `POST /machine/register` and the long-lived streaming `POST /machine/map` (captured chunk by chunk).

- **Mutate.** Match/replace rules rewrite either direction on the hot path and emit a paired captured/mutated flow.
- **Replay.** Re-send any captured flow. `sidescale` rebinds register signatures, hardware attestation, and map sessions when it holds the key material, and otherwise strips and annotates them.
- **Inject.** The `tailscale_inject` tool originates fresh inner messages into an active or new tunnel.

Flows are tagged `tailscale.tunnel`, `tailscale.control`, or `tailscale.control.map.stream`.

### DERP

With a `derp:` section present, the same process intercepts the DERP relay. Relayed packets are end-to-end encrypted and stay opaque, so what is exposed is the frame-level metadata and the decrypted login handshake: `ClientInfo` / `ServerInfo`, the control frames (peer-gone, peer-present, note-preferred, health, restarting, ping/pong), and the packet frames with their source and destination node keys, sizes, and disco classification.

- **`relay` mode** bridges a real DERP server transparently.
- **`terminate` mode** runs a synthetic relay with no upstream, registering each client by node key and forwarding packets between them.
- **Inject.** The `derp_inject` tool originates frames, most usefully the server-to-client frames a hostile relay could send.

Flows are tagged `tailscale.derp.tunnel` or `tailscale.derp.frame`.

Because the flows are HTTP-shaped, agents use sectool's existing tools unchanged.

## Getting started

### 1. Build

```bash
make build          # builds bin/sidescale (Linux)
```

### 2. Enable sidecars in sectool

Sidecars are off by default. Enable them in `~/.sectool/config.json`, then start sectool with a workflow selected (the sidecar's setup handshake needs one):

```bash
tmp=$(mktemp); jq '.sidecars.enabled = true' ~/.sectool/config.json > "$tmp" && mv "$tmp" ~/.sectool/config.json
sectool mcp --workflow none
```

### 3. Run sidescale

```bash
bin/sidescale -config /path/to/sidescale.json
```

`sidescale` resolves sectool's socket at `~/.sectool/sidecar.sock` by default. Override it with `-sidecar-socket` or the config's `sectool.socket` field.

### 4. Start order

Start sectool, then sidescale, then the client. The Tailscale client caches the server's Noise key on its first `/key` fetch and never refetches on the hot path, so both must be up before the client makes first contact. If the client connected first, restart it (`tailscale down` / `up`).

## Configuration

A JSON file with a `control` section (always active) and an optional `derp` section:

```json
{
  "name": "sidescale",
  "sectool": { "socket": "/home/you/.sectool/sidecar.sock" },
  "control": { "...": "..." },
  "derp":    { "...": "..." }
}
```

### Control section

| Field | Description |
|-------|-------------|
| `control_hosts` | Host patterns to claim for `POST /ts2021` (default `controlplane.tailscale.com`). Add a `:port` when the `substitute` `/key` responder runs on a non-443 port |
| `key_strategy` | `substitute` (default) serves the client a fresh responder key; `borrow` serves the real upstream key and requires `noise_keypair_path` |
| `key_substitution` | Under `substitute`: `responder` (default) registers a canned `/key` response, or `sidecar_tls` terminates the `/key` TLS in the sidecar |
| `noise_keypair_path` | Responder Noise private key. Required for `borrow`; optional for a persistent `substitute` key |
| `upstream_overrides` | Map of `host` to `host:port` redirecting the upstream dial (for example a local coordinator) |
| `machine_identity` | Upstream initiator identity: `per_client` (default, one stable key per client), `shared` (one key for all clients), `path:<file>`, or `pool:<dir>` |
| `device_cert_path`, `device_key_path`, `hw_key_path` | Optional key material to rebind register signatures and hardware attestation on replay instead of stripping them |
| `upstream_scheme` | `auto` (default, HTTPS/443), `https`, or `http` for a plaintext control server |
| `upstream_pool_mode` | `shared` (default, one upstream session per machine identity) or `per_client` (one session per client-facing tunnel) |
| `early_noise` | `forward` (default), `suppress`, or `replace` the upstream EarlyNoise frame |

**Choosing a key strategy.** `substitute` is the only strategy that works against an upstream whose key you do not hold, including production `controlplane.tailscale.com`. `borrow` is for an operator-controlled coordinator whose Noise private key you can supply. It trades stealth for exact real-key fidelity. A minimal `borrow` config against a local coordinator:

```json
"control": {
  "control_hosts": ["ts.test"],
  "key_strategy": "borrow",
  "noise_keypair_path": "/home/you/noise_private.key",
  "upstream_overrides": { "ts.test": "127.0.0.1:8443" },
  "machine_identity": "per_client"
}
```

### DERP section

Present this section to enable the DERP surface alongside control.

| Field | Description |
|-------|-------------|
| `derp_hosts` | Host patterns to claim for `GET /derp`, as `host` or `host:port` (default port 443). Required |
| `relay_mode` | `relay` (default) bridges a real DERP server; `terminate` runs a synthetic relay with no upstream |
| `server_key` | Client-facing server key: `substitute` (default, fresh key) or `borrow` (requires `server_keypair_path`) |
| `server_keypair_path` | DERP server node private key. Required for `borrow` |
| `node_identity` | Upstream client identity (`relay` only): `per_client` (default), `shared`, `path:<file>` for a transparent relay, or `pool:<dir>` |
| `upstream_overrides` | Map of `host` to `host:port` for the upstream DERP dial |
| `cert_name_sans` | Additive leaf SANs, for a `terminate` host whose DERP map pins a plain `CertName` |
| `dup_policy` | Duplicate-key policy in `terminate` mode: `last_writer` (default) or `disable_fighters` |
| `mesh_key` | Mesh key for mesh impersonation (injecting mesh frames or presenting a mesh identity the client did not) |

**`relay` mode** bridges a real DERP server. With `node_identity: per_client` the sidecar presents a fresh stable key per client, which captures the client-to-sidecar leg, handshake, and metadata cleanly but is not a fully transparent relay: peer return paths keyed to the client's real node key do not survive. Use `path:<file>` with the client's node private key to preserve addressing end to end.

```json
"derp": {
  "derp_hosts": ["ts.test"],
  "relay_mode": "relay",
  "server_key": "substitute",
  "node_identity": "per_client",
  "upstream_overrides": { "ts.test": "127.0.0.1:8443" }
}
```

**`terminate` mode** needs no upstream, so `node_identity` and `upstream_overrides` are ignored and `derp_hosts` names the synthetic host every client dials:

```json
"derp": {
  "derp_hosts": ["derp.test"],
  "relay_mode": "terminate",
  "server_key": "substitute"
}
```

## Reading the flows

`sidescale` flows nest. The `/ts2021` (or `/derp`) upgrade is a top-level flow, the tunnel envelope and upstream dial audit are its children, and the inner control requests or DERP frames are children of the tunnel envelope. `proxy list` is oldest-first and shows only top-level flows, so drill down by parent:

```bash
sectool proxy list --limit 3000 | grep /ts2021 | tail        # newest /ts2021 upgrade
sectool proxy list --parent-flow-id <ts2021_flow_id>         # dial audit + tunnel envelope
sectool proxy list --parent-flow-id <tunnel_flow_id>         # register + map children
sectool proxy get  <tunnel_flow_id>                          # decrypted handshake headers
sectool proxy get  <register_flow_id>                        # decrypted RegisterRequest body
```
