# The DERP Protocol

DERP (**D**esignated **E**ncrypted **R**elay for **P**ackets) is Tailscale's packet relay protocol. It routes packets between clients that are addressed by their WireGuard-style Curve25519 public keys ("node keys") rather than by IP address.

DERP relays two kinds of payloads, both of which are already end-to-end encrypted before they reach the relay:

* **Disco discovery messages** — the side channel used during NAT traversal.
* **Encrypted WireGuard packets** — the transport of last resort when UDP is blocked or NAT traversal fails.

The DERP server never decrypts relayed payloads; it only reads the destination key in the frame header and forwards the opaque bytes.

---

## 1. Protocol constants

| Constant | Value | Meaning |
|---|---|---|
| `ProtocolVersion` | `2` | Bumped on wire-incompatible changes. v1 ("zero on wire"): consistent box headers. v2: `FrameRecvPacket` carries the source key. |
| `Magic` | `"DERP🔑"` (8 bytes: `44 45 52 50 f0 9f 94 91`) | Sent at the start of the server greeting. |
| `MaxPacketSize` | `65536` (64 KiB) | Maximum relayed packet payload (excludes framing). |
| `KeyLen` | `32` | Length of a raw Curve25519 public key. |
| `NonceLen` | `24` | NaCl box nonce length. |
| `FrameHeaderLen` | `5` | 1 byte frame type + 4 byte length. |
| `MaxInfoLen` | `1 MiB` | Maximum server-info box size a client will accept. |
| `KeepAlive` | `60s` | Minimum server keep-alive frequency (jitter is added; 2× this can be considered a missed keep-alive). |

All multi-byte integers on the wire are **big-endian**.

---

## 2. Transport establishment

DERP is a stream protocol. It normally runs over TCP + TLS + an HTTP/1.1 upgrade, so that to any middlebox it looks like an ordinary HTTPS connection / WebSocket. Default ports: 443 (HTTPS) or 3340 (plain HTTP when dialing by region, debug/tests; URL-based clients use 80). A node may advertise a non-default port. Three transports exist:

### 2.1 HTTP upgrade (the normal path)

The client sends an HTTP request to the server's `/derp` endpoint:

```
GET /derp HTTP/1.1
Host: <server>
Upgrade: DERP
Connection: Upgrade
```

Optional request headers:

* `Ideal-Node: <node name>` — informative; sent when the client is *not* connecting to its ideal node (the region's primary node). The value is the ideal node's name (the node it wishes it were connected to). The server tracks these connections in metrics and flags them as not-ideal to mesh watchers.
* `Derp-Fast-Start: 1` — tells the server to *not* write the HTTP 101 response at all; the DERP byte stream begins immediately (see §2.3).

Without fast-start, the server hijacks the TCP connection and replies:

```
HTTP/1.1 101 Switching Protocols
Upgrade: DERP
Connection: Upgrade
Derp-Version: 2
Derp-Public-Key: <64 hex chars of the server's node public key>
```

After the blank line, both directions speak raw DERP frames (§3). The `Derp-Version`/`Derp-Public-Key` response headers are informational only: a client checks just the 101 status and learns the server key from the `FrameServerKey` frame (or the metacert, §2.3). Requests whose `Upgrade` header is neither `derp` nor `websocket` are rejected with `426 Upgrade Required`.

### 2.2 WebSocket

For browser clients (js/wasm) that cannot speak raw TCP, the same frame stream can be carried in **binary WebSocket messages**. A WebSocket DERP client must request the `derp` subprotocol (`Sec-WebSocket-Protocol: derp`); the server distinguishes real WebSocket clients from ancient clients that sent `Upgrade: websocket` but spoke raw DERP by requiring that subprotocol. Compression is disabled. Once established, the byte stream inside the WebSocket connection is identical to §3 onward.

### 2.3 TLS "metacert" fast start (round-trip elimination)

The server generates a self-signed ed25519 x509 "metacert" at startup:

* Subject CommonName: the fixed prefix `derpkey` followed by the lowercase-hex node public key of the server.
* Certificate serial number: the DERP `ProtocolVersion`.

The server appends this metacert to its real certificate chain (after the leaf and intermediates). Because TLS 1.3 encrypts server certificates, the client can read the metacert without revealing to observers that this is DERP.

When a client sees a metacert in a TLS ≥1.3 handshake, it learns the server's public key and protocol version early and:

1. Sends `Derp-Fast-Start: 1` in the upgrade request and does not wait for (or read) any HTTP response.
2. Skips waiting for the `FrameServerKey` greeting (it already knows the key) and immediately sends its `FrameClientInfo`.

This saves a full round trip. If a corporate TLS-intercepting proxy strips the extra cert, the client silently falls back to the ordinary handshake.

---

## 3. Framing

Every message in both directions is a frame:

```
+------------+---------------------+------------------------+
| type (1B)  | length (4B, BE)     | payload (length bytes) |
+------------+---------------------+------------------------+
```

The length covers only the payload, not the 5-byte header. Receivers must skip frames with types they don't understand (both the client and server do this), which is the protocol's primary extensibility mechanism. Several frames are also explicitly defined to allow future trailing bytes.

Length validation differs by direction. The server closes the connection on malformed frames: `FrameNotePreferred` length ≠ 1, `FrameWatchConns` ≠ 0, `FrameClosePeer` ≠ 32, `FramePing` < 8 or > 1000, `FrameClientInfo` < 56 or > 256 KiB, and `FrameSendPacket`/`FrameForwardPacket` whose packet payload exceeds 64 KiB. Clients are lenient: they kill the connection only on frames larger than 1 MiB, and silently skip known frame types that are too short (short peer-gone, peer-present, recv-packet, ping, pong, restarting).

### Frame type summary

| Type | Name | Direction | Payload |
|---|---|---|---|
| `0x01` | `FrameServerKey` | S→C | 8B magic + 32B server public key (+ future bytes) |
| `0x02` | `FrameClientInfo` | C→S | 32B client public key + NaCl box of JSON `ClientInfo` |
| `0x03` | `FrameServerInfo` | S→C | NaCl box of JSON `ServerInfo` |
| `0x04` | `FrameSendPacket` | C→S | 32B dest key + packet bytes |
| `0x05` | `FrameRecvPacket` | S→C | 32B src key + packet bytes (src key only in protocol v2+) |
| `0x06` | `FrameKeepAlive` | S→C | empty |
| `0x07` | `FrameNotePreferred` | C→S | 1 byte: `0x01` home server / `0x00` not |
| `0x08` | `FramePeerGone` | S→C | 32B peer key + 1B reason |
| `0x09` | `FramePeerPresent` | S→C | 32B peer key [+ 16B IP + 2B port [+ 1B flags]] |
| `0x0a` | `FrameForwardPacket` | mesh peer→S | 32B src key + 32B dst key + packet bytes |
| `0x10` | `FrameWatchConns` | C→S (privileged) | empty |
| `0x11` | `FrameClosePeer` | C→S (privileged) | 32B peer key |
| `0x12` | `FramePing` | both | 8B opaque payload |
| `0x13` | `FramePong` | both | 8B payload echoed from the ping |
| `0x14` | `FrameHealth` | S→C | UTF-8 problem text; empty clears |
| `0x15` | `FrameRestarting` | S→C | 4B reconnect-in ms + 4B try-for ms |

---

## 4. Handshake

```
client                              server
  |  ---------- TCP/TLS/HTTP upgrade ---------->  |
  |  <--------- FrameServerKey ----------------   |   (skipped if metacert seen)
  |  ---------- FrameClientInfo -------------->   |
  |  <--------- FrameServerInfo ---------------   |
  |             (steady state begins)             |
```

### 4.1 `FrameServerKey` (server → client)

Payload: `Magic` (8 bytes) followed by the server's 32-byte public node key. Clients tolerate additional trailing bytes for future use, up to a 1 KiB total frame. A client that already learned the key from the TLS metacert does not read this frame during setup; the server sends it anyway, and the client's normal receive loop later discards it as an unhandled frame type.

### 4.2 `FrameClientInfo` (client → server)

Payload: the client's 32-byte public key, then a **NaCl box** (crypto_box: Curve25519 + XSalsa20-Poly1305; 24-byte nonce prepended to the ciphertext) sealed from the client's private key to the server's public key. This is the client's proof of identity: only the holder of the private key matching the claimed public key can produce a box the server can open.

The plaintext is JSON `ClientInfo`:

```json
{
  "version": 2,               // ProtocolVersion the client speaks; omitted if zero
  "meshKey": "…",             // pre-shared mesh key (64 hex chars); omitted if empty
  "CanAckPings": true,        // whether the client will answer FramePing; always present
  "IsProber": false           // whether this is a monitoring prober; omitted if false
}
```

The frame must be at least 56 bytes (key + nonce) and at most 256 KiB. The server applies a 10-second deadline to each handshake step (greeting, then client-info); after the client is verified (§7.4) the deadline is removed.

### 4.3 `FrameServerInfo` (server → client)

Payload: a NaCl box sealed from the server's private key to the client's public key, containing JSON `ServerInfo`:

```json
{
  "version": 2,
  "TokenBucketBytesPerSecond": 0,  // advisory send rate for the client; 0 = unspecified
  "TokenBucketBytesBurst": 0       // advisory burst size; 0 = unspecified
}
```

Current servers always send just `{"version": 2}`; the token-bucket fields are legacy (if a nonzero rate is given, a client installs a local token-bucket limiter and silently *drops* its own `FrameSendPacket` writes that exceed it). Clients do not block the handshake on this frame; they parse it in the normal receive loop.

Version negotiation is vestigial: the server never reads `ClientInfo.version` (or `CanAckPings`) and always writes v2-format `FrameRecvPacket` frames, and the client ignores `ServerInfo.version` and always parses the v2 layout. New implementations need not support v0/v1 framing.

---

## 5. Steady state

### 5.1 Sending and receiving packets

* Client sends `FrameSendPacket`: 32-byte destination key + payload (payload ≤ 64 KiB, otherwise the connection errors).
* The server delivers it to the destination as `FrameRecvPacket`: 32-byte source key + payload (v2 framing; v0/1 omitted the source key).

Delivery is **best-effort and unordered relative to drops**: the server queues packets per destination and drops under pressure (§7.2). There are no acknowledgements at the DERP layer; loss recovery belongs to the payload protocol (WireGuard, disco retries).

### 5.2 Keep-alives, pings, pongs

* The server sends `FrameKeepAlive` (empty) on a fixed per-connection ticker of `KeepAlive` (60s) plus a random jitter of up to 5s chosen once per connection, regardless of other traffic. It is one-way; no reply is expected.
* Either side may send `FramePing` with 8 opaque bytes; the other side replies `FramePong` echoing the same 8 bytes. The server answers client pings (buffering at most one outstanding pong reply; excess pings are ignored) and accepts ping payloads up to 1000 bytes for future extensibility, using only the first 8. Clients advertise willingness to answer server pings via `CanAckPings`.
* Clients use a 120-second read timeout (2× keep-alive) — if nothing arrives in that window the connection is considered dead.

### 5.3 `FrameNotePreferred` (client → server)

One byte, `0x01`/`0x00`: whether this server is the client's "home" (preferred) DERP. Used only for server statistics (current home client counts, home-move counters).

### 5.4 `FramePeerGone` (server → client)

Payload: 32-byte peer key + 1-byte reason. Sent to a client B when:

* A peer A that previously sent packets to B disconnects from the region — reason `0x00` (`PeerGoneReasonDisconnected`) — so B can drop its reverse DERP route to A. The server tracks, per connection, the set of source keys it has delivered packets from, and subscribes to region-wide disconnects of those keys.
* B sends a packet (directly, or as a mesh peer forwarding one) to a key the server has no route for — reason `0x01` (`PeerGoneReasonNotHere`), sent back on the connection that sent the packet. To avoid amplification, "not here" replies are only generated in response to packets that look like disco messages and are rate-limited to 1/second (burst 3) per connection. They fire only when the key has no connections at all; packets to a duplicate set with no active client (§7.1) are dropped without a reply.

Reason `0xf0` (`PeerGoneReasonMeshConnBroke`) never appears on the wire; it's synthesized locally by mesh watch clients when their watch connection breaks.

Older servers sent this frame without the reason byte; clients treat a missing byte as `Disconnected`.

### 5.5 `FrameHealth` (server → client)

The payload is a human-readable problem description; an empty payload clears the problem state. Defined for telling a client its connection was detected as a duplicate; current servers parse but never send it, so clients must handle it but servers need not emit it.

### 5.6 `FrameRestarting` (server → client)

Two big-endian `uint32` durations in **milliseconds**:

1. `ReconnectIn` — advisory wait before reconnecting (lets the server smear the reconnect thundering herd).
2. `TryFor` — advisory total duration to keep retrying before falling back to normal failure logic. Servers shouldn't send more than a few seconds.

Like `FrameHealth`, this frame is parsed by clients but not sent by current servers.

---

## 6. Mesh protocol (regional server federation)

Tailscale runs multiple DERP nodes per region, "meshed" together. Every node connects to every other node in its region as a **privileged client**, authenticated by presenting the pre-shared **mesh key** in `ClientInfo.meshKey`. Mesh keys are compared in constant time. Packets are forwarded at most **one hop** within a region; there is no inter-region routing.

Privileged (mesh) connections unlock four frame types:

### 6.1 `FrameWatchConns` (client → server, no payload)

Subscribes to the server's connection table. Sent by a mesh node (or trusted monitoring tools) right after connect. The server immediately floods the watcher with one `FramePeerPresent` per currently connected key (the active connection of each set), then streams `FramePeerPresent`/`FramePeerGone` as clients come and go. Sending this without mesh permission is a fatal error (connection closed).

Note: `FramePeerPresent` is sent for *every* new connection of a key, while `FramePeerGone` historically fires only when a key's connection count drops to zero, so watchers must do their own duplicate accounting.

### 6.2 `FramePeerPresent` (server → watcher)

Layout (current servers send 51 bytes; older send fewer, newer may send more):

```
[32B peer public key][16B IP (IPv4 as v6-mapped)][2B BE port][1B flags]
```

Flags bitmask (`PeerPresentFlags`; a value of 0 means the server predates the field):

| Bit | Meaning |
|---|---|
| `1<<0` | regular client |
| `1<<1` | mesh peer |
| `1<<2` | prober |
| `1<<3` | connection is not the client's ideal node in the region |

The regular-client bit is set only when no other bit applies (e.g. a not-ideal regular client reports just `1<<3`).

### 6.3 `FrameForwardPacket` (mesh peer → server)

`[32B src key][32B dst key][payload]`. When node X receives a `FrameSendPacket` for a key connected to sibling node Y (learned via the watch stream), X forwards it over its mesh connection to Y. Y delivers it to the local destination as a normal `FrameRecvPacket` carrying the *original* source key. A forwarded packet that finds no local destination is dropped (never re-forwarded), avoiding loops. Mesh connections are exempt from server receive rate limits and get a longer write timeout (30s vs 2s). On the sending side, each forward write is guarded by a 5-second stall timer that closes the connection on expiry; forwards are also exempt from the client's advisory send-rate limiter (§4.3).

If a key is reachable via multiple sibling nodes simultaneously (a client mid-reconnect), the server consistently prefers the earliest-registered forwarder rather than picking randomly.

### 6.4 `FrameClosePeer` (mesh peer → server)

`[32B peer key]`. Administratively closes all of that peer's TCP connections on this server. Intended for cluster rebalancing, to push a client back to its ideal node.

---

## 7. Server behavior details

These are server behaviors that shape what clients can rely on.

### 7.1 Client registry and duplicate connections

Clients are keyed by public key. Multiple simultaneous connections with the same key form a **duplicate set**. The server never kicks the earlier connection; all members stay open (so buggy clients don't spin) and are flagged as duplicates, and packets to a set with no active client are dropped. Which member is the **active** client — the one receiving data frames — is governed by a server `dupPolicy`:

* `lastWriterIsActive` (default) — the newest connection is active on register, and thereafter the active client follows the last connection to write.
* `disableFighters` — the newest connection is active and writes do not move it, but if the set's connections interleave sends (a sign of a cloned key), every member is disabled and the set has no active client, dropping packets to it until it collapses back to a single connection.

Removing a member never emits `FramePeerGone`. When the active connection leaves a set with two or more members, the set has no active client (packets to it drop) until another member writes; only a collapse back to a single connection re-enables a disabled member and makes it active. Peer-gone fires only when the last connection for a key departs, so an old connection tearing down after a replacement has taken over is a no-op.

### 7.2 Per-client send queues and drop policy

Each client connection has two queues (default depth 32 each):

* A normal-packet queue.
* A disco queue — packets that look like disco messages, queued separately so NAT-traversal control traffic survives data floods.

On a full queue the enqueuer makes up to 3 attempts, each time dropping the packet at the queue **head** (oldest) to make room; if it still can't enqueue it tail-drops the new packet. Drops are categorized by reason (unknown destination, unknown destination on forward, gone/disconnected, queue-head eviction, tail-drop, write error, duplicate-client) and by kind (disco vs other). When a connection's send loop exits, both queues are drained and their packets counted as gone/disconnected drops.

A single writer goroutine per connection drains: peer-gone requests, mesh updates, both packet queues, pong replies, and the keep-alive timer, batching frames between flushes. Write timeout is 2s for regular clients, 30s for mesh-key holders.

### 7.3 Receive rate limiting (server side)

Optionally, the server can token-bucket limit bytes *read* per client (configured with a per-client rate in bytes/sec and a burst size), by pausing reads so TCP backpressure throttles the sender. The burst is clamped to at least `MaxPacketSize + KeyLen` (the largest possible `FrameSendPacket`). Mesh peers are exempt.

### 7.4 Client admission (verification)

At connect time, after opening the `ClientInfo` box, the server can verify the client key by any combination of:

1. **Mesh key** — matching mesh-key clients are trusted outright and skip the other checks.
2. **Local daemon check** — the key must be a visible peer of the local Tailscale daemon running on the same host.
3. **Admission controller URL** — the server POSTs a JSON request `{NodePublic, Source}` (the client key and source IP) and requires HTTP 200 with `{"Allow": true}` within 5s; optionally fail-open if the controller is unreachable.

---

## 8. Client behavior details

The behaviors below describe how a well-behaved DERP-over-HTTP client operates.

* **Dialing a region**: nodes are tried sequentially in DERP-map order (STUN-only nodes skipped); for each node the client races IPv4 and IPv6 TCP dials (IPv4 delayed 200ms when IPv6 is preferred), with a 1.5s TCP-dial timeout per node and a 10s overall budget for DNS + TCP + TLS + upgrade. HTTP CONNECT proxies are supported.
* **TLS**: the SNI / verified name is the node's hostname (or the URL host); a node may pin an expected cert name or a `sha256-raw:` hash. The handshake is forced eagerly so the metacert can be inspected before the upgrade. The WebSocket path (js/wasm) never uses metacert fast-start.
* **Home node**: callers mark their home server via a note-preferred call; the client sends the frame immediately and replays the last-set state on each reconnect.
* **Ping correlation**: a ping sends 8 random bytes and matches the pong by payload, with a 5s cap.
* **Mesh watch loop**: reconnects every 5s on error, invokes add/remove callbacks for `PeerPresent`/`PeerGone`, and on reconnect synthesizes `PeerGone(MeshConnBroke)` for all previously seen peers before the fresh `PeerPresent` flood arrives.

---

## 9. Security properties and limits

* **Authentication**: mutual proof of key possession via NaCl box in the `ClientInfo`/`ServerInfo` exchange. The server's key is learned from the TLS metacert or the (TLS-protected) `FrameServerKey` greeting — the 101 response headers are ignored; the DERP map from the coordination server pins which servers a client trusts.
* **The server can spoof source keys in principle** (it writes the src key in `FrameRecvPacket`), but payloads are authenticated end-to-end, so a spoofed source yields undecryptable packets.
* **Limits**: 64 KiB max relayed packet; 1 MiB max frame a client will accept (larger frames kill the connection); 256 KiB max `ClientInfo`; 10s handshake deadline; amplification-resistant, rate-limited "not here" replies (§5.4).

---

## 10. Related non-protocol endpoints

A DERP server commonly exposes a few HTTP endpoints alongside the relay that are not part of the relay protocol itself:

* `/derp/probe` (a.k.a. `/derp/latency-check`): a HEAD/GET endpoint used by clients without UDP (e.g. js/wasm) to measure DERP HTTP latency instead of STUN.
* `/generate_204`: a no-content endpoint for captive-portal detection, echoing an `X-Tailscale-Challenge` header value back in an `X-Tailscale-Response` header.
* A UDP **STUN** responder typically runs alongside the relay for NAT discovery; it is a separate protocol and not part of DERP.
