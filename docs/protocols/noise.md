# The Tailscale Control Protocol (Noise / TS2021)

The Tailscale **control protocol** (also called **TS2021**), is how a Tailscale node talks to its coordination server ("control"): registering the machine, fetching the network map, and exchanging configuration. It carries no user data-plane traffic; that lives in the WireGuard and DERP data plane.

The control channel is protected end-to-end by a **Noise** tunnel, so the coordination server is authenticated cryptographically and the session is confidential even when the outer transport is plaintext HTTP. Inside that tunnel the two sides speak ordinary **HTTP/2**: the client issues JSON `POST`s to `/machine/*` endpoints and receives JSON (or a streamed, compressed sequence of JSON fragments) back.

The protocol has three layers, established in order:

1. **Trust bootstrap** — a plain-TLS `GET /key` that hands the client the server's long-term Noise public key.
2. **Noise tunnel** — a Noise IK handshake carried over an HTTP upgrade to `/ts2021`, after which the raw TCP connection is an encrypted duplex stream.
3. **Inner HTTP/2** — the registration and map protocol, spoken as HTTP/2 frames inside the Noise tunnel.

---

## 1. Protocol constants

| Constant | Value | Meaning |
|---|---|---|
| Noise protocol name | `Noise_IK_25519_ChaChaPoly_BLAKE2s` | The exact string used to initialize the handshake hash. IK pattern, Curve25519 DH, ChaCha20-Poly1305 AEAD, BLAKE2s-256 hash. |
| Prologue prefix | `"Tailscale Control Protocol v"` | Followed by the decimal protocol version; mixed into the handshake hash. |
| `CurrentCapabilityVersion` | `142` (release-specific) | The client's capability version. Bumped on most releases; appears in four places (§2). Servers enforce a minimum. |
| Upgrade token | `tailscale-control-protocol` | HTTP `Upgrade` header value (and WebSocket subprotocol name). |
| Handshake header | `X-Tailscale-Handshake` | Carries the base64 Noise initiation in the upgrade request (§4.1). |
| Upgrade path | `/ts2021` | The control-tunnel HTTP upgrade endpoint. |
| Key path | `/key` | The trust-bootstrap endpoint (§3). |
| `EarlyPayloadMagic` | `\xff\xff\xffTS` (5 bytes: `ff ff ff 54 53`) | Marks a server EarlyNoise payload; deliberately not a valid HTTP/2 frame prefix (§4.3). |
| Max Noise frame | `4096` bytes | Full transport record including its 3-byte header. |
| Max Noise plaintext | `4077` bytes | Per record (4096 − 3-byte header − 16-byte AEAD tag). |
| Max EarlyNoise payload | `10 MiB` | Larger is rejected. |
| Key text prefixes | `mkey:` / `nodekey:` / `discokey:` | Machine / node / disco public keys, each `<prefix><64 hex chars>` (§8). |

**Endianness is not uniform, and this is the single most error-prone point in the protocol:**

* All **Noise-layer** length fields and the transport nonce counter are **big-endian** (the 2-byte version, every 2-byte message length, the EarlyNoise 4-byte length).
* The **inner MapResponse** stream frames its fragments with a 4-byte **little-endian** length prefix (§7).

---

## 2. The capability version

A single integer, `CurrentCapabilityVersion` (142 at the time of writing, incremented by most releases), identifies what the client speaks. The **same value appears four times** per session and all four must agree:

1. The 2-byte big-endian protocol version at the head of the Noise initiation message (§5.2), mixed into the handshake prologue.
2. The `v=<version>` query parameter of the `GET /key` bootstrap (§3).
3. The `Version` field of every `RegisterRequest` (§6).
4. The `Version` field of every `MapRequest` (§6).

Because the version travels in cleartext in the Noise initiation header **and** in the prologue that is mixed into the handshake hash, tampering with it in flight breaks MAC verification — the two sides are cryptographically bound to the version each advertised in the clear. A man-in-the-middle that regenerates the initiation must carry the client's advertised version through unchanged.

Servers enforce a floor. As a concrete reference point, one open-source coordination server gates the `/key` response on version ≥ 39 but rejects `register`/`map` below version 113, returning HTTP 400 with an "unsupported client version" message. A client between those two thresholds gets a valid key but is refused at register time.

---

## 3. Trust bootstrap (`GET /key`)

The client does not bake the server's Noise public key into the binary. It fetches the key at runtime over ordinary TLS:

```
GET /key?v=<capabilityVersion> HTTP/1.1
Host: <control-server>
```

* The `v` query parameter is the client's capability version. A server may require it (returning 400 if missing or non-numeric) and uses it to decide whether it still needs to return the legacy key.
* Only HTTP 200 is accepted; the response body is size-limited (64 KiB).

The response body is JSON of type `OverTLSPublicKeyResponse`:

```json
{
  "publicKey":       "mkey:<64 hex>",   // the server's Noise public key
  "legacyPublicKey": "mkey:<64 hex>"    // the server's legacy NaCl machine key; may be absent/zero
}
```

* `publicKey` is the server's **Noise** static public key — the responder identity the client will handshake against. Its wire form is the `mkey:<hex>` text encoding, **not** base64.
* `legacyPublicKey` is the server's older NaCl `crypto_box` machine key. It is zero/empty for new-enough clients and for servers that never had one. It is not used by the Noise transport, but it **is** the key the registration signature binds (§6.3), so a client that intends to sign caches it verbatim. An empty value is treated as the zero key on both sides. A coordination server with no pre-Noise history returns **only** `publicKey` and leaves `legacyPublicKey` zero; below its `/key` version floor such a server may return an empty `200` body with no key at all (§2).
* A pre-JSON control server that returns a raw key body is tolerated: the client parses it as the legacy key.

The client caches both keys in memory for the lifetime of the in-process control client and does **not** refetch on the hot path; the Noise key is version-invariant, so a stale cache is normally fine. A process restart triggers a fresh fetch.

---

## 4. Transport establishment

After the key fetch, the client opens the Noise tunnel over an HTTP upgrade on the same host.

### 4.1 The `/ts2021` HTTP upgrade

The client sends:

```
POST /ts2021 HTTP/1.1
Host: <control-server>
Upgrade: tailscale-control-protocol
Connection: upgrade
X-Tailscale-Handshake: <base64(noise initiation)>
```

The defining trick is the **deferred initiation**: the Noise IK initiation (message 1) is **not** written on the socket. It is built up front, base64-encoded (standard alphabet, padded), and carried in the `X-Tailscale-Handshake` **request header**, so it rides along with the protocol-switch request and saves a round trip.

The server reads the initiation from the header, replies:

```
HTTP/1.1 101 Switching Protocols
Upgrade: tailscale-control-protocol
Connection: upgrade
```

and hijacks the underlying TCP socket. It then completes the handshake as the Noise **responder**, writing the 51-byte Noise response (message 2) as the first post-101 bytes on the raw stream. Only message 2 and everything after it travel on the socket; message 1 was consumed from the request header. The client validates that the status is 101 and the `Upgrade` header echoes `tailscale-control-protocol`.

A WebSocket fallback exists for clients that cannot hijack raw TCP (browser / wasm): the same handshake value is passed as a query/form parameter, the `tailscale-control-protocol` subprotocol is negotiated, compression is disabled, and the identical Noise + HTTP/2 byte stream runs inside binary WebSocket messages.

### 4.2 Port selection

The client prefers **plaintext port 80** and falls back to **HTTPS port 443**:

* Two candidate URLs are formed: `http://host:80/ts2021` (preferred) and `https://host:443/ts2021` (fallback).
* Port 80 is preferred because the Noise layer already provides confidentiality and authentication; TLS on 443 only adds redundant encryption and server CPU cost.
* The port-80 dial starts first; a backup timer fires the port-443 dial after **500 ms** if port 80 has neither succeeded nor failed. An outright port-80 failure triggers the 443 dial immediately. First successful connection wins; the loser is cancelled.
* Certain conditions force 443-only (an environment override, or a health signal that a recent port-80 dial failed after the upgrade — a heuristic for middleboxes that mangle the post-upgrade byte stream).
* On the 443 fallback, **outer TLS certificate verification is intentionally demoted to a non-fatal warning.** The real security is the inner Noise layer, so a middlebox that MITMs the outer TLS is deliberately tolerated — the Noise handshake will still fail against anyone who does not hold the real server key.

HTTP/2 is disabled on the *outer* transport, because HTTP/2 cannot perform the 101 protocol switch the upgrade depends on.

> **Sidecar note.** The sidescale MITM dials the upstream control server per its `upstream_scheme` config (`auto`→https:443, `http`→plaintext:80, or a per-host `upstream_overrides` URL like `http://host:80`), so it can intercept plaintext control servers (e.g. a self-hosted coordination server with TLS disabled). It does **not** mirror the client's port-80-preferred *race* — transport selection is a deterministic config choice, so tests are reproducible.

### 4.3 EarlyNoise (server side-channel, pre-HTTP/2)

Immediately after the handshake completes and **before** the inner HTTP/2 session begins, the server MAY send one **EarlyNoise** payload over the encrypted tunnel. It is a way to push information to the client without an extra round trip (a stand-in for HTTP/2 server push, which Go's client API does not expose).

Framing — a 9-byte header, chosen to be exactly the size of an HTTP/2 frame header so the reader can peek 9 bytes and disambiguate:

```
+----------------------+---------------------------+------------------+
| magic (5B)           | length (4B, big-endian)   | JSON payload     |
| ff ff ff 54 53 ("TS")| uint32, ≤ 10 MiB           | EarlyNoise       |
+----------------------+---------------------------+------------------+
```

If the first 5 bytes are **not** the magic, there is no early payload: the 9 bytes are the start of the HTTP/2 stream and are pushed back into the reader. If the magic is present, the JSON payload is:

```json
{ "nodeKeyChallenge": "<challenge public key>" }
```

`nodeKeyChallenge` is a random per-connection public key used to let the client prove possession of its WireGuard node private key. The payload is optional; clients must tolerate its absence. Capability version 49 marks when clients began to understand EarlyNoise, but emitting the payload is a server-side decision: a server should only send one to a client new enough to parse it, and is otherwise free to send it to every client it admits. A server may also populate `nodeKeyChallenge` without ever verifying the client's response to it (one open-source coordination server does exactly this — challenge sent, proof unchecked), consistent with the register signature often going unverified (§6.3).

### 4.4 Inner transport

Once the handshake (and optional EarlyNoise) is done, both directions carry standard **HTTP/2 (RFC 7540)** inside the Noise tunnel over the same TCP connection. Because the outer bytes are already Noise-encrypted, the HTTP/2 stack is run in cleartext-h2 mode (it is unaware of the Noise crypto beneath it). A single connection is reused for all inner requests.

---

## 5. The Noise handshake

The control plane uses **`Noise_IK_25519_ChaChaPoly_BLAKE2s`** with a fresh Curve25519 ephemeral keypair per handshake. In the IK pattern the **initiator** (client) already knows the **responder**'s (server's) static public key — that is exactly what the `/key` fetch provided — and the responder authenticates the initiator's static key (its **machine key**) during the handshake.

### 5.1 Prologue and pre-messages

Before any message, the handshake hash is initialized from the protocol name and the following are mixed in, in order:

1. **Prologue** — the ASCII string `"Tailscale Control Protocol v"` followed by the decimal protocol version (e.g. `Tailscale Control Protocol v142`). This binds the cleartext version in the initiation header to the transcript.
2. **Responder static public key** (the IK `<- s` pre-message) — the server's Noise public key that the client learned from `/key`.

The message token sequences are the standard IK pattern:

```
-> e, es, s, ss      (initiation, message 1)
<- e, ee, se         (response, message 2)
```

### 5.2 Wire framing

Every Noise message begins with a 1-byte **type**; the initiation additionally prepends a 2-byte big-endian version. All length fields are **big-endian**.

| Message | Type | Total | Layout |
|---|---|---|---|
| Initiation (msg 1) | `0x01` | 101 B | `[2B BE version][1B type][2B BE len=96][32B client ephemeral pub][48B encrypted client machine static: 32B key + 16B tag][16B final tag]` |
| Response (msg 2) | `0x02` | 51 B | `[1B type][2B BE len=48][32B server ephemeral pub][16B final tag]` |
| Error | `0x03` | var | `[1B type][2B BE len][UTF-8 message]` — **unauthenticated, unencrypted** |
| Transport record | `0x04` | ≤ 4096 B | `[1B type][2B BE ciphertext-len][ciphertext]` (§5.4) |

In the **initiation**, the client ephemeral public key is cleartext; the client's static **machine** public key is encrypted (protected by the `es` DH), and the trailing 16-byte tag authenticates the whole message. In the **response**, the server ephemeral public key is cleartext and nothing else is transmitted — the server's static key was a pre-message the client already had, and the `ee`/`se` DH operations prove the server holds its private half. No static key is sent in message 2.

The **error** message (type `0x03`) is a plaintext, unauthenticated hint only; it can be forged or tampered with on the wire, so a receiver treats it as a diagnostic, not a trusted signal. Its length is capped (≤ 64 KiB) and servers deliberately avoid echoing attacker-controlled input back in it.

### 5.3 Session keys

On handshake completion the chaining key is split (HKDF-BLAKE2s) into two ChaCha20-Poly1305 AEAD states. The two directions use opposite states (client transmits with the first / receives with the second; the server mirrors), so each direction has an independent cipher. The final handshake hash is exposed as a channel-binding value that inner messages may reference.

### 5.4 Transport records and nonces

After the handshake, all bytes are carried in **transport records** (type `0x04`):

* Maximum full frame is **4096 bytes**; the 2-byte length gives the ciphertext length, which is the plaintext length plus the 16-byte Poly1305 tag. Maximum ciphertext is 4093 bytes, maximum plaintext **4077 bytes** per record.
* A larger inner HTTP/2 frame is split across multiple records. Zero-length-plaintext records are legal and must be preserved.
* The AEAD **nonce is 12 bytes**: the first 4 bytes are always zero and the low 8 bytes are a **big-endian uint64 counter** starting at 0, incremented once per record, independently per direction. (Note this differs from the little-endian nonce used by standard Noise and WireGuard.) The per-direction counter starts at 0 only once the session keys are derived; the AEADs used *during* the handshake (encrypting the static key and message tags in messages 1–2) use a fixed **all-zero** 12-byte nonce and are separate from this transport counter.
* **There is no rekey.** Each direction counts up until the counter is exhausted (the all-ones value is a sentinel for "invalid"), at which point the cipher is destroyed and the connection becomes permanently unusable. In practice the connection is torn down long before this.

---

## 6. Inner protocol (HTTP/2 over the tunnel)

Inside the tunnel the client speaks HTTP/2, issuing JSON `POST`s (one `PATCH`) to `/machine/*` endpoints. URLs are built from the server URL with the scheme forced to `https`. The two core endpoints:

### 6.1 `POST /machine/register`

* Request body: JSON `RegisterRequest` (machine key, node key, hostinfo, auth key or OAuth state, `Version`, optional signature, …).
* Response body: JSON `RegisterResponse` (whether the node is authorized, the assigned identity, any interactive-login URL, an error string, …). Most failures are folded into the response body's error field rather than surfaced as HTTP error codes; HTTP 429 signals rate limiting with a retry-after.

### 6.2 `POST /machine/map`

* Request body: JSON `MapRequest` (node key, endpoints, hostinfo, `Version`, …).
* **Streaming is requested by a boolean field in the request body** (`Stream: true`) — **not** by a query parameter. Compression is a separate, **opt-in** request field: the stock client sets `Compress: "zstd"`, but `Compress: ""` (or absent) is valid and yields **uncompressed** frames (§7). When `Stream` is false the server returns a single response; a "lite" variant (`Stream:false`, `OmitPeers:true`) is an endpoint-only update that returns an empty 200.
* Response: one or more `MapResponse` messages, framed as in §7. The streamed form is long-lived — the session stays open until either side tears it down. Keepalive is HTTP/2-layer (PING) plus periodic `MapResponse{KeepAlive:true}` frames; there is no Noise-layer keepalive. A client-side watchdog aborts the long poll if no frame arrives within a couple of minutes.

### 6.3 The registration signature

`RegisterRequest` may carry a signature, but signing is **optional** and only performed under an enterprise machine-certificate policy. With no such policy configured the request is sent unsigned (signature type "none"), which is the common case.

When the client does sign:

* **Algorithm:** RSA-PSS over SHA-256, with salt length equal to the hash length. Only RSA machine-certificate identities are supported. The full X.509 certificate chain (concatenated raw DER) is placed in the request's `DeviceCert` field so the server can validate it against its copy of the enterprise root.
* **Hash input (`SignatureV2`), concatenated in this exact order with no separators:**
  1. `Timestamp` — the request creation time, RFC 3339 in UTC.
  2. `ServerURL` — the control server identity.
  3. `DeviceCert` — the raw concatenated certificate chain bytes.
  4. The server's **legacy** machine public key (from `/key`'s `legacyPublicKey`, §3) — hashed as its `mkey:<hex>` text form; may be the zero key.
  5. The node's own machine public key — likewise `mkey:<hex>` text.
* `SignatureV1` (deprecated) uses the identical field order but an older, shorter key serialization. (The `SignatureType` enum orders as `none`, `unknown`, `v1`, `v2` — an unused `SignatureUnknown` sits between `none` and `v1`.)

Note the hash binds the **server legacy key** (not the Noise key) and the **machine key**, but **not** the node key — so mutating the node key does not invalidate the register signature. It is a per-machine, per-server, timestamped assertion; replaying it across a different tunnel (different machine key or server) requires re-signing.

Server-side verification is not universal: an open-source coordination server ignores the signature entirely and relies on the Noise-handshake machine-key authentication plus its own auth-key / interactive-login authorization. The production coordination server may enforce it.

### 6.4 Other `/machine/*` endpoints

The inner surface is generic HTTP/2 — any current or future `/machine/*` endpoint is just another request/response over the tunnel. Beyond `register` and `map`, common endpoints include:

* `POST /machine/set-dns` — publish ACME DNS-01 challenge TXT records.
* `PATCH /machine/set-device-attr` — device posture attributes.
* `POST /machine/audit-log` — client audit events.
* `POST /machine/update-health` — client health signal.
* `/machine/whoami`, `/machine/feature/query` — identity / feature lookups.
* `/machine/webclient/*` — web-client login flows.
* `/machine/tka/*` — tailnet-lock (network-lock) key-authority operations (`init/begin`, `init/finish`, `bootstrap`, `sync/offer`, `sync/send`, `sign`, `disable`, `affected-sigs`).

Each carries its own `Version` and node key. A given server may implement only a subset and stub the rest with HTTP 501.

---

## 7. MapResponse stream framing

Whether streamed or single-shot, each `MapResponse` message on `/machine/map` is framed identically:

```
+---------------------------+-----------------------------+
| length (4B, LITTLE-endian)| JSON body (zstd or raw)     |
+---------------------------+-----------------------------+
```

* The 4-byte length prefix is **little-endian** — distinct from every big-endian length in the Noise layer (§1).
* The body is a JSON `MapResponse`, **zstd-compressed only when `Compress:"zstd"` was requested** in the `MapRequest`. Compression is opt-in: with `Compress:""` the body is raw JSON under the same framing. The stock client always requests zstd and always assumes zstd on decode (it does not sniff the body or key off the field at read time), so a stock peer never emits an uncompressed stream — but the wire format permits one, and an interoperable reader should disambiguate on the zstd frame magic (`28 B5 2F FD`) rather than assume. The reader reads the length, then exactly that many body bytes, decompresses if compressed, and parses the JSON.
* In non-streaming mode the very first response uses the same framing, then the connection closes.
* Keepalives are sent as a `MapResponse{KeepAlive:true}` frame. The stock client recognizes them by byte-equality without decompressing, but the compared value is **learned per session** (the session's observed zstd encoding of `{"KeepAlive":true}`), not a fixed well-known constant.

The stream is stateful (incremental deltas over a shared session), so fragments must be delivered and consumed **in order**; there is no sequence number because ordering is intrinsic to the transport.

---

## 8. Key types

A Tailscale node uses three distinct Curve25519 keys, each 32 raw bytes, each text-encoded as a fixed prefix plus 64 lowercase hex characters:

| Key | Prefix | Purpose |
|---|---|---|
| Machine key | `mkey:` | Long-lived per-device identity. Authenticates the node to control; it is the initiator static key in the Noise handshake. The server's own machine key is what `/key` returns. |
| Node key | `nodekey:` | The WireGuard data-plane public key. Rotatable. Carried inside `RegisterRequest` (as `NodeKey` / `OldNodeKey`) and `MapRequest`. |
| Disco key | `discokey:` | Peer-to-peer path-discovery (NAT-traversal) key, advertised to control via hostinfo and used with NaCl seal/open between peers. |

The **machine key** is the identity the Noise tunnel binds; the **node key** and **disco key** are data-plane material that merely travel as fields inside the (encrypted) inner messages and carry no Noise-layer binding of their own.

---

## 9. Security properties and limits

* **Mutual authentication.** The Noise IK handshake binds both static keys into the transcript: the client proves possession of its machine key (sent encrypted in the initiation), and the server proves possession of the private half of the public key the client fetched from `/key`. Neither side can be impersonated without the corresponding private key.
* **Confidentiality and integrity.** Everything after the handshake is ChaCha20-Poly1305 AEAD with per-record big-endian counters. The inner HTTP/2 — registration, map, all configuration — is invisible and untamperable to any on-path observer of the outer transport.
* **Version binding.** The capability version is echoed in cleartext and mixed into the handshake prologue, so it cannot be downgraded in flight without breaking the MAC.
* **Registration signature is optional and not always enforced.** Absent an enterprise machine-cert policy, `RegisterRequest` is unsigned; authentication then rests entirely on the Noise machine-key binding and the server's own authorization (auth keys, interactive login). Some servers do not verify the signature at all.
* **Size limits.** `/key` response ≤ 64 KiB; Noise transport record ≤ 4096 bytes (≤ 4077 plaintext); EarlyNoise payload ≤ 10 MiB; Noise error message ≤ 64 KiB.

---

## 10. Layer summary

```
client                                             control server
  |  --- GET /key?v=<ver>  (plain TLS) --------------->  |
  |  <-- OverTLSPublicKeyResponse {publicKey,...} -----  |   learn server Noise key
  |                                                       |
  |  --- POST /ts2021  Upgrade: tailscale-control ---->  |
  |      X-Tailscale-Handshake: b64(Noise msg 1)          |   (deferred initiation)
  |  <-- 101 Switching Protocols ---------------------   |   hijack socket
  |  <-- Noise msg 2 (51B) on raw stream -------------   |   handshake complete
  |  <-- [EarlyNoise magic+len+JSON] (optional) ------   |   before HTTP/2
  |                                                       |
  |  ==================  Noise tunnel  ================   |   ChaCha20-Poly1305 records
  |  --- HTTP/2: POST /machine/register (JSON) ------->   |
  |  <-- RegisterResponse (JSON) ---------------------   |
  |  --- HTTP/2: POST /machine/map {Stream, zstd} ---->   |
  |  <-- [LE-len | zstd JSON MapResponse] * N --------   |   long-lived stream
```

