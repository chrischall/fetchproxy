# fetchproxy 0.1.0 — Concentrator + E2E Encryption

**Status:** Approved 2026-05-21. Implementation begins immediately.

## Goal

Allow N MCP servers to share one WebSocket port (127.0.0.1:37149) with end-to-end encryption between each peer MCP and the extension, so a host MCP acting as a multiplexer cannot read or modify peer traffic.

## What this replaces

The current model (Phase 1, shipped as 0.0.3) is **port-per-MCP**: each MCP runs its own `@fetchproxy/server` listener on its own port. The extension dials each one. Trust is keyed off `(port, server-name, domain)`.

0.1.0 collapses all MCPs onto one port. The first MCP to start wins the `bind()` and becomes the **host** (a concentrator, not a daemon — its lifetime is its parent MCP's). Subsequent MCPs detect `EADDRINUSE` and connect to the host as **peer clients**. The host multiplexes frames between peers and the single extension WS.

The host is in the data path, so we add end-to-end encryption between each peer and the extension. The host forwards opaque ciphertext.

## Architecture

```
                     ┌─────────────────────────┐
                     │ Extension (one WS)      │
                     └────────────┬────────────┘
                                  │ ws://127.0.0.1:37149
                                  │
                      ┌───────────▼───────────┐
                      │ MCP A (won bind)      │
                      │   ├ runs WS server    │
                      │   ├ owns its peer WS  │
                      │   └ multiplexes peers │
                      └──┬─────────────────▲──┘
                         │ local WS        │ local WS
                ┌────────▼──┐         ┌────┴──────┐
                │ MCP B     │         │ MCP C     │
                │ (dialed)  │         │ (dialed)  │
                └───────────┘         └───────────┘
```

### Election

Every MCP runs the same logic in `@fetchproxy/server`:

```
try   bind(127.0.0.1:37149) → host role
catch EADDRINUSE             → dial(127.0.0.1:37149) → peer role
```

No election protocol, no coordinator service. TCP `bind()` is the lock. When the host exits, peers see WS close and re-race. One wins, others reconnect as peers to the new host.

### Multiplexing

Every frame after `hello` carries an `mcpId` field. The host maintains `Map<mcpId, WebSocket>` (one per peer + one self-entry). The extension WS is logically a single pipe — frames are tagged by `mcpId` so the extension knows which session they belong to.

Host routing rule:
- Frame inbound on extension WS with `mcpId: X` → forward to peer WS for X (or process locally if X is the host's own id).
- Frame inbound on peer WS → forward to extension WS, preserving `mcpId`.

The host never decrypts frames it forwards. It can only see `type`, `mcpId`, and (for encrypted frames) the ciphertext blob.

## mcpId format

`<server-name>:<version>:<rand>`

- `<server-name>` — npm package name, e.g., `opentable-mcp`. ASCII, no colons.
- `<version>` — semver string from package.json, e.g., `0.9.1`.
- `<rand>` — 16 random hex chars, generated per process start (`crypto.randomBytes(8).toString('hex')`).

Example: `opentable-mcp:0.9.1:a3f7c91d2e8b4f56`

Properties:
- Globally unique with high probability (1 in 2⁶⁴ collision per server-name).
- Carries identity (server-name) and version for routing/display.
- Per-process — same MCP restarting gets a fresh `mcpId`, so stale routing state expires naturally.

## Cryptographic design

### Identity keys

Each MCP holds a **long-term identity keypair** stored at:

```
~/.fetchproxy/identity/<server-name>.json   (mode 0600)
```

File contents:

```json
{
  "x25519Priv": "<base64 32 bytes>",
  "x25519Pub": "<base64 32 bytes>",
  "ed25519Priv": "<base64 32 bytes>",
  "ed25519Pub": "<base64 32 bytes>",
  "createdAt": 1716250000000
}
```

The X25519 pair is for ECDH key agreement. The Ed25519 pair signs ephemeral session data to prevent replay across sessions.

Generated on first run. Re-used on every subsequent run. Deletion forces a re-pair.

The extension does **not** persist an identity keypair in 0.1.0. It generates a fresh ephemeral X25519 keypair per connection, sends the public key in the `ready` frame, and uses the private key only to derive the session key via ECDH. (Future versions may add a persistent extension identity to authenticate the extension to MCPs; not needed for the localhost trust model.)

### Pair code (SAS — Short Authentication String)

Derived from the MCP's identity X25519 public key:

```
pairCode = SHA256(identityX25519Pub).slice(0, 4 bytes) → mod 1_000_000 → format "XXX-XXX"
```

Deterministic per identity. The same MCP shows the same pair code every time. The user can verify "this is still my opentable-mcp" by code stability.

Collision space: ~1M. Birthday collisions among installed MCPs are negligible (you'd need ~1000 paired MCPs to hit a ~50/50 chance, and we expect users to have <10).

### Pairing flow

First connection from an unknown `mcpId`:

1. MCP sends `hello` with `identityX25519Pub`, `identityEd25519Pub`, `mcpId`, `serverName`, `version`, `domain`, `sessionNonce` (32 random bytes), `sessionSig: Ed25519Sign(identityEd25519Priv, mcpId || sessionNonce)`.
2. Host forwards `hello` to extension verbatim.
3. Extension computes `pairCode = SHA256(identityX25519Pub) → 6 digits`.
4. Extension shows popup: server-name, version, domain, **pair code prefilled**, [Cancel] [Approve] buttons.
5. User reads pair code from MCP's stderr (or `~/.fetchproxy/pending/<server-name>.txt`), confirms popup matches, clicks Approve.
6. Extension stores trust record (see below), generates an ephemeral X25519 keypair, computes `shared = ECDH(extEphemeralPriv, mcpIdentityX25519Pub)`, derives `sessionKey = HKDF-SHA256(shared, salt=sessionNonce, info="fetchproxy/0.1.0/session", 32)`, sends `ready` frame with the ephemeral public key as `extensionSessionPub`.
7. MCP receives `ready`, computes `shared = ECDH(mcpIdentityX25519Priv, extEphemeralPub)`, derives the same `sessionKey` via the same HKDF (ECDH is symmetric).

Subsequent connections from a known `mcpId`:

1. Same `hello`.
2. Extension recognizes `identityX25519Pub`, verifies `sessionSig` against `identityEd25519Pub`.
3. Skip pair-code prompt. Generate `extensionSessionPub`, send `ready`, derive `sessionKey`.

### Encrypted frames

All frames after `ready` are encrypted:

```jsonc
{
  "type": "frame",
  "mcpId": "opentable-mcp:0.9.1:a3f7c91d2e8b4f56",
  "seq": 1,
  "iv": "<base64 12 bytes>",
  "ciphertext": "<base64 — AES-256-GCM(sessionKey, iv, innerFrame)>"
}
```

`innerFrame` is the JSON-encoded original frame (`request` / `response` / `ping` / `pong`).

The host sees `type`, `mcpId`, `seq`, `iv`, `ciphertext` — and routes by `mcpId`. The host cannot decrypt or modify ciphertext without detection (AES-GCM is authenticated).

### Replay protection

`seq` is monotonic per direction per session. The extension tracks `lastSeqPerMcpId` and rejects frames with `seq <= last`. Servers track the same for extension → server frames. Out-of-band frames (host forwarding) preserve order because WS is ordered.

### Trust storage (extension)

`chrome.storage.local`, key `trustedMcps`:

```json
{
  "<sha256-hex(identityX25519Pub)>": {
    "serverName": "opentable-mcp",
    "domain": "opentable.com",
    "identityX25519Pub": "<base64>",
    "identityEd25519Pub": "<base64>",
    "pairedAt": 1716250000000,
    "extensionVersionAtPair": "0.1.0"
  }
}
```

Trust is keyed by identity public-key hash (not server-name) — so a malicious server with the same `serverName` but a different identity key fails the lookup and triggers a re-pair prompt.

`serverName` and `domain` are stored for display + allowlist enforcement.

## What this closes from SECURITY.md

- **T1 / T4 / T8 (MCP impersonation):** identity key is a stable cryptographic anchor. Trust binds to the keypair, not the port or process. A malicious process spoofing server-name fails verification.
- **Open Q1 (shared-secret token):** answered. We use identity keys + signed session data instead of a static shared secret.
- **Open Q3 (trust scope):** answered. Trust is `(identityX25519Pub, serverName, domain)`. The port goes away as a trust dimension.

## What this does NOT close

- **Forward secrecy** — identity keys serve double-duty (long-term identity AND ECDH endpoint). Compromise of the identity key file lets attacker decrypt past traffic captured by the host. Acceptable trade-off for localhost trust; if attacker has filesystem read on your account, they have worse problems.
- **DoS by host** — host can drop or delay peer frames. Detectable (request timeouts), not preventable.
- **Compromised MCP itself** — host or peer, if the MCP code is malicious, it knows its own identity key and can use its own domain allowlist freely. Per-domain allowlist (existing T3 defense) still applies.

## Out of scope for 0.1.0

- Per-session ephemeral identity keys (PFS).
- Cross-machine sync of trusted MCPs.
- Daemon-mode alternative.
- Linux/Windows installer changes.
- UI for re-pairing or revoking trust (popup will surface trusted MCPs in a later release).
- Migration UX for users on 0.0.3 — extension just re-prompts; old port-based trust records are discarded.

## Backwards compatibility

**None.** 0.1.0 is a clean cut. Hello frames change shape, transport multiplexes, trust storage schema changes. The extension on 0.1.0 refuses to talk to 0.0.x servers (no encryption capability), and vice versa.

Mitigation: bump `@fetchproxy/server` peer-dep range in `opentable-mcp` to `^0.1.0` so the upgrade is forced atomically.

## File structure

### New (`packages/protocol`)

- `src/crypto.ts` — Web Crypto wrappers: ECDH X25519, Ed25519 sign/verify, HKDF-SHA256, AES-256-GCM seal/open, SHA-256.
- `src/pair-code.ts` — derive pair code from identityX25519Pub; format `XXX-XXX`.
- `src/mcp-id.ts` — generate `<serverName>:<version>:<rand>`; parse + validate.

### Modified (`packages/protocol`)

- `src/frames.ts` — add `HelloFrameV2`, `ReadyFrameV2`, `EncryptedFrame`; keep `FetchRequest`/`FetchResponse` as the *inner* frame types.
- `src/validate.ts` — validators for new frame types.
- `src/index.ts` — exports.

### New (`packages/server`)

- `src/identity.ts` — load/generate identity keypair from `~/.fetchproxy/identity/<server-name>.json`.
- `src/election.ts` — bind-or-dial logic; reports `host` | `peer`.
- `src/host.ts` — concentrator: WS server + multiplexer + extension-WS routing.
- `src/peer.ts` — peer-client: dial host, encrypted-frame send/receive.
- `src/session.ts` — per-peer session state (sessionKey, last seqs, pending requests).

### Modified (`packages/server`)

- `src/ws-server.ts` — collapse into a thin orchestrator that calls election → host or peer. Most logic moves to host.ts/peer.ts.
- `src/index.ts` — public API: `FetchproxyServer` still works; internally branches on role.

### New (`packages/extension-core`)

- `src/session-keys.ts` — `Map<mcpId, { sessionKey, lastInboundSeq, outboundSeq }>`.

(No persistent extension identity in 0.1.0. The extension generates an ephemeral X25519 keypair per connection — the MCP's `sessionNonce` provides freshness through HKDF salt. `@fetchproxy/protocol`'s `crypto.ts` works in both Node 22 and MV3 service workers via Web Crypto API.)

### Modified (`packages/extension-core`)

- `src/background.ts` — multiplexed routing; per-mcpId session state; one WS to host.
- `src/popup/popup.ts` — pair-code-prefilled prompt UI; show all trusted MCPs.
- `src/trust-store.ts` — re-key from `(port, server, domain)` to `(identityHash, server, domain)`; major-version invalidation now uses `extensionVersionAtPair`.

### Modified (`opentable-mcp`)

- `package.json` — bump `@fetchproxy/server` to `^0.1.0`.
- `src/transport-fetchproxy.ts` — likely no changes if `FetchproxyServer`'s public API is stable.

## Versioning

- `@fetchproxy/protocol` → 0.1.0
- `@fetchproxy/server` → 0.1.0
- `fetchproxy-extension` (Chrome MV3) → 0.1.0
- `opentable-mcp` → 0.10.0 (minor bump to signal the protocol break)
