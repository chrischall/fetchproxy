# fetchproxy protocol (v1, ships with 0.2.0+)

The wire format between MCP servers and the browser extension. JSON-over-WebSocket. Three top-level frame types; all data frames after the handshake are AES-256-GCM encrypted end-to-end between each MCP and the extension.

`PROTOCOL_VERSION` is `3`. The `hello` frame carries it explicitly; mismatches are rejected.

**0.2.0 is wire-incompatible with 0.1.x.** The server hello now carries `domains: string[]` instead of `domain: string` — a single-domain MCP just sends a 1-element array; a multi-domain MCP (e.g. HoneyBook, which spans two hosts) sends multiple. Trust records, popup state, and the per-request allowlist all key off the full set.

0.2.0 also adds `capabilities: string[]` to the server hello and discriminates inner request/response frames by `op`. Existing fetch-only MCPs need no changes — `capabilities` is optional on the wire and defaults to `['fetch']` — but new verbs like `read_cookies` are opt-in and forced through the pair flow.

## Big picture

```
                     ┌─────────────────────────┐
                     │ Extension (one WS)      │
                     └────────────┬────────────┘
                                  │ ws://127.0.0.1:37149
                                  │
                      ┌───────────▼───────────┐
                      │ MCP A (won the bind)  │
                      │   ├ WS server         │
                      │   ├ multiplexer       │
                      │   └ own MCP traffic   │
                      └──┬─────────────────▲──┘
                         │ local WS        │ local WS
                ┌────────▼──┐         ┌────┴──────┐
                │ MCP B     │         │ MCP C     │
                │ (peer)    │         │ (peer)    │
                └───────────┘         └───────────┘
```

Every MCP runs the same election: try `bind(127.0.0.1:37149)`. On success it is the **host** (concentrator). On `EADDRINUSE` it dials the existing host as a **peer**. The host forwards frames between peers and the single extension WS.

Frames after the handshake are encrypted with a per-MCP session key the host never sees. The host can route (it sees `mcpId`, `seq`, `iv`, opaque `ciphertext`), but it cannot read or modify peer traffic.

## mcpId

Every MCP identifies itself with a per-process id of the form `<server-name>:<version>:<rand>` where `rand` is 16 lowercase hex chars. Examples:

```
opentable-mcp:0.10.0:a3f7c91d2e8b4f56
resy-mcp:0.0.4:b2d8e7c91a4f6e58
```

Per-process — same MCP restarting gets a fresh `mcpId`, so stale routing state expires naturally.

## Connection lifecycle

```
Extension                            Host MCP                       Peer MCP
   │                                    │                              │
   │ WS open ws://127.0.0.1:37149       │                              │
   │ ─────────────────────────────────▶ │                              │
   │                                    │                              │
   │                                    │ ◀────── WS open (local) ──── │
   │                                    │ ◀────── hello (peer) ────────│
   │ ◀──── hello (peer, forwarded) ─────│                              │
   │ ◀──── hello (host's own MCP) ──────│                              │
   │                                    │                              │
   │ (verify sessionSig, look up trust)                                │
   │ (if unknown identity → popup,                                     │
   │  user verifies pair code)                                         │
   │                                    │                              │
   │ ready { mcpId, extensionSessionPub }                              │
   │ ─────────────────────────────────▶ │                              │
   │                                    │ ──── ready (forwarded) ────▶ │
   │                                    │                              │
   │ (each side computes shared = ECDH; sessionKey = HKDF(...))        │
   │                                                                   │
   │ frame { mcpId, seq, iv, ciphertext } — AES-GCM, opaque to host    │
   │ ─────────────────────────────────▶ │ ──── forwarded verbatim ───▶ │
   │                                    │                              │
   │ ◀──────────── frame ───────────────│ ◀──────── frame ─────────────│
```

## Frame types

All frames are JSON objects with a `type` discriminator. Unknown `type` closes the WS with code `1002`. Defensive validators reject:

- Non-plain objects, non-default prototypes, `__proto__`/`constructor`/`prototype` keys
- Non-base64 strings in identity / nonce / signature / iv / ciphertext fields
- Non-positive integers for `seq`
- Invalid `mcpId` format
- Non-`http(s)` URLs in inner request fields
- Empty, non-array, or malformed-hostname `domains` in the server hello
- Empty, non-array, non-string, or unknown-value `capabilities` in the server hello
- Inner requests/responses with unknown `op`

### Top-level frames (in plaintext on the wire)

#### `hello` (server → host → extension)

Each MCP sends one of these as the very first frame after connecting.

```jsonc
{
  "type": "hello",
  "protocolVersion": 1,
  "role": "server",
  "mcpId": "opentable-mcp:0.10.0:a3f7c91d2e8b4f56",
  "serverName": "opentable-mcp",
  "version": "0.10.0",
  "domains": ["opentable.com"],
  "capabilities": ["fetch"],          // optional — defaults to ["fetch"]
  "identityX25519Pub": "<base64 raw 32B>",
  "identityEd25519Pub": "<base64 raw 32B>",
  "sessionNonce": "<base64 random ≥16B, fresh per connection>",
  "sessionSig": "<base64 Ed25519Sign(identityEd25519Priv, mcpId || sessionNonce)>"
}
```

`domains` is a non-empty array of hostnames the MCP is allowed to reach. Each entry must be a valid DNS hostname (≥2 labels, alphanumeric + hyphen, no leading/trailing hyphen). The extension allows a fetch iff its URL host matches one of these entries exactly OR is a subdomain of one of them. Most MCPs send one entry (`["opentable.com"]`); MCPs that legitimately span multiple hosts send all of them (`["honeybook.com", "hbsplit.com"]`).

`capabilities` is an optional non-empty array of inner-verb capability strings the MCP wants the extension to expose. Known values:

- `"fetch"` — issue HTTP requests against the user's signed-in tab. Default; if `capabilities` is omitted, the extension treats it as `["fetch"]`.
- `"read_cookies"` — read non-HttpOnly `document.cookie` from a matching tab. Strictly opt-in; the popup shows a visible warning so the user notices the elevated trust.
- `"graphql"` — invoke a declared GraphQL operation through the matched tab's OWN Apollo client (`window.__APOLLO_CLIENT__`) in the page MAIN world, reusing the live `DocumentNode` the page already observed for the declared `operationName`. This runs the exact code path the page itself uses, so it carries whatever per-request bot-telemetry the page's Apollo link injects — clearing edge bot-protection (e.g. Akamai) that the isolated-world `fetch` path cannot. The MCP declares an allowlist of operations in `graphqlOps` (see below); a per-call request references one by `name` and supplies its own `variables`. Strictly opt-in; elevated; the popup shows the declared operations verbatim. It does NOT add arbitrary page-JS execution — only the declared operations, through the page's own client, are reachable.

Unknown values are rejected at validation time. The trust record stores the approved capability set; if the same MCP later declares a different set (upgrade or downgrade), the extension treats it as a re-pair and prompts the user again. The check is order-insensitive — `["fetch", "read_cookies"]` and `["read_cookies", "fetch"]` are equivalent.

`graphqlOps` is an optional array declared alongside `capabilities` — required (non-empty) for the `'graphql'` capability to do anything; empty/absent means no GraphQL operations are permitted even when `'graphql'` is declared:

```jsonc
"graphqlOps": [
  { "name": "restaurantsAvailability", "operationName": "RestaurantsAvailability" }
]
```

Each entry is `{ name, operationName }`:

- `name` — the logical handle the MCP references per-call (`GraphqlQueryInit.name`). `[A-Za-z0-9_.\-]`, 1-256 chars, unique within `graphqlOps`.
- `operationName` — the GraphQL operation name whose live `DocumentNode` the page's Apollo client already owns (standard GraphQL `Name` grammar, `[_A-Za-z][_0-9A-Za-z]*`, ≤128 chars). The extension carries no query text or hash of its own — it resolves `name` → `operationName` → the DocumentNode captured off the page's own `client.link.request`, so it auto-adapts when the site revises the query.

`graphqlOps` is approved at pair time (the popup lists every declared `operationName` verbatim) and diffed on change like every other declared scope — widening or altering the set forces a re-pair.

The signature lets the extension prove the connecting process holds the Ed25519 private key. Re-pair only happens on first sight of a new identity key; subsequent sessions just verify the signature against the stored `identityEd25519Pub`. The trust record also stores the approved `domains` set — a server that later widens the set (or changes `serverName`) is refused auto-trust and falls back to a re-pair prompt.

#### `hello` (extension → host)

The extension's hello carries no crypto material — its identity is "the only WS client allowed to connect."

```jsonc
{
  "type": "hello",
  "protocolVersion": 1,
  "role": "extension",
  "platform": "chrome" | "safari" | "firefox",
  "extensionId": "fetchproxy",
  "version": "0.1.0"
}
```

**Only one extension is active at a time.** A second extension that connects is closed with `1008 "extension already connected"`.

**1.12.0+: the host relays this frame to every peer**, and to a peer that joins later. A peer has to authenticate the extension behind the concentrator before deriving a session key from a `ready` the concentrator handed it (see below), and the identity + nonce in this hello are the only material that lets it. Peers before 1.12.0 ignore the frame; hosts before 1.12.0 never send it, so a 1.12.0 peer behind an older host warns and proceeds unless `requireExtensionIdentity` is set.

**1.12.0+: the MCP pins this identity.** The first extension to complete a handshake is recorded at `~/.fetchproxy/identity/<server-name>.extension-trust.json`, and a later hello carrying a different `identityX25519Pub`/`identityEd25519Pub` is refused with `1008` before any session exists — the mirror of the extension's own `trustedMcps`. The pin is written only after the `ready` signature verifies, so claiming an identity is never enough to become the pinned one. `fpx trust list` / `fpx trust clear <server-name>` and `FETCHPROXY_TRUST_NEW_EXTENSION=1` are the deliberate ways out; see `docs/SECURITY.md` §T-fake-extension.

#### `ready` (extension → host → server)

The signature binds both endpoints' nonces, and **both the host and (1.12.0+) peers verify it** before deriving a session key. That proves the extension on the other end is the one whose hello arrived — it cannot be produced without the extension's Ed25519 private key.

**2.0.0+: it binds `extensionSessionPub` too.** The payload is
`mcpHelloNonce || extHelloNonce || extensionSessionPub` (`readySignaturePayload()` in `@fetchproxy/protocol`). Under v2 the ephemeral key was unsigned, so a relay forwarding genuine frames could substitute its own and derive the same session key; signing it is what makes the session private against something already in the middle. `PROTOCOL_VERSION` is 3 and v2 is refused at the hello — there is deliberately no negotiated downgrade, because a relay that can rewrite frames could choose it.

After the user approves a new pair (or auto-trust hits for a known identity), the extension generates an ephemeral X25519 keypair, computes the session key, and sends:

```jsonc
{
  "type": "ready",
  "mcpId": "opentable-mcp:0.10.0:a3f7c91d2e8b4f56",
  "extensionSessionPub": "<base64 raw 32B>"
}
```

#### `frame` (encrypted, either direction)

After `ready`, every data frame is encrypted:

```jsonc
{
  "type": "frame",
  "mcpId": "opentable-mcp:0.10.0:a3f7c91d2e8b4f56",
  "seq": 1,                       // monotonic per direction, starts at 1
  "iv": "<base64 raw 12B, fresh per frame>",
  "ciphertext": "<base64 — AES-256-GCM(sessionKey, iv, innerFrameJson)>"
}
```

`ciphertext` includes the 16-byte GCM tag. The host routes by `mcpId` and never decrypts.

Replay protection: the receiving side rejects any `seq <= lastInbound` (per direction, per session). WS guarantees ordering, so gaps from out-of-order arrival are not a concern.

### Inner frames (inside ciphertext)

The JSON payload inside `frame.ciphertext` is one of:

#### `ping` / `pong`

Keepalive. Either side sends `ping` every ~20s; the other answers `pong`. Keeps MV3 service workers warm.

```jsonc
{ "type": "ping" }
{ "type": "pong" }
```

#### `request` (server → extension)

Inner requests are discriminated by `op`. v1 defines two verbs: `fetch` (always available, the default) and `read_cookies` (opt-in via `capabilities`). The extension rejects any request whose `op` was not declared in the MCP's hello.

##### `op: "fetch"`

The extension issues `window.fetch(url, ...)` from a tab matching `tabUrl`.

```jsonc
{
  "type": "request",
  "id": 1,                                 // server-generated, monotonic per session
  "op": "fetch",
  "init": {
    "url": "https://www.opentable.com/user/dining-dashboard",
    "method": "GET",                       // any HTTP verb the browser fetch supports
    "headers": {
      "Content-Type": "application/json",
      "x-csrf-token": "..."                // auto-injected from window.__CSRF_TOKEN__
    },
    "body": "{\"x\":1}",                   // optional; string only
    "tabUrl": "https://www.opentable.com/" // prefix-matched against open tabs
  }
}
```

Semantics:

- `url`: absolute. Must match one of the MCP's declared `domains` (or a subdomain of one of them) — the extension enforces a per-MCP allowlist; cross-domain fetches return `ok: false`.
- `method`: any HTTP verb. `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, etc.
- `headers`: optional. `Cookie`, `User-Agent`, `Origin`, `Referer` are controlled by the browser and ignored if set here. `credentials: 'include'` is always implied.
- `body`: optional string. The caller serialises JSON.
- `tabUrl`: required. Prefix-matched against `chrome.tabs.query({})`. First match wins. If no match, the response is `ok: false`. After a successful pair, the extension proactively opens `https://${domains[0]}/` if no matching tab is open. (Future: open a tab for every declared domain.)
- `inPage`: optional boolean, default `false`. When `true` the request is issued by the page's MAIN world instead of the content script's isolated world — same URL, method, body, injected CSRF header and cookies; only the calling world differs. Requires the `fetch_in_page` capability: the background rejects `inPage: true` from an MCP that didn't declare it, before the request reaches any tab. Must be a real boolean — a non-boolean is a protocol error, never coerced.

  Use it only where the isolated world genuinely fails. Some edge bot-managers accept a request from the page and reject the byte-identical one from the isolated world: on opentable.com a GraphQL **mutation** POST 403s from the isolated world and returns 200 from the page, while GraphQL queries and REST writes pass from either. The cost is that page script can see and patch `window.fetch`, so a flagged request loses the isolated world's tamper resistance — see `T-in-page-fetch` in [SECURITY.md](./SECURITY.md). Flag individual calls, never everything.

**Body size caps:** request body ≤ 1 MB, response body ≤ 5 MB. Larger bodies are rejected with `ok: false` — including on the `inPage` path, which re-checks the response cap in the content script before the body leaves it.

##### `op: "read_cookies"`

The extension returns `document.cookie` from a tab matching `tabUrl`. Only non-HttpOnly cookies are visible to page JS — that's the intentional security model.

```jsonc
{
  "type": "request",
  "id": 2,
  "op": "read_cookies",
  "init": {
    "tabUrl": "https://www.creditkarma.com/" // prefix-matched, same as fetch
  }
}
```

Semantics:

- `tabUrl`: required. Same matching rules as `fetch`; must also map to one of the MCP's declared `domains` (or a subdomain of one). No other `init` fields are permitted.
- The MCP must have declared `"read_cookies"` in its hello `capabilities` AND the user must have approved that set at pair time. Otherwise the response is `{ok: false, op: "read_cookies", error: "capability ... not granted ..."}`.

##### `op: "graphql_query"`

The extension invokes a declared GraphQL operation through the matched tab's OWN `window.__APOLLO_CLIENT__`, in the page MAIN world, using the live `DocumentNode` the page's client already captured for that operation.

```jsonc
{
  "type": "request",
  "id": 3,
  "op": "graphql_query",
  "init": {
    "name": "restaurantsAvailability",       // must match a declared graphqlOps[].name
    "variables": {                            // the MCP's full GraphQL variables object
      "restaurantIds": ["1175428"],
      "date": "2026-07-31",
      "time": "17:00",
      "partySize": 2,
      "databaseRegion": "NA"
    },
    "tabUrl": "https://www.opentable.com/"   // optional; same matching as fetch/read_cookies
  }
}
```

Semantics:

- `name`: required, non-empty string. Must match a `name` in the MCP's declared `graphqlOps`. The extension resolves `name` → `operationName` → the cached `DocumentNode`, then calls `client.query({ query, variables, fetchPolicy: 'no-cache' })`.
- `variables`: required. A plain (non-array, non-null) object passed straight through to `client.query`; may be empty. The extension does not inspect or transform it.
- `tabUrl`: optional. Same host-or-subdomain matching as other verbs; must map to one of the MCP's declared `domains`. Omitted ⇒ the extension picks a tab on the MCP's declared domain.
- The MCP must have declared `"graphql"` in its hello `capabilities` AND the specific `name` must be one of the declared `graphqlOps` — both gates are checked on every call, not just at pair time.
- If the page's Apollo client has not yet observed the declared `operationName` (its `DocumentNode` isn't cached — e.g. the user hasn't loaded the relevant page in this tab), the response is a typed failure: `{ok: false, op: "graphql_query", error: "operation not yet observed on this tab — open <hint> and retry"}` (exact wording may vary).
- That miss is per-tab, so it does not end the search: the extension walks **every** matching tab and returns the first one whose Apollo client owns the operation. Only when no matching tab has observed it is the miss returned to the MCP. Before 2.3.3 the walk stopped at the first tab that answered at all, so a single stale same-origin tab (a dashboard, a confirmation page) could shadow the tab that had the operation on every call — reloading the right page never helped, because that page was never asked.

Response:

```jsonc
// Success
{
  "type": "response",
  "id": 3,
  "ok": true,
  "op": "graphql_query",
  "data": { "availability": [ /* ... */ ] }   // the GraphQL response's `data` object, verbatim
}
```

`data` is exactly the `data` field of the GraphQL response the page's own Apollo client received — no envelope, no `errors` passthrough (a GraphQL-level error surfaces as an `ok: false` protocol failure instead). The MCP reads whatever fields its declared operation returns.

#### `response` (extension → server)

Successful responses carry an `op` discriminator that matches the request. Existing 0.1.x senders that omit `op` are still accepted by the validator for the fetch shape (back-compat) — but new senders always set it.

```jsonc
// Success — fetch outcome
{
  "type": "response",
  "id": 1,
  "ok": true,
  "op": "fetch",
  "status": 200,
  "url": "https://www.opentable.com/user/dining-dashboard",
  "body": "<html>..."
}

// Success — read_cookies outcome
{
  "type": "response",
  "id": 2,
  "ok": true,
  "op": "read_cookies",
  "cookies": "sid=abc; csrf=xyz"
}

// Protocol-level failure (no tab, content-script not injected, fetch threw,
// capability not granted)
{
  "type": "response",
  "id": 1,
  "ok": false,
  "op": "fetch",                          // op echo; omitted on legacy transport-level errors
  "error": "no tab matching https://www.opentable.com/"
}
```

`ok: false` is reserved for protocol-level failures. HTTP-level errors (404, 500, 403) come back as `ok: true, op: "fetch"` with the relevant `status`. Callers handle non-2xx themselves.

## Cryptographic handshake

### Identity keys (persistent)

Each MCP holds a long-term keypair stored at `~/.fetchproxy/identity/<server-name>.json`, mode `0600`:

```json
{
  "x25519Priv": "<base64>",
  "x25519Pub": "<base64>",
  "ed25519Priv": "<base64>",
  "ed25519Pub": "<base64>",
  "createdAt": 1716250000000
}
```

- X25519 keypair → ECDH for session-key agreement.
- Ed25519 keypair → signs `mcpId || sessionNonce` so the extension can prove freshness per connection.

The extension does **not** persist a long-term identity in 0.2.x. It generates an ephemeral X25519 keypair per connection, so the session key is fresh every time even when the same MCP identity reconnects.

### Pair code (SAS)

Derived deterministically from the MCP's X25519 public key:

```
pairCode = SHA256(identityX25519Pub)[0..3]
           interpreted as big-endian uint32
           mod 1_000_000
           formatted "XXX-XXX"
```

Same code every time for the same identity. The MCP prints it to stderr at startup. The extension shows the same code in the pair popup. The user compares the two and clicks Approve — that is the SAS verification.

### Session key derivation

After the extension sends its `ready` frame:

```
shared     = X25519(extEphemeralPriv, identityX25519Pub)
           = X25519(identityX25519Priv, extEphemeralPub)   (symmetric)
sessionKey = HKDF-SHA256(
               IKM  = shared,
               salt = sessionNonce,
               info = "fetchproxy/0.1.0/session",
               L    = 32
             )
```

Both sides derive the same key without sending it on the wire. `sessionNonce` is fresh per connection, so reconnecting the same MCP gives a different `sessionKey`.

### Trust store (extension)

`chrome.storage.local["trustedMcps"]`:

```json
{
  "<hex(sha256(identityX25519Pub))>": {
    "serverName": "opentable-mcp",
    "domains": ["opentable.com"],
    "capabilities": ["fetch"],
    "identityX25519Pub": "<base64>",
    "identityEd25519Pub": "<base64>",
    "pairedAt": 1716250000000,
    "extensionVersionAtPair": "0.2.0"
  }
}
```

Keyed by identity hash, not port. Trust survives port changes, restarts, and MCP package renames as long as the identity key on disk doesn't change. The `domains` AND `capabilities` sets are compared as sets (order-insensitive); if the MCP at re-connect time declares a different set than the user originally approved (e.g. adds `"read_cookies"`), the extension treats the record as missing and falls back to a re-pair prompt. Records persisted before 0.2.0 added the `capabilities` field are normalised to `["fetch"]` on read.

Major-version bumps of the extension invalidate trust (force re-pair); patch and minor bumps carry trust forward. The 0.1.x → 0.2.0 jump is a major-equivalent: 0.1.x trust records would deserialise into an object with no `domains` field and fail the set comparison, so users see a one-time re-pair prompt after upgrading.

## Multi-MCP concentrator

The host MCP's `WebSocketServer` accepts:

- **One** extension WS (extras get `1008 "extension already connected"`).
- **N** peer WSes, one per other MCP on the machine.

Frame routing rule (executed inside the host):

| From | `mcpId` matches host's own? | Action |
|---|---|---|
| extension | yes  | decrypt locally, dispatch inner |
| extension | no   | forward verbatim to `peers.get(mcpId).ws` |
| peer      | always | forward verbatim to the extension |

1.12.0+ adds one non-`mcpId`-keyed relay: the extension's own `hello` goes to every peer (on extension connect, and on peer registration when an extension is already attached). It carries no secret — identity pubs and a nonce — and without it a peer cannot tell which browser it is talking to.

Host shutdown: peers see WS close and re-race the port. Whoever wins becomes the new host; others reconnect as peers. There is a brief blip (~100 ms) but no state loss because trust + session derivation are stateless given the identity keys.

## Remote relays (2.1.0+)

The extension can hold several bridges at once: `ws://127.0.0.1:37149` always, plus zero-or-more configured `wss://` targets. Each is an independent link speaking exactly the protocol above — the concentrator being on another machine changes the topology, not the wire.

**The browser leg's credential travels as a subprotocol**, because an MV3 service worker cannot set a request header:

```
Sec-WebSocket-Protocol: fetchproxy.bridge.v1, fetchproxy.token.<credential>
```

A relay must accept the connection with `fetchproxy.bridge.v1` selected. Subprotocol values are RFC 7230 tokens, so a credential may not contain `=`, `/`, `,` or spaces (unpadded base64url is fine).

**What a relay MUST do**, all of it forced by the handshake rather than by convention:

1. **Forward `hello` verbatim in BOTH directions.** `ready.sessionSig` covers `(mcpHelloNonce || extHelloNonce || extensionSessionPub)` and the MCP verifies it against the extension hello *it was handed*, so a relay that mints a hello of its own is closed by the MCP as a MITM — correctly. The extension's hello has to reach every MCP unmodified, and each MCP's hello has to reach the extension unmodified.
2. **Route on its OWN bookkeeping, never on what a frame asserts.** `mcpId` is `<serverName>:<version>:<16-hex>`, minted by the MCP. A relay serving more than one user must resolve the destination from the socket a hello arrived on and refuse any frame carrying an `mcpId` it did not itself bind to that user. The extension does the same in the other direction: an `mcpId` belongs to the link it said hello on, and a frame arriving on any other link is dropped.
3. **Mint nothing else either.** `frame` payloads are AES-256-GCM under a key derived from the MCP's identity, so a relay cannot read or forge one — but `pair-pending` and `ready` are cleartext, and passing them through unmodified is what keeps the pair code meaningful on both ends.
4. **Expect a reconnect to invalidate everything derived from the old hello.** The extension's nonce is per connection, so when the browser leg drops, every MCP link built on that hello has to be re-established.

**`download` is local-only.** It answers with a filesystem path on the browser's machine, so the extension refuses it on a remote link (`ok: false`, with a reason naming why) rather than returning a path that cannot resolve — and rather than letting a remote MCP write files onto somebody's machine. Every other verb crosses unchanged.

A relay cannot serve MCPs by dialling an existing concentrator as a peer and standing behind it: a peer receives frames for its own `mcpId`, not the extension role's traffic. It has to terminate the browser's socket itself.

The MCP-side identity pin (§`T-fake-extension` in `docs/SECURITY.md`, 1.12.0+) is a precondition for running one of these, not an enhancement to it: without it an MCP accepts whatever identity presents a well-formed hello, so a stolen relay credential is a working session with every MCP behind that relay rather than a prompt.

## Timeouts + retries

- **Handshake** — the host gives the extension `15s` to send its hello. Peers give the host `15s` to forward the extension's `ready`.
- **Request** — no protocol-level timeout. Callers (`FetchproxyServer.fetch`) hold their own deadlines.
- **Retries** — not in the protocol. `ok: false` is surfaced to the MCP, which decides whether to retry.

## What's not in the protocol (closed by design)

- `eval_js`, `inject_script` — no arbitrary JS execution in tabs. `graphql` does not add this: it can only invoke an operation the MCP declared in `graphqlOps`, through the page's own Apollo client, and only once the page's client has organically observed that operation.
- `read_storage` (localStorage, IndexedDB) — no general exfiltration primitives. `read_cookies` is a deliberate, narrow exception: the user explicitly opts in at pair time, and only non-HttpOnly cookies are visible to page JS.
- `click`, `navigate` — no UI automation. Use claude-in-chrome for that.
- Wildcard MCPs — the declared `domains` set must be enumerated explicitly. No `*.com` or "any domain" wildcards.
- Wildcard capabilities — the declared `capabilities` set must be enumerated explicitly. Unknown capability strings are rejected by the validator.
- Streaming responses — bodies are buffered and returned whole.

These omissions are the security model. See `docs/SECURITY.md`.

## Versioning

The `hello.protocolVersion` field is the wire-format version. v1 is the current and only released version. Mismatched protocol versions get the handshake rejected — no graceful downgrade.

Code packages:

- `@fetchproxy/protocol` — frame types, validators, crypto wrappers, mcpId, pair-code, seal/open.
- `@fetchproxy/server` — `FetchproxyServer` (election + host/peer roles + convenience methods).
- `fetchproxy-extension` (Chrome MV3) — the WS client + content script + popup.

Major version bumps of these packages indicate wire-incompatible changes. Patch/minor bumps add features additively or fix bugs.
