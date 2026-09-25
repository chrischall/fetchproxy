# fetchproxy protocol (v4, ships with 3.0.0+)

The wire format between MCP servers and the browser extension. JSON-over-WebSocket. A small set of top-level frame types; all data frames after the handshake are AES-256-GCM encrypted end-to-end between each MCP and the extension.

`PROTOCOL_VERSION` is `4`. The `hello` frame carries it explicitly; a mismatch is **refused at the hello, out loud, in both directions** — never negotiated down. See [§Versioning](#versioning) for the version table, the refusal texts, and why the package major and the protocol version are off by one.

**3.0.0 is wire-incompatible with 2.x (protocol 3).** The MCP now contributes a per-session X25519 **ephemeral** (`hello.sessionPub`) and the session key is derived ephemeral × ephemeral, salted with a transcript over both nonces and both ephemerals. Under v3 the MCP's half of the ECDH was its **long-term** identity key, so anyone holding an MCP's identity plus a recording of its frames decrypted them afterwards — passively, retroactively, with nothing to notice. v4 makes the identities authenticate **only**: both signatures widen to cover both ephemerals, and every encrypted frame is sealed under AAD binding it to `mcpId ‖ seq ‖ direction`. Because the ECDH no longer proves possession of the long-term key, the proof is now explicit — a verifier must check the hello signature against the Ed25519 key **its own trust record** holds, not merely the one carried in the same frame ([§The verification rule](#the-verification-rule-both-keys-or-neither)). All packages release together and the extension must be reloaded; a v3 peer is refused at the handshake with a reason naming both versions.

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
   │                                    │ ◀────── WS open (local) ──── │
   │                                    │ ◀─ hello (peer, REGISTRATION)│
   │                                    │    answersExtNonce = 32×0x00 │
   │                                    │    (withheld — Rule B)       │
   │ WS open ws://127.0.0.1:37149       │                              │
   │ ─── hello (extension) ───────────▶ │                              │
   │                                    │ ─── hello (extension) ─────▶ │
   │                                    │    each peer's mint trigger  │
   │                                    │ ◀─ hello (peer), answering   │
   │ ◀─ hello (host's own MCP) ─────────│    THIS extension session    │
   │    minted for THIS session         │                              │
   │ ◀─ hello (peer, forwarded) ────────│                              │
   │                                    │                              │
   │ (verify sessionSig against the PINNED Ed25519 key, look up trust) │
   │ (if unknown identity → popup, user verifies pair code)            │
   │                                    │                              │
   │ ready { mcpId, extensionSessionPub, mcpSessionPub, sessionSig }   │
   │ ─────────────────────────────────▶ │                              │
   │                                    │ ──── ready (forwarded) ────▶ │
   │                                    │                              │
   │ (each side: shared = X25519(own ephemeral priv, far ephemeral     │
   │  pub); sessionKey = HKDF(shared, salt = transcript, info))        │
   │                                                                   │
   │ frame { mcpId, seq, iv, ciphertext } — AES-GCM under AAD over     │
   │   (mcpId, seq, direction); opaque to the host either way          │
   │ ─────────────────────────────────▶ │ ──── forwarded verbatim ───▶ │
   │                                    │                              │
   │ ◀──────────── frame ───────────────│ ◀──────── frame ─────────────│
```

The extension's hello comes **first on every connection**, and every server
hello a session is opened from is minted in answer to one. There is no cached
server hello anywhere in this sequence: under v4 a replayed hello names an
ephemeral whose private half has already been zeroed, so the extension would
derive a key nobody holds. A peer's registration hello is the one hello that
answers no extension session, it says so on the wire, and the host will not
forward it — [§The ephemeral's lifetime](#the-ephemerals-lifetime) is the whole
of that rule.

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
- A `hello.protocolVersion` that is not `4` — and this one is *answered* rather than merely dropped; see [§Versioning](#versioning)
- A server hello with no `sessionPub`, or one that is not exactly 32 raw bytes (the key the ECDH runs on — length-checked where the identity pubs are not)
- A server hello with no `answersExtNonce`, or one that is not exactly 32 raw bytes. The **value** 32 zero bytes is accepted here: it means "this hello answers no extension session", and refusing a hello for that is a gate's job, not the validator's
- A `ready` with no `mcpSessionPub`, or one that is not exactly 32 raw bytes

### Top-level frames (in plaintext on the wire)

#### `hello` (server → host → extension)

A peer sends one of these as the very first frame after dialling the host (its
**registration** hello). Every other server hello is minted in answer to an
extension hello — see [§The ephemeral's lifetime](#the-ephemerals-lifetime),
which is the rule governing when one may be sent at all.

```jsonc
{
  "type": "hello",
  "protocolVersion": 4,
  "role": "server",
  "mcpId": "opentable-mcp:0.10.0:a3f7c91d2e8b4f56",
  "serverName": "opentable-mcp",
  "version": "0.10.0",
  "domains": ["opentable.com"],
  "capabilities": ["fetch"],          // optional — defaults to ["fetch"]
  "identityX25519Pub": "<base64 raw 32B>",   // long-term — the TRUST key
  "identityEd25519Pub": "<base64 raw 32B>",  // long-term — authenticates
  "sessionNonce": "<base64 raw 32B, fresh per extension session>",
  "sessionPub": "<base64 raw 32B>",          // 3.0.0+: the per-session X25519 EPHEMERAL
  "answersExtNonce": "<base64 raw 32B>",     // 3.0.0+: the extension hello's
                                             //   sessionNonce this hello was
                                             //   minted against, or 32 zero
                                             //   bytes for "answers none"
  "sessionSig": "<base64 Ed25519Sign(identityEd25519Priv, helloSignaturePayload(...))>"
}
```

**`sessionPub` (3.0.0+) is what the session key is derived from**, against the
extension's own ephemeral. `identityX25519Pub` stays the **trust key** — the
extension pins `sha256(identityX25519Pub)`, the pair code commits to both
identities, and nothing about pinning, trust records or re-pair prompts moved —
so `sessionPub` sits *beside* the identity rather than replacing it, which is
what keeps v4 from re-pairing the fleet. It is minted per **extension session**,
not per process: a per-process ephemeral would bound forward secrecy at the
process lifetime, which is not a property worth calling forward secrecy.

**`answersExtNonce` (3.0.0+) is always 32 bytes**, never absent: the
`sessionNonce` of the extension hello this hello was minted against, or 32 zero
bytes (`ANSWERS_NO_EXT_SESSION`) for a hello that answers none. It is a *value*
rather than an absence for two separate reasons. On the wire it makes a hello
self-describing about which extension session its `sessionPub` belongs to, and
the two gates owed that fact are fixed 32-byte equalities with no branch for a
missing field — a nonce from a CSPRNG is never 32 zeroes, so "answers nothing"
fails them by arithmetic rather than by a special case. In the signed payload it
is fixed-length because `mcpId` is variable-length and sits in front of it: an
omitted trailing field would let two different `(mcpId, answers)` pairs
concatenate to the same signed message.

`domains` is a non-empty array of hostnames the MCP is allowed to reach. Each entry must be a valid DNS hostname (≥2 labels, alphanumeric + hyphen, no leading/trailing hyphen). The extension allows a fetch iff its URL host matches one of these entries exactly OR is a subdomain of one of them. Most MCPs send one entry (`["opentable.com"]`); MCPs that legitimately span multiple hosts send all of them (`["honeybook.com", "hbsplit.com"]`).

`capabilities` is an optional non-empty array of inner-verb capability strings the MCP wants the extension to expose. Known values:

- `"fetch"` — issue HTTP requests against the user's signed-in tab. Default; if `capabilities` is omitted, the extension treats it as `["fetch"]`.
- `"read_cookies"` — read the declared `cookieKeys` for an origin via `chrome.cookies.get`, which **includes HttpOnly cookies such as the login session** (the legacy `{tabUrl}` form reads the tab's `document.cookie`, non-HttpOnly only). Strictly opt-in; the popup lists the cookie names and warns that they may include the login session.
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

**`sessionSig` and what it covers (3.0.0+).** One exported function states the
bytes, so the two server paths that produce them and the extension paths that
verify them cannot drift apart (`helloSignaturePayload` in
`@fetchproxy/protocol`):

```
helloSignaturePayload(mcpId, sessionNonce, sessionPub, answersExtNonce)
  = utf8(mcpId) || sessionNonce || sessionPub || answersExtNonce
  signed with the MCP's long-term Ed25519 key
  (protocol 3 and earlier: utf8(mcpId) || sessionNonce)
```

`sessionPub` is the whole reason the payload widened: the session key is derived
from it, so without a signature over it a relay substitutes an ephemeral it
holds the private half of, the extension derives against the relay's key, and
forward secrecy is fiction. It is the exact mirror of what 2.0.0 did for the
`ready`. `answersExtNonce` is signed because the host's forwarding gate **reads**
it — an unsigned echo is one a relay re-points at whichever extension session it
wants the hello delivered to. The last two fields are the same length and
adjacent, so which is which is a fact only that function states; every producer
and verifier reads it from there rather than concatenating its own.

#### The verification rule: both keys, or neither

**A signature is worth only what its verifier pins**, and under v4 the extension
has to pin both halves. A hello is auto-trusted only when the trust record's
`serverName`, `domains` **and `identityEd25519Pub`** all match the hello;
anything else falls through to a re-pair prompt. An absent stored value
mismatches rather than being normalised to the hello's — normalising would make
the check a tautology.

This is new in 3.0.0 and it is not tidiness. Under v3 the extension derived the
session key from `identityX25519Pub`, the very key its trust record is keyed on,
so *completing* a session was itself a proof that the far end held the pinned
private key; the hello signature was belt-and-braces on top, and omitting the
Ed25519 comparison was harmless. **v4 inverts that.** The key now comes from an
ephemeral, and a signature under `identityEd25519Pub` is the only thing binding
that ephemeral to a trusted identity. With the comparison missing, an attacker
holding nothing but **public** values impersonates any trusted MCP: copy
`identityX25519Pub` out of any recorded hello (it is plaintext on the wire by
construction, and a hosted relay sees every one), present it beside an Ed25519
key and a `sessionPub` of their own, sign the hello payload with their own key —
which verifies, against the key carried in the *same frame* — hit the genuine
record on the `sha256(identityX25519Pub)` lookup, and auto-trust with no prompt.
Shipping the ephemerals without this would be an upgrade in confidentiality and
a downgrade in authentication.

The other direction already had it and needs nothing: the MCP has never had
implicit proof of possession of the extension's identity (the extension's
contribution has been an ephemeral since 0.4.0), so `decideExtensionTrust`
(`@fetchproxy/server`) has compared **both** pinned keys since 1.12.0, for the
reason its own comment gives — a rotation of one is a different extension, and a
half-match lets an attacker keep the key it needs while swapping the key it does
not hold, or the reverse. v4 makes that rule true of both ends. **One** state
names what the check is worth rather than hiding it: a **first** pairing has
nothing pinned to compare against, and the user's own approval of the pair code
stands in its place.

Under v3 there was a second, and v4 closed it rather than carrying it forward: a
peer behind a pre-1.12.0 concentrator ([a label, not a
release](#1120-is-a-label-not-a-release)) is forwarded no extension hello, so it
had nothing to verify against and warned and proceeded unless
`requireExtensionIdentity` was set. **Since 3.0.0 that peer refuses.** The HKDF
salt is a transcript over both hello nonces, and the extension's arrives on the
relayed hello and nowhere else, so a peer that never receives one cannot compute
a session key at all — the warn-and-proceed branch is gone rather than
configurable, and the option is a deprecated no-op. The configuration is in any
case unreachable under v4: that peer's own registration hello carries
`protocolVersion: 4`, which a pre-3.0.0 host's validator throws on before the
peer is mapped at all.

Re-pair only happens on first sight of a new identity key; subsequent sessions
verify the signature against the stored `identityEd25519Pub`. The trust record
also stores the approved `domains` set — a server that later widens the set (or
changes `serverName`) is refused auto-trust and falls back to a re-pair prompt.

#### `hello` (extension → host)

Sent **first on every connection**, in the socket's `open` handler, before any
server hello. That ordering is what makes a v3 extension refusable by a v4 MCP
without either end negotiating ([§Versioning](#versioning)), and since 3.0.0 it
is also what every server hello is minted in answer to.

```jsonc
{
  "type": "hello",
  "protocolVersion": 4,
  "role": "extension",
  "platform": "chrome" | "safari" | "firefox",
  "extensionId": "fetchproxy",
  "version": "3.0.0",
  "identityX25519Pub": "<base64 raw 32B>",   // 0.4.0+: long-term
  "identityEd25519Pub": "<base64 raw 32B>",  // 0.4.0+: signs the ready
  "sessionNonce": "<base64 raw 32B, fresh per connection>"
}
```

(0.4.0 gave the extension a long-term identity of its own; before that its
identity was "the only WS client allowed to connect".) The `sessionNonce` is 32
raw bytes from a CSPRNG, which is what the server hello's `answersExtNonce`
echoes back.

**Only one extension is active at a time.** A second extension that connects is closed with `1008 "extension already connected"`.

**1.12.0+: the host relays this frame to every peer**, and to a peer that joins later. A peer has to authenticate the extension behind the concentrator before deriving a session key from a `ready` the concentrator handed it (see below), and the identity + nonce in this hello are the only material that lets it. Peers before 1.12.0 ignore the frame; hosts before 1.12.0 never send it. Under v3 a 1.12.0 peer behind such a host warned and proceeded unless `requireExtensionIdentity` was set; **since 3.0.0 it refuses, and that option is a deprecated no-op** — the v4 HKDF salt is a transcript over both hello nonces, and the extension's reaches a peer only on this frame, so a peer that is never sent one has nothing to derive from and says so (`no extension hello has been relayed to this peer …`). The seam it used to cover is unreachable from a v4 peer anyway: that peer's own registration hello carries `protocolVersion: 4`, and a pre-3.0.0 host validates it against its own `PROTOCOL_VERSION` and throws (`hello.protocolVersion: must be 3`) before the peer is ever mapped. **Since 3.0.0 this relay is also the peer's mint trigger** — one ephemeral per extension session, which is why the second send (to a peer that joins later) is gated to a peer's **registration** hello ([Rule A](#rule-a--mint-on-an-extension-hello-never-otherwise)).

**1.12.0+: the MCP pins this identity.** The first extension to complete a handshake is recorded at `~/.fetchproxy/identity/<server-name>.extension-trust.json`, and a later hello carrying a different `identityX25519Pub`/`identityEd25519Pub` is refused with `1008` before any session exists — the mirror of the extension's own `trustedMcps`. The pin is written only after the `ready` signature verifies, so claiming an identity is never enough to become the pinned one. `fpx trust list` / `fpx trust clear <server-name>` and `FETCHPROXY_TRUST_NEW_EXTENSION=1` are the deliberate ways out; see `docs/SECURITY.md` §T-fake-extension. `FETCHPROXY_TRUST_DIR` (or the `trustDir` option) moves the pin off the identity directory, which a host that provisions the identity read-only has to set or no pin is ever kept.

#### `ready` (extension → host → server)

The signature binds both endpoints' nonces, and **both the host and (1.12.0+) peers verify it** before deriving a session key. That proves the extension on the other end is the one whose hello arrived — it cannot be produced without the extension's Ed25519 private key.

After the user approves a new pair (or auto-trust hits for a known identity), the extension generates an ephemeral X25519 keypair, computes the session key, and sends:

```jsonc
{
  "type": "ready",
  "mcpId": "opentable-mcp:0.10.0:a3f7c91d2e8b4f56",
  "extensionSessionPub": "<base64 raw 32B>",
  "mcpSessionPub": "<base64 raw 32B>",   // 3.0.0+: the MCP ephemeral this
                                         //   ready was derived against
  "sessionSig": "<base64 Ed25519Sign(extEd25519Priv, readySignaturePayload(...))>"
}
```

**What `sessionSig` covers**, in one exported function for the same reason the
hello's is (`readySignaturePayload()` in `@fetchproxy/protocol`):

```
readySignaturePayload(mcpHelloNonce, extHelloNonce, extensionSessionPub, mcpSessionPub)
  = mcpHelloNonce || extHelloNonce || extensionSessionPub || mcpSessionPub
  signed with the extension's long-term Ed25519 key
  (protocol 3: the same without mcpSessionPub; protocol 2: the two nonces alone)
```

`extensionSessionPub` arrived in 2.0.0: under v2 the ephemeral key was unsigned,
so a relay forwarding genuine frames could substitute its own and derive the same
session key. 3.0.0 adds the fourth field, the MCP's own ephemeral, so the
transcript is bound **symmetrically** — after v4 neither side's contribution to
the ECDH can be substituted without a signature from a long-term key the relay
does not hold. Each server path verifies it against the `identityEd25519Pub` the
extension sent in its own hello, which its trust decision separately holds to the
pinned record — [both keys, never either](#the-verification-rule-both-keys-or-neither).

**`mcpSessionPub` is named explicitly rather than left implicit in the
signature, and that is a requirement on the server paths** (they live outside
`@fetchproxy/protocol`, which is why the frame's own doc states it as an
obligation). A server MUST compare this field to the ephemeral it currently
holds **before** verifying the signature, and MUST treat the two outcomes
differently:

| `mcpSessionPub` | What the server does |
|---|---|
| equals the ephemeral it holds | verify the signature; an invalid one closes `1008`, as it always has |
| anything else, or it holds none | **discard** — log it, close nothing, reject nothing, change nothing |

Under v3 a stale `ready` and a forged one were the same `1008`, so an ordinary
extension reconnect that raced a re-hello stranded a bridged MCP. A discard is
right here exactly because a superseding hello is already on its way
([§The ephemeral's lifetime](#the-ephemerals-lifetime), Rules C and D). The
comparison is before the verify for two reasons: that branch is reached before
anything has been authenticated, so anything able to put a frame on the socket
can reach it and it must therefore cost nothing; and the extension signs over
the pub it derived against, so a stale `ready`'s signature is *always* over the
stale pub — checking the signature first would refuse every stale one for the
wrong reason.

#### `frame` (encrypted, either direction)

After `ready`, every data frame is encrypted:

```jsonc
{
  "type": "frame",
  "mcpId": "opentable-mcp:0.10.0:a3f7c91d2e8b4f56",
  "seq": 1,                       // monotonic per direction, starts at 1
  "iv": "<base64 raw 12B, fresh per frame>",
  "ciphertext": "<base64 — AES-256-GCM(sessionKey, iv, innerFrameJson, aad)>"
}
```

`ciphertext` includes the 16-byte GCM tag. The host routes by `mcpId` and never decrypts.

**3.0.0+: every frame is sealed under AAD naming its own identity.**

```
frameAad(mcpId, seq, direction)
  = utf8('fetchproxy/4/frame' || NUL || mcpId || NUL || decimal(seq) || NUL || direction)

direction = 's2e'   // server (the MCP) → extension
          | 'e2s'   // extension → server
```

`mcpId` and `seq` ride on the **envelope**, outside the ciphertext, so until v4
nothing the GCM tag covered committed to either: a party in the path could
replay a recorded frame under a bumped counter, re-file one under another MCP's
id on the shared concentrator socket, or reflect one back at its sender. All
three now fail the tag, rather than being caught — or not caught — by a check
downstream. `direction` is **not on the wire** and deliberately so: each end
knows which value it is entitled to use from the socket a frame arrived on, so a
reflected frame authenticates under neither. `sealInnerFrame` and both open
functions take it as a **required** parameter, so no call site can omit it and
no default can be wrong.

NUL-separated because `mcpId`'s charset excludes NUL and `seq` is rendered
decimal, so no value of one field can spell the boundary of another and the
encoding is unambiguous. The domain label in front means an AAD can never be
mistaken for any other signed or authenticated string in this protocol.

**The wire size does not move.** GCM's additional data is authenticated and
never transmitted, so a v4 frame is byte for byte the size its v3 counterpart
was: `sealedFrameWireBytes` returns the same number, and the 42 MiB
`MAX_FRAME_BYTES` beside it — derived from the largest legitimate response body
rather than picked — is not the AAD's to move. The frozen v3 corpus carries the
measurement, against a frame `@fetchproxy/protocol@2.11.3` actually sealed. The
two versions disagree about what a frame *means*, never about how large one may
be.

Replay protection: the receiving side rejects any `seq <= lastInbound` (per direction, per session). WS guarantees ordering, so gaps from out-of-order arrival are not a concern. Since 3.0.0 that counter check is a second line rather than the only one — `seq` is inside the AAD, so a replay under a bumped counter fails to open at all.

#### `hello-rejected` (extension → host → server), 2.6.0+

Sent when the extension refuses a `hello` before any session exists — a bad
`sessionSig`, an `mcpId` already bound to another bridge, a hello answering an
extension session this link did not open ([Rule C](#rule-c--the-extension-refuses-a-stale-hello-the-mcp-discards-a-stale-ready)),
or, since 3.0.0, a [protocol version mismatch](#the-two-refusal-paths) — which is
the one case reached from a frame the validator **threw out**, read back through
a narrow `peekHelloVersion` that grants nothing: no session, no `mcpId` binding,
no trust read, no counter moved.

```jsonc
{
  "type": "hello-rejected",
  "mcpId": "resy-mcp:0.13.1:2259288954ecdf3d",
  "reason": "serverName/domains mismatch with trust record"
}
```

Without it a refusal is indistinguishable from silence: the extension logs to
a service worker nobody has open, and the MCP waits out
`SESSION_READY_TIMEOUT_MS` before throwing `not-ready` — whose hint blames
being signed out or a changed scope, causes that may both already be
satisfied. With it the MCP fails immediately and reports the real reason
(`FetchproxyHelloRejectedError`).

**Gated on `accepts`, at BOTH hops.** The extension sends it only to a server
whose `hello` listed `"hello-rejected"`, and a host relays it onward only to a
peer that listed it — the same two-sided rule `extension-disconnected`
follows. `validateFrame` on a server older than 2.6.0 throws `unknown frame
type` and its caller closes the socket, so an ungated send at either hop would
turn a diagnosable refusal into a dropped connection, which is worse than the
silence it replaces. A server that cannot hear it keeps the old behaviour and
times out.

**Classified.** `classifyBridgeError` returns `'hello_rejected'`, distinct
from `'session_not_ready'`: the latter is a timeout that can only guess, this
one is the extension's own answer and will be identical on retry.

**Diagnostic only.** It carries no authority and grants nothing; a forged one
can make a session fail, which a silent peer could do anyway by never
answering. `reason` is capped at 200 characters because it lands verbatim in
an error message a caller may log.

#### `peer-gone` (host → extension)

```jsonc
{ "type": "peer-gone", "mcpId": "resy-mcp:0.13.1:2259288954ecdf3d" }
```

Sent by the host when a PEER's socket to it closes. The extension drops that
mcpId's session key, scope grants and link binding — the per-MCP half of what
a whole-link close already does. Before it, only the link closing cleared
them, so every short-lived peer (each bootstrap lift and `fpx` call gets a
fresh mcpId) left a session behind for the life of the loopback link, and the
popup kept listing exited MCPs as connected.

**Gated on `accepts`.** The extension's own `hello` now carries an optional
`accepts` list (`["peer-gone"]`), the mirror of a server's; a host sends the
notice only to an extension that listed it, because an older extension's
`validateFrame` refuses the unknown type. An older host simply never sends it.
The extension honours it only for an mcpId bound to the link it arrived on.

**No authority.** It can only END a session, which the host could already do
by never forwarding that peer's frames.

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
- `tabUrl`: required. Must itself be on one of the MCP's declared `domains` (or a subdomain of one), exactly like `url` — a request naming a relay tab outside them is refused before any tab is messaged. Prefix-matched against `chrome.tabs.query({})`. First match wins. If no match, the response is `ok: false`. After a successful pair, the extension proactively opens `https://${domains[0]}/` if no matching tab is open. (Future: open a tab for every declared domain.)
- `inPage`: optional boolean, default `false`. When `true` the request is issued by the page's MAIN world instead of the content script's isolated world — same URL, method, body, injected CSRF header and cookies; only the calling world differs. Requires the `fetch_in_page` capability: the background rejects `inPage: true` from an MCP that didn't declare it, before the request reaches any tab. Must be a real boolean — a non-boolean is a protocol error, never coerced.

  Use it only where the isolated world genuinely fails. Some edge bot-managers accept a request from the page and reject the byte-identical one from the isolated world: on opentable.com a GraphQL **mutation** POST 403s from the isolated world and returns 200 from the page, while GraphQL queries and REST writes pass from either. The cost is that page script can see and patch `window.fetch`, so a flagged request loses the isolated world's tamper resistance — see `T-in-page-fetch` in [SECURITY.md](./SECURITY.md). Flag individual calls, never everything.

**Body size caps:** request body ≤ 1 MB, response body ≤ 5 MB. Larger bodies are rejected with `ok: false` — including on the `inPage` path, which re-checks the response cap in the content script before the body leaves it.

##### `op: "read_cookies"`

Legacy shape: the extension returns `document.cookie` from a tab matching `tabUrl`, so only non-HttpOnly cookies are included. The `{ origin, keys }` shape (see `ReadCookiesInitV3` in `packages/protocol/src/frames.ts`) reads each declared key with `chrome.cookies.get` and **does return HttpOnly cookies, including session cookies** — see `docs/SECURITY.md` §T-cookie-exfil.

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

## The ephemeral's lifetime

Everything above says "the ephemeral this process currently holds" as though
minting one and installing it were a single step. They are not — the mint awaits
a keygen and a signature — and under protocol 3 a server hello reached the
extension by three paths rather than one: the host's own, the host's replay of a
peer's **cached** hello, and its live forward of a peer's hello. Two further
paths are not hellos at all but a `ready` arriving after the hello it answers has
been superseded — one minutes later, when the user answers a pair prompt, and one
milliseconds later, when a service-worker reconnect lands an extension hello
while a peer's re-hello is still in flight. The first needs the rule to hold for
longer; the second needs it to say what happens when it cannot. So the rule both
ends are held to is stated once, over every path, and it is meant to be checked
against the code rather than believed.

> **Invariant.** Every server hello the extension can act on carries a
> `sessionPub` whose private half is held, by exactly one MCP process, from the
> moment that hello was **committed** until the extension session it was minted
> for ends — which is also the moment after which that `sessionPub` can no
> longer produce a usable `ready`. While it is held it is displaced only by a
> mint for a **later** extension session, never by one for an earlier session
> whose crypto resolved late. A hello that would not satisfy it is never
> forwarded to the extension in the first place — and, when the process learns
> before the send that it minted for a session that has since ended, never sent;
> and a `ready` that names a `sessionPub` this process no longer holds is
> **discarded**, never refused, because the hello that superseded it is already
> on its way.
>
> **And it has a LIVENESS half, which is the trigger side of the same rule:**
> one extension session draws exactly **one** session-ephemeral mint per MCP
> process, and every session-ephemeral mint is drawn by an extension session.
> *Session-ephemeral* is what makes the second clause true rather than nearly
> true: a peer also mints a **bootstrap** keypair, once, at dial, drawn by no
> extension session at all (below). Without the liveness half the safety half is
> satisfied by a process that mints forever — every hello it sends names the
> live session, every mint it commits is the current one, nothing is ever
> stale — and no session ever opens.

Four rules produce it. **Committed**, rather than *minted*, is the load-bearing
word, and Rule D is where it is cashed.

### Rule A — mint on an extension hello, never otherwise

The host mints in its extension-hello handler and sends the hello it built from
that mint. A peer mints when the *relayed* extension hello arrives and sends a
fresh server hello in the same handler. Nothing else mints a session ephemeral,
and nothing reuses one across two extension sessions.

Which frames are **triggers** is as load-bearing as what a mint does, because a
peer's trigger arrives from the host and the peer's answer goes straight back to
it — so a trigger the host re-sends in answer to that answer is a loop, and Rule
B's mirror is what forbids it. A path added later owes a row here:

| Frame reaching a peer | A mint trigger? | Why |
|---|---|---|
| the extension hello fanned out on extension connect | **yes** | one per extension session, to every peer in the map at that moment |
| the cached extension hello at the tail of the peer-hello branch | **yes — and only in answer to a REGISTRATION hello**, per Rule B's mirror | it is how a peer that registered *after* that fan-out learns an extension is attached at all; un-gated it also answers the peer's own re-hello, which is the livelock |
| `extension-disconnected` | no | it ends a session: it zeroes, it does not mint |
| a `ready` on either path | no | Rule C's subject — it names an ephemeral rather than asking for one |

### Rule B — the host forwards a server hello only when the hello names the current extension session

The gate is: an extension is attached, and the frame's `answersExtNonce` equals
that extension hello's `sessionNonce` — a fixed 32-byte comparison, with no
branch for an absent field. Two sends that were unconditional under v3 fail it,
and both are wrong under v4 for the same reason: the replay of each peer's
**cached** hello to a newly connected extension (**removed** in 3.0.0), and the
forward of a peer's **registration** hello to an already-connected extension (now
withheld). In both cases the `sessionPub` on the wire is one Rule A is about to
supersede.

**The gate is on the FRAME, never on a mark recorded per peer.** A mark is the
slot's *latest* state rather than the frame's provenance, and it fails twice
over: it would be read after an `await ed25519Verify` that the extension-hello
handler can re-point the mark inside, and even captured synchronously it stands
in for "which extension session this hello was minted against" — a proxy that
holds only while a peer never has two mints in flight, which it can, since the
peer's message handler is `async` and unserialised. So the echo goes on the wire
and inside the signed payload. The gate then needs no per-slot state, nothing to
clear on a reconnect and nothing to carry across a slot overwrite: a reconnecting
extension has a new nonce, so every hello minted against the old one stops
matching by arithmetic.

**Rule B's second half gates the other direction, with the test inverted, and
without it every peer session establishment livelocks.** The host also sends the
cached *extension* hello at the tail of its peer-hello branch, which is a Rule A
trigger. Un-gated, a peer's Rule A re-hello draws another one:

> registration hello → forward withheld (Rule B) → host sends E's hello → peer
> mints and re-hellos → the re-hello echoes E's live nonce, so Rule B now
> forwards it → host sends E's hello **again** → peer mints and re-hellos →
> unbounded.

Nothing in the other three rules stops it: Rule B passes every iteration
(each re-hello legitimately answers the live session), Rule D commits every
iteration, and Rule C is downstream of a session that never settles. Each turn
costs a keygen and a signature on the peer, a verify on the host, and a full
hello handling — bind, ECDH, HKDF, ready — on the extension. So the mirror: hand
a peer the cached extension hello **only in answer to a hello that answers no
extension session**, tested through `answersNoExtSession`, the one predicate
`@fetchproxy/protocol` exports for the fact. The two relays are then mutually
exclusive per (peer, extension session) — a peer already in the map is triggered
once by the fan-out, a peer that registers after it is triggered once by this
send, a peer that registers with no extension attached is triggered by neither
and by the fan-out when one connects. This half reads the frame and **no
authoritative variable at all**, so it has no await window to lose.

### Rule C — the extension refuses a stale hello; the MCP discards a stale `ready`

A gate that fails open must not be the only thing standing, so the rule is
enforced at both ends, by the party each failure lands on. The two outcomes are
deliberately different:

- **Extension side — refuse.** `onServerHello` refuses a hello whose
  `answersExtNonce` is not this link's own `sessionNonce`, **before** it binds
  the `mcpId`: no binding, no trust read, no pair prompt, and the existing
  `hello-rejected` path carries the reason (`this hello answers a different
  extension session`). A hello answering 32 zero bytes is refused here too, by
  that same comparison rather than a second check — `link.sessionNonce` comes
  from a CSPRNG and is never that value.
- **MCP side — discard.** Both server paths compare the `ready`'s
  `mcpSessionPub` to the ephemeral they hold before verifying the signature.
  Equal → verify, and an invalid signature keeps the `1008` it has always had.
  Not equal → **discard**: log it, change nothing, close nothing, reject
  nothing. Under v3 a stale `ready` and a forged one were one refusal;
  separating them is what stops an ordinary extension reconnect from stranding a
  bridged MCP. A relay that
  rewrites a genuine echo turns that `ready` into a discarded one, which is a
  capability it already has by dropping the frame.

### Rule D — a mint is installed only if it is still the current one

The mint awaits a keygen and a signature, and nothing serialises the handler
around it. So a mint does all of its crypto into **locals** and then **commits**
— installs `{nonce, pub, priv}` and sends the hello — at one **synchronous**
point, which first re-reads the single authoritative variable naming the
extension session the mint was for: on the host, that the extension socket it is
answering is still the attached one; on a peer, that the relayed extension hello
it is answering is still the current frame. A mint that fails its own check
**zeroes the private half it just minted, installs nothing and sends nothing.**
It loses to the newer mint rather than displacing it.

This is the one rule with **no wire footprint at all**, which is why it is
written down as what it is: an implementation obligation on both ends, without
which the invariant above is unprovable. Delete it and nothing reopens a
`1008` — a mint for an ended session overwrites the live one when its crypto
resolves, the extension's legitimate `ready` names a pub the process no longer
holds, Rule C discards it, and nothing re-mints, because the only trigger is an
extension hello and the live extension has already sent its. Rule D is therefore
what lets Rule C be a discard without being a trap: a discard is right exactly
when a superseding hello is already on its way, and Rule D is what makes
"superseding" mean *the mint that committed last* rather than *the crypto call
that returned last*. Without it, the loud failure v3 had becomes a hang.

### The bootstrap mint

A peer cannot wait for an extension hello before it hellos: the host's
`hello/server` dispatch is what **registers** the peer, and the host relays the
extension hello only to peers already registered. That registration hello must
carry a `sessionPub` — the field is required and the host verifies the signature
over it before it will map the slot — so a peer mints a **bootstrap** keypair
for it at dial and sets `answersExtNonce` to 32 zero bytes.

The bootstrap keypair is a registration credential and never a session
ephemeral: no key is ever derived from it, and what makes that a fact rather
than an intention is the wire. The frame says it answers nothing, so Rule B
refuses to forward it and the extension's own check would refuse it if the gate
ever failed open — therefore no `ready` can ever name it. Its private half is
zeroed at the first Rule A mint **that commits**, or at the peer socket's close
if none ever does; a mint that loses Rule D's check zeroes only its own half, so
the bootstrap survives it and dies to the mint that won.

### Every hello the extension can receive

The reviewable form of the invariant. A path added later owes a row.

| Hello the extension acts on | Minted | `ready` sent from | Corresponds to | Live at that moment because |
|---|---|---|---|---|
| the host's own hello | the extension-hello handler (Rule A), committed under Rule D while that socket is still the attached extension — **not** same-tick: the mint awaits | the auto-trust path, immediately | that mint | the commit is what makes it current, and from there it is zeroed only by the extension socket's close handler, which *is* the end of this extension session. A mint for an EARLIER session resolving late cannot displace it: Rule D makes it zero its own half instead |
| the host's own hello, needs-pair → the user clicks approve minutes later | as above | the approval path | that same mint | the approval path skips an mcpId with no live link, and for the HOST's own mcpId that link IS the extension's socket to this host — so the thing the guard reads dies exactly when the mint is zeroed. Not true of a peer's mcpId; see the residual below |
| a peer's Rule A hello, forwarded by the host | the relayed-extension-hello handler, ONCE per extension session — Rule B's mirror is what makes it once — committed under Rule D while that relayed hello is still the current frame | the auto-trust path or the approval path | that mint | it is zeroed on `extension-disconnected`, or displaced by a LATER session mint at its commit point — never by an earlier one resolving late. Those are the events that end this extension session; a `ready` arriving after one of them names a superseded `sessionPub` and is discarded by Rule C, not refused |
| a peer's **registration** hello | at dial (bootstrap) | — | nothing | it says so on the wire (`answersExtNonce` = 32 zero bytes), so Rule B will not forward it and Rule C's extension-side check would refuse it anyway; no `ready` can name it |
| a peer's cached hello, replayed to a newly connected extension | — | — | — | **path removed in 3.0.0** |

Zeroing at the peer's own socket close is deliberately **not** in that last
column. It is a teardown obligation — this process is leaving and must not keep
a private half it can no longer use — and not one of the moments that ends an
extension session: the socket it closes is the peer's link to the *host*, and
the extension's link to the concentrator is untouched by it.

**The one residual, stated because the guard the approval row leans on cannot
see it.** The approval path reads the link the mcpId hello'd on — the
concentrator socket, shared by the host's own mcpId and every peer's. For a
*peer's* mcpId that guard therefore **passes while the peer is gone**: the user
approves minutes later, the extension derives against an ephemeral whose private
half died with the peer, sends a `ready`, and the host drops it because that peer
is no longer in its map. The extension is left holding a session key for a dead
MCP — unusable, since nobody holds the other half, and overwritten by that
mcpId's next successful handshake. Accepted, with the reason: the peer that would
have to repair it does not exist any more. What Rule C repairs is the
neighbouring case — the peer is alive but has re-minted since the prompt — which
was the same `1008` as a forgery and is now a discard.

The cost of all of this is one round trip before a peer's session opens: the peer
hellos again once it hears about the extension, which it already pays waiting for
`ready`. What it buys is that the sequence has exactly one shape on every path —
extension hello → server hello → `ready` — with no cached frame and no superseded
key anywhere in it.


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

- X25519 keypair → **names** the MCP. The extension pins `sha256(x25519Pub)` and the pair code commits to it. Protocol 3 and earlier also ran the ECDH on it; protocol 4 does not, which is the whole of the forward-secrecy change.
- Ed25519 keypair → signs `helloSignaturePayload(mcpId, sessionNonce, sessionPub, answersExtNonce)` (protocol 3 and earlier: `mcpId || sessionNonce`). Since protocol 4 this is the **only** proof that the far end holds the pinned identity, so a verifier checks it against the key its own trust record holds — [both keys, or neither](#the-verification-rule-both-keys-or-neither).

**Per-session ephemerals, one on each side (3.0.0+).** The MCP mints a fresh
X25519 keypair per **extension session** and publishes the public half as
`hello.sessionPub`; the extension mints one per handshake and publishes it as
`ready.extensionSessionPub`.

**The two sides dispose of their private halves by different mechanisms**, and
the difference is worth stating rather than covering with one word. The MCP has
to **hold** its half across the wait for a `ready` — milliseconds on the
auto-trust path, minutes on the approval one — so holding it is a state the
implementation owes an end to: it is `fill(0)`'d at every point the extension
session can end (the extension socket's close and the peer's
`extension-disconnected` among them), at every point a mint loses its own commit
check, and at the install that displaces it, per [§The ephemeral's
lifetime](#the-ephemerals-lifetime) — which is also the rule that keeps exactly
one of them live at a time. The extension holds
no such state: its private half is a **local of the handshake itself**, spent
once in the ECDH on the following line, stored nowhere, and gone when that
handler returns — bounded by scope rather than by a wipe, because a JavaScript
runtime offers no way to guarantee one.

What both give is the same property, and it is the property rather than either
mechanism that a reader should rely on: neither ECDH input is a long-term key any
more, so an identity holder with a recording of the frames has nothing left to
derive with.

(0.4.0 gave the extension a long-term identity of its own; it authenticates
the `ready` and is never an ECDH input. Its private halves are now
non-extractable WebCrypto keys in the extension origin's IndexedDB — earlier
versions (3.2.x) kept them as raw bytes in `chrome.storage.local`, where content scripts could read
them. See SECURITY.md §T-fake-extension.)

### Pair code (SAS)

Derived deterministically from the PAIR TRANSCRIPT — both identities, both
hello nonces and the MCP's session ephemeral (protocol 4; `pairTranscript` in
`@fetchproxy/protocol`):

```
pairCode = SHA256(utf8("fetchproxy/4/pair") || NUL
                  || mcpIdentityX25519Pub || extIdentityX25519Pub
                  || mcpHelloNonce || extHelloNonce || mcpSessionPub)[0..7]
           interpreted as a big-endian BigInt
           mod 100_000_000
           formatted "XXXX-XXXX"
```

A DIFFERENT code on every pairing attempt. The MCP prints it to stderr when
the extension's hello arrives. The extension shows the same code in the pair
popup. The user compares the two and clicks Approve — that is the SAS
verification.

Protocol 3 and earlier derived six digits from the two long-term identity pubs
alone (`SHA256(mcpPub || extPub)[0..3] mod 1_000_000`, `XXX-XXX`). Both inputs
were public and never changed, so one OFFLINE grind produced a code usable
against that MCP forever; committing to a transcript makes the grind online
and per-pairing, and eight digits raise its cost from ~10⁶ to ~10⁸. It does not
remove the grind: a party posing as the extension picks its own side of the
inputs.

### Session key derivation

After the extension sends its `ready` frame, **ephemeral × ephemeral, salted
with the transcript** (protocol 4):

```
shared     = X25519(mcpSessionPriv, extSessionPub)
           = X25519(extSessionPriv, mcpSessionPub)         (symmetric)
transcript = SHA256(mcpHelloNonce || extHelloNonce || mcpSessionPub || extSessionPub)
sessionKey = HKDF-SHA256(
               IKM  = shared,
               salt = transcript,
               info = "fetchproxy/4.0.0/session",
               L    = 32
             )
```

Both sides derive the same key without sending it on the wire, and neither
long-term key is an input: the identities authenticate, the ephemerals agree.
`transcriptHash()` is exported from `@fetchproxy/protocol` because four call
sites compute it — the host, the peer and both extension derivation paths — and
the order is load-bearing rather than tidy: each side concatenates the same four
values in the same order or the two salts differ and every decryption fails with
nothing to point at.

The **salt** is a transcript rather than the MCP's hello nonce because that also
closes the replayed-`ready` case: under v3 a replayed old `ready` re-established
an old key with a reset counter, harmless only because the request `id` did not
match downstream. With both nonces and both ephemerals in the salt, a replayed
`ready` derives a key nothing else holds.

`HKDF_SESSION_INFO` moved from `"fetchproxy/1.0.0/session"` to
`"fetchproxy/4.0.0/session"` with the version, so even a hypothetical key
confusion between two versions' inputs yields different bytes rather than one
key under two sets of rules.

Protocol 3 and earlier derived it as `X25519(extEphemeralPriv,
identityX25519Pub)`, salted with the MCP's hello nonce — the MCP's half was its
long-term key, which is what made an identity a standing decryption capability
over every recorded session. **Protocol 3's** info label was
`"fetchproxy/1.0.0/session"`; the label is scoped to the protocol version here
because it has never tracked one. It was introduced at 0.5.1, so protocol 1 and
protocol 2 up to 0.5.0 used `"fetchproxy/0.1.0/session"` and protocol 2 changed
label mid-life without changing derivation — which is the reason 4.0.0 is the
protocol number rather than the package's. The frozen v3 corpus in
`packages/server/tests/cross-version/` carries protocol 3's bytes and its label
(`V3_HKDF_SESSION_INFO`), so the old derivation is pinned as a fixture rather
than remembered.

### Trust store (extension)

The extension's trust store (`trustedMcps` in the extension origin's IndexedDB vault; in earlier versions `chrome.storage.local["trustedMcps"]`, which content scripts could write — see SECURITY.md §Defense 4):

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

Keyed by identity hash, not port. Trust survives port changes, restarts, and MCP package renames as long as the identity key on disk doesn't change. The `domains` AND `capabilities` sets are compared as sets (order-insensitive); if the MCP at re-connect time declares a different set than the user originally approved (e.g. adds `"read_cookies"`), the extension treats the record as missing and falls back to a re-pair prompt. **Since 3.0.0 the stored `identityEd25519Pub` is compared too**, and an absent stored value mismatches rather than being normalised to the hello's — see [§The verification rule](#the-verification-rule-both-keys-or-neither) for why omitting it was harmless under v3 and is impersonation under v4. Records persisted before 0.2.0 added the `capabilities` field are normalised to `["fetch"]` on read.

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

1.12.0+ adds one non-`mcpId`-keyed relay: the extension's own `hello` goes to every peer (on extension connect, and on peer **registration** when an extension is already attached). It carries no secret — identity pubs and a nonce — and without it a peer cannot tell which browser it is talking to. Since 3.0.0 that relay is also each peer's **mint trigger**, so the second send is gated to registration hellos only: un-gated it answers a peer's own re-hello and the pair livelocks ([Rule B's second half](#rule-b--the-host-forwards-a-server-hello-only-when-the-hello-names-the-current-extension-session)).

Host shutdown: peers see WS close and re-race the port. Whoever wins becomes the new host; others reconnect as peers. There is a brief blip (~100 ms) but no state loss because trust + session derivation are stateless given the identity keys.

## Remote relays (2.1.0+)

The extension can hold several bridges at once: `ws://127.0.0.1:37149` always, plus zero-or-more configured `wss://` targets. Each is an independent link speaking exactly the protocol above — the concentrator being on another machine changes the topology, not the wire.

**The browser leg's credential travels as a subprotocol**, because an MV3 service worker cannot set a request header:

```
Sec-WebSocket-Protocol: fetchproxy.bridge.v1, fetchproxy.token.<credential>
```

A relay must accept the connection with `fetchproxy.bridge.v1` selected. Subprotocol values are RFC 7230 tokens, so a credential may not contain `=`, `/`, `,` or spaces (unpadded base64url is fine).

**What a relay MUST do**, all of it forced by the handshake rather than by convention:

1. **Forward `hello` verbatim in BOTH directions.** `ready.sessionSig` covers `(mcpHelloNonce || extHelloNonce || extensionSessionPub || mcpSessionPub)` and the MCP verifies it against the extension hello *it was handed*, so a relay that mints a hello of its own is closed by the MCP as a MITM — correctly. The extension's hello has to reach every MCP unmodified, and each MCP's hello has to reach the extension unmodified. Since protocol 4 the server hello's own `sessionSig` covers `sessionPub` and `answersExtNonce` too, so a relay cannot substitute an ephemeral it holds the private half of, and cannot re-point a hello at an extension session it was not minted for.
2. **Route on its OWN bookkeeping, never on what a frame asserts.** `mcpId` is `<serverName>:<version>:<16-hex>`, minted by the MCP. A relay serving more than one user must resolve the destination from the socket a hello arrived on and refuse any frame carrying an `mcpId` it did not itself bind to that user. The extension does the same in the other direction: an `mcpId` belongs to the link it said hello on, and a frame arriving on any other link is dropped.
3. **Mint nothing else either.** `frame` payloads are AES-256-GCM under a key derived from the MCP's identity, so a relay cannot read or forge one — but `pair-pending` and `ready` are cleartext, so pass them through unmodified. What keeps the pair code meaningful is no longer the relay's good behaviour: an MCP shows only the code it derived itself from the pair transcript, and a `pair-pending` carrying any other number closes the connection with a logged alarm. A relay that rewrites one breaks the link it is relaying rather than choosing what the user compares.
4. **Expect a reconnect to invalidate everything derived from the old hello, and never replay a cached one.** The extension's nonce is per connection, so when the browser leg drops, every MCP link built on that hello has to be re-established. Since protocol 4 a cached *server* hello is worse than useless: the `sessionPub` it names has had its private half zeroed, so the extension would derive a key nobody holds. A relay re-sends nothing and lets each MCP hello afresh — [§The ephemeral's lifetime](#the-ephemerals-lifetime).

**`download` is local-only.** It answers with a filesystem path on the browser's machine, so the extension refuses it on a remote link (`ok: false`, with a reason naming why) rather than returning a path that cannot resolve — and rather than letting a remote MCP write files onto somebody's machine. Every other verb crosses unchanged.

A relay cannot serve MCPs by dialling an existing concentrator as a peer and standing behind it: a peer receives frames for its own `mcpId`, not the extension role's traffic. It has to terminate the browser's socket itself.

The MCP-side identity pin (§`T-fake-extension` in `docs/SECURITY.md`, 1.12.0+) is a precondition for running one of these, not an enhancement to it: without it an MCP accepts whatever identity presents a well-formed hello, so a stolen relay credential is a working session with every MCP behind that relay rather than a prompt.

## Timeouts + retries

- **Handshake** — the host gives the extension `15s` to send its hello. Peers give the host `15s` to forward the extension's `ready`.
- **Request** — no protocol-level timeout. Callers (`FetchproxyServer.fetch`) hold their own deadlines.
- **Retries** — not in the protocol. `ok: false` is surfaced to the MCP, which decides whether to retry.

## What's not in the protocol (closed by design)

- `eval_js`, `inject_script` — no arbitrary JS execution in tabs. `graphql` does not add this: it can only invoke an operation the MCP declared in `graphqlOps`, through the page's own Apollo client, and only once the page's client has organically observed that operation.
- `read_storage` (localStorage, IndexedDB) — no general exfiltration primitives. `read_cookies` is a deliberate, narrow exception: the user explicitly opts in at pair time to a named list of cookies — which can include HttpOnly session cookies.
- `click`, `navigate` — no UI automation. Use claude-in-chrome for that.
- Wildcard MCPs — the declared `domains` set must be enumerated explicitly. No `*.com` or "any domain" wildcards.
- Wildcard capabilities — the declared `capabilities` set must be enumerated explicitly. Unknown capability strings are rejected by the validator.
- Streaming responses — bodies are buffered and returned whole.

These omissions are the security model. See `docs/SECURITY.md`.

## Versioning

The `hello.protocolVersion` field is the wire-format version. **Protocol 4 is
current**, shipped by package 3.0.0. A mismatch gets the handshake refused, out
loud, in both directions — never a graceful downgrade.

### PROTOCOL_VERSION → package major → what changed

| `PROTOCOL_VERSION` | Package major | What changed on the wire |
|---|---|---|
| 1 | 0.1.x – 0.3.x | the original: identity X25519 + Ed25519 on the server hello, `sessionSig` over `mcpId ‖ sessionNonce`, session key `HKDF(X25519(identityPriv, extEphemeralPub), salt = sessionNonce)`. (0.2.0 replaced `domain` with `domains` and added `capabilities` — a hard break within v1.) |
| 2 | 0.4.x – 1.x | the extension gained a long-term identity, a nonce and a `ready.sessionSig`; the pair code committed to **both** identities. The MITM-as-extension fix. |
| 3 | 2.x | `ready.sessionSig` widened to cover `extensionSessionPub` (GHSA-j6jv-w774-77m6): under v2 the ephemeral was unsigned, so a relay forwarding genuine frames could substitute its own and read the session. |
| **4** | **3.x** | a per-session MCP **ephemeral** (`hello.sessionPub`) with the session key derived ephemeral × ephemeral and salted with the transcript; `hello.sessionSig` widened to cover `sessionPub` + `answersExtNonce`; `ready.sessionSig` widened to cover `mcpSessionPub`; `ready.mcpSessionPub` added; AEAD **AAD** over `mcpId ‖ seq ‖ direction`; the pair code re-derived from the pair transcript at eight digits; the extension's trust match extended to `identityEd25519Pub`. |

**The package major and the protocol version are off by one, deliberately.**
Package 2.x spoke protocol 3; package 3.x speaks protocol 4. Renumbering either
to line them up would desynchronise the changelog from release-please's own
arithmetic for one cosmetic gain, so the offset stays and is written down here
and in `packages/protocol/src/frames.ts` instead. **Read a version string as a
package version;** `PROTOCOL_VERSION` is the only protocol number.

#### "1.12.0" is a label, not a release

One version string in this file names no release, and it is load-bearing enough
to appear ten times above: the peer-side verification of the extension's `ready` and
the MCP-side extension pin (#208) are marked **1.12.0+** here and in the source
comments, and **no `v1.12.0` was ever tagged.** The tags go `v1.11.0` →
`v2.0.0`, and #208 landed in package **2.0.0**, alongside the protocol 2 → 3
break. The label is left as it is rather than corrected in one document, because
it is what every comment in the tree says and a doc that disagreed with the code
would be the worse failure; read `1.12.0+` as *"the #208 change, shipped in
2.0.0"*. A sweep that retires the label everywhere at once is the only fix worth
making, and it is not this break's.

### A refusal, never a negotiation

There is deliberately no version field to negotiate on. The argument is #222's,
from the 2 → 3 break, unchanged: a version a relay can rewrite is a version a
relay can **choose**, and both ends would then agree on the weaker payload. v4
sharpens it rather than repeating it, because the party a negotiation would hand
the choice to is precisely the party the ephemerals and the AAD exist to defeat.
The same argument forbids the transitional shape that looks like the obvious way
to shrink an upgrade window: **a v4 extension that still accepts v3 IS the
downgrade path.**

### The two refusal paths

Until 3.0.0 a mismatch was a *hang*, which is the worst failure mode it can
have: the extension logged a warning to a service worker nobody has open, the
MCP waited out its 30-second session-ready timeout, and the resulting `not-ready`
hint blamed being signed out or a changed scope — causes that may both already
be satisfied. An upgrade looked exactly like the bridge being down. Both
directions are now clean, and **both are fixed by changing only the v4 side**,
which is what makes an upgrade window minutes rather than an ordering problem:

| Pair | What happens | Whose code changed |
|---|---|---|
| **v3 MCP ↔ v4 extension** | the extension recovers `protocolVersion`, `mcpId` and `accepts` from the refused hello and answers [`hello-rejected`](#hello-rejected-extension--host--server-260) with a reason naming both versions. An MCP at ≥ 2.6.0 already parses that frame and fails its pending session immediately. No session, no trust read, no `mcpId` binding. | extension only |
| **v4 MCP ↔ v3 extension** | the extension sends its hello **first on every connection**, so the MCP reads `protocolVersion: 3` off it, rejects the pending session immediately, and closes `1002` with a reason naming both versions | server only |

The close code stays **`1002`** — RFC 6455's protocol error, which a version
mismatch exactly is, while `1008` is spent on identity and authorization
refusals. What 3.0.0 changed there is the *reason* and the *immediate rejection*,
never the code.

The texts are fixed and asserted by tests, because they are what a person
actually reads. Each is **one line**; they are wrapped below to fit the page.
The extension's `hello-rejected` reason:

```
protocol version mismatch: this browser extension speaks fetchproxy protocol 4,
this MCP speaks 3 — upgrade @fetchproxy/server to >= 3.0.0
```

The MCP's thrown error (`FetchproxyProtocolVersionError`), which is what surfaces
in a tool result:

```
protocol version mismatch: this MCP speaks fetchproxy protocol 4, the attached
browser extension speaks 3 — update ContextMint Bridge to a release that speaks
fetchproxy protocol 4
```

It names the extension by its **user-facing** name, because the person reading
that in a claude.ai tool error has a browser, not a package. It names the
**protocol** the extension must speak rather than a version to update to: the
extension versions on its own release line
([nullnet-app/contextmint-bridge](https://github.com/nullnet-app/contextmint-bridge)),
so no `@fetchproxy/server` version describes it. The far end gets the
same fact cut to fit a close frame, since RFC 6455 caps a close reason at 123
bytes:

```
protocol version mismatch: this MCP speaks 4, the extension speaks 3
```

A frame malformed for any *other* reason still takes the pre-existing path — the
generic `1002 'protocol error'` on the server side, a silent drop on the
extension side — so the version mismatch is the only case that answers, and a
malformed-frame flood is not a send amplifier.

### Code packages

- `@fetchproxy/protocol` — frame types, validators, crypto wrappers, mcpId, pair-code, seal/open.
- `@fetchproxy/server` — `FetchproxyServer` (election + host/peer roles + convenience methods).
- `@fetchproxy/bootstrap` — the repeatable session lift over `FetchproxyServer`.
- `@fetchproxy/cli` — `fpx`, including the bridge-error remedies.
- `@fetchproxy/test-helpers` — the published `FetchproxyServer` mock for consumers.

All of them share **one version**, released together. The browser extension —
the WS client, content script and popup — is ContextMint Bridge, in its own repo
([nullnet-app/contextmint-bridge](https://github.com/nullnet-app/contextmint-bridge))
on its own release line; the protocol number, not a package version, is the
contract between it and these packages. Major version bumps
indicate wire-incompatible changes; patch/minor bumps add features additively or
fix bugs.
