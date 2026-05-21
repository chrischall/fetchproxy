# fetchproxy 0.4.0 — Mutual Auth + 0.3.0-Migration Ergonomics

**Status:** Approved 2026-05-21. Implementation begins immediately.

## Goal

Close the "MITM-as-extension" gap in the pair protocol AND polish the
ergonomics gaps that surfaced during the 0.3.0 migration round (seven
MCPs migrated cleanly, HoneyBook needed Pattern A++ with significantly
more boilerplate).

The MITM fix is the only **security-significant** change — everything
else is convenience that makes the next migration round (Resy + the
remaining holdouts) one-shot rather than copy/paste.

## What this is NOT

- Not a wire-additive change. **`PROTOCOL_VERSION` bumps 1 → 2.** Hello
  frames with `protocolVersion: 1` are rejected at validation. 0.3.0
  extensions cannot talk to 0.4.0 MCPs (or vice-versa). All MCP servers
  must upgrade together. Wire-additive evolution resumes within v2.
- Not a port change. Still `127.0.0.1:37149` by default.
- Not a Manifest-V3 permissions change. `chrome.storage`,
  `chrome.cookies`, `chrome.webRequest`, `<all_urls>` cover IndexedDB
  reads from content scripts.

## A. Mutual authentication (the MITM fix)

### Threat being fixed

Currently, only the MCP authenticates itself to the extension: the
server hello carries a long-term X25519 identity key, a per-session
nonce, and an Ed25519 signature over `mcpId || sessionNonce`. The
extension verifies the signature, checks the trust record (by
SHA-256 of the X25519 identity pub), and either auto-trusts or asks
the user to confirm a 6-digit pair code that commits to *only the
MCP's* identity.

There is no equivalent authentication of the extension. Any local
process X (not a real browser extension) can:

1. Dial `ws://127.0.0.1:37149` before the real extension does.
2. Send a structurally valid `HelloFrameFromExtension`.
3. Receive the MCP's server hello (including identity + nonce).
4. Pick a fresh X25519 ephemeral, send a `ReadyFrame` with
   `extensionSessionPub = ephemeral.pub`.
5. Derive the session key via ECDH (`shared = ECDH(eph_priv, mcp_pub)`
   then HKDF-extract+expand with the MCP's nonce as salt).
6. Decrypt every inner frame the MCP sends. Optionally relay the
   request to the real extension, then encrypt the response back to
   the MCP so it never notices.

Pair-code mitigation today: the pair code is derived from the MCP's
X25519 pub *only*. The user reads the code from the MCP terminal and
compares to the code shown by their browser popup — but in the
MITM-relay attack, BOTH ends see the same MCP pub, so BOTH ends
compute the same code. The user has no signal that anyone is in the
middle.

### Fix design

**1. Extension long-term identity.**

The extension generates a persistent X25519 + Ed25519 keypair on
first run, stored in `chrome.storage.local` under `extensionIdentity`.
Same shape as MCP identity (raw 32-byte private + public for each
algorithm, base64-encoded on disk). Generated lazily in
`maybeBoot()` before the first WS connect.

```ts
interface ExtensionIdentity {
  x25519Priv: string;   // base64 32B
  x25519Pub: string;    // base64 32B
  ed25519Priv: string;  // base64 32B
  ed25519Pub: string;   // base64 32B
  createdAt: number;
}
```

A new helper `loadOrCreateExtensionIdentity()` in
`packages/extension-core/src/extension-identity.ts` is the single
read+write point. Survives service-worker restarts because it lives
in chrome.storage.local.

**2. `HelloFrameFromExtension` claims identity. `ReadyFrame` carries the binding signature.**

The handshake order stays as in 0.3.0: extension hello → server hello → ready.
What changes is that:

- The extension hello carries identity claims (so the host knows
  whose signature to verify) but no signature yet.
- The `ReadyFrame` carries the Ed25519 signature over both nonces.

Extension hello (added fields):

```jsonc
{
  "type": "hello",
  "protocolVersion": 2,
  "role": "extension",
  "platform": "chrome",
  "extensionId": "fetchproxy",
  "version": "0.4.0",

  // NEW in 0.4.0:
  "identityX25519Pub":  "<base64 32B>",
  "identityEd25519Pub": "<base64 32B>",
  "sessionNonce":       "<base64 ≥16B>"
}
```

`ReadyFrame` (added field):

```jsonc
{
  "type": "ready",
  "mcpId": "...",
  "extensionSessionPub": "<base64 32B>",
  "sessionSig":          "<base64 — Ed25519Sign(extEdPriv, mcpHelloSessionNonce || extHello.sessionNonce)>"
}
```

The signature **binds the MCP's session nonce** to the extension's
nonce. This defeats a MITM relay attack: the relay would either need
to sign with the real extension's key (impossible without
compromising the browser process) or use its own key (which makes
the pair-code mismatch detectable).

**3. Pair code commits to BOTH identities.**

```
pairCode = digits(SHA256(mcpIdentityX25519Pub || extensionIdentityX25519Pub))
```

Both inputs are 32-byte raw X25519 pubs, concatenated in that fixed
order. The MCP cannot compute the pair code until the extension hello
arrives; the popup cannot compute it until the MCP hello arrives. Both
sides delay printing/showing until they've seen both.

Concretely:

- **MCP side:** `FetchproxyServer` does NOT print/log a pair code on
  `listen()`. Instead, on receipt of the extension hello, it derives
  `pairCode(mcpPub || extPub)` and exposes it via a new callback
  `onPairCode(cb)`. Existing MCPs that use bootstrap can opt in via
  `bootstrap()` opts; standalone MCPs (none today) would subscribe
  manually.
- **Extension side:** `handleServerHello` returns a `needs-pair`
  result whose `pairCode` is derived from `mcpPub || extPub`. The
  popup shows the resulting code.

**4. Trust record stores extension identity.**

```ts
// TrustRecord additions:
extensionIdentityX25519Pub: string;   // base64 — for pair-code re-derivation
extensionIdentityEd25519Pub: string;  // base64 — for sessionSig verification
```

On auto-trust (subsequent connections from a known MCP identity), the
extension's session signature is verified against the stored
`extensionIdentityEd25519Pub`. A signature failure (e.g. because a
fake extension produced a fresh keypair) → reject the hello, log a
security alert.

Stored extension identity must equal the extension's *own current*
identity. A wholesale extension reinstall (chrome.storage wiped)
produces a fresh keypair and re-triggers pair — that's correct
behavior; the user is re-approving an unknown extension binary.

**5. Popup displays extension identity fingerprint.**

Short hex digest (first 4 bytes of `SHA256(extensionIdentityX25519Pub)`,
rendered as `XXXX-XXXX`) shown beneath the trusted-MCPs list on the
status popup screen:

```
Extension ID: 12af-9c3e
```

User verifies this once after install (e.g. against a value printed
on the Chrome Web Store listing). After that they don't need to think
about it. Pair-time popup shows the same fingerprint near the pair
code as a reminder.

**6. `PROTOCOL_VERSION` bumps 1 → 2.**

A hard cut, not a back-compat window. Reasoning:

- The MITM fix is security-significant: shipping a half-version where
  some MCPs still accept extension hellos without identity proofs
  defeats the point.
- 0.3.0 is only a week old. The downstream MCPs upgrade in lockstep
  with one PR each (npm dep bump from `^0.3.0` → `^0.4.0`).
- Wire-additive evolution within v2 is preserved for future patches.

Validator rejects `protocolVersion !== 2` with a clear error message.
0.3.0 → 0.4.0 producers need to know they must upgrade.

**7. Storage schema migration on extension side.**

Existing 0.3.0 trust records have no `extensionIdentityX25519Pub` /
`extensionIdentityEd25519Pub` fields. On `TrustStore.get()`, a record
missing either field is treated as missing — forces re-pair. Same
mechanism that already handles capability/scope mismatches.

The user re-pairs ONCE per trusted MCP after upgrading. After re-pair,
the new fields are populated and subsequent connections auto-trust.

### Attack analysis

**Fake-extension on initial pair.**

X dials the WS port pretending to be the extension. Sends an extension
hello with X's own identity. Pair code = `SHA256(mcpPub || X_pub)`.
The user opens the *real* extension's popup, which shows no pending
pair (because X intercepted the WS connection — the real extension
never saw the server hello, never produced a popup notification). The
user has nothing to approve, and would notice the absence.

If we imagine X also relays the server hello to the real extension
out-of-band: the real extension's popup shows pair code
`SHA256(mcpPub || extPub_real)`, the MCP shows pair code
`SHA256(mcpPub || X_pub)`. Codes differ → user sees mismatch → cancel.

**Active relay attempt.**

X interposes between the MCP and the real extension as a transparent
proxy. To make the MCP-side handshake complete, X must send an
extension hello to the MCP. Two cases:

- X forwards the real extension's hello verbatim. The real extension's
  signature is over `(mcpNonce_X-sees || extNonce)`. But the MCP-side
  sees its own freshly generated nonce, which differs from what the
  real extension signed over (the real extension signed over the MCP
  nonce X sent it, which is X's own nonce, not the original). Either:
  - X used its own MCP-impersonator nonce when talking to the real
    extension. Then the signature it forwards verifies against the
    real extension's identity, but using `X's nonce`, not the MCP's
    nonce. MCP-side signature verification fails.
  - X tried to use the real MCP's nonce when talking to the real
    extension. Then it doesn't know its own X25519 priv to derive a
    session key from the real extension — the protocol breaks before
    it can even decrypt traffic.

- X synthesises its own extension hello with X's identity. Pair code
  on MCP side = `SHA256(mcpPub || X_pub)`. Pair code on real-extension
  side = `SHA256(mcpPub || extPub_real)`. Codes differ → user notices.

In both cases the relay either fails the signature verification or
produces visibly mismatched pair codes.

**Post-pair impersonation attempt.**

After a successful pair, X tries to connect as a known MCP with
X's extension identity. The MCP's server hello arrives → X sends
an extension hello with X's identity. The MCP-side WS server now
verifies the extension's session signature against the stored
`extensionIdentityEd25519Pub` for that MCP. Mismatch → close WS with
1008 + log security alert. (Implementation point: the trust check
lives on the MCP side, not the extension side — the extension can
verify the server's hello against its trust store, and the server can
verify the extension's hello against its.)

The MCP-side verification is implemented in the host's connection
handler. On extension-hello receipt, before sending its own hello:

```ts
if (server has a remembered extension identity from a previous pair) {
  verify(remembered_ext_ed_pub, mcpNonce || extNonce, extSessionSig);
  if (fail) → close ws, log security alert
}
```

The "remembered extension identity" lives in `Identity` on the MCP
disk file alongside the MCP's own keys. Updated on first successful
pair (signalled by an inbound `ready` frame).

**Trust-store tamper.**

If chrome.storage.local is tampered with, an attacker can already
load an arbitrary trust record. This is the existing chrome.storage
threat model — a compromised browser process can do anything. We are
not trying to defend against this; we're defending against
extension-pretending local processes.

## B. `read_indexed_db` capability (unblocks Resy)

Resy's auth bootstrap reads tokens from IndexedDB. Without a verb for
it, Resy migration to Pattern A stalls. Add:

**Capability:** `'read_indexed_db'` added to the union.

**Hello declaration:**

```jsonc
{
  "capabilities": ["read_indexed_db"],
  "indexedDbScopes": [
    {
      "origin": "https://resy.com",
      "database": "resy",
      "store": "auth",
      "keys": ["userToken", "userId"]
    }
  ]
}
```

Validator rules:

- `indexedDbScopes`: optional array of `IndexedDbScopeDecl`.
- `IndexedDbScopeDecl`: `{ origin: string; database: string; store: string; keys: string[] }`.
- `origin`: HTTPS bare origin (same shape as storage origin).
- `database`, `store`: 1–256 chars from `[A-Za-z0-9_.\-]`.
- `keys`: non-empty array of 1–256-char strings (same SCOPE_KEY_RE as
  storage keys), no duplicates within a scope.
- Empty array allowed (declares "no IDB reads"). Duplicate scopes (same
  origin/database/store/keys) are rejected.

**Inner request:**

```jsonc
{
  "type": "request",
  "id": 7,
  "op": "read_indexed_db",
  "init": {
    "origin": "https://resy.com",
    "database": "resy",
    "store": "auth",
    "keys": ["userToken"]
  }
}
```

Each call's `(origin, database, store, keys)` must be subset-matchable
to a declared scope: same origin/database/store, requested keys ⊆
declared keys.

**Inner response (ok):**

```jsonc
{
  "type": "response",
  "id": 7,
  "ok": true,
  "op": "read_indexed_db",
  "values": { "userToken": "ey..." }
}
```

`values` is `Record<string, unknown>` — values must be JSON-serializable
(plain objects, arrays, strings, numbers, booleans, null). If a value
isn't serializable (e.g. contains a Blob or a typed array), the
extension throws and the verb fails for that whole call. Missing
keys are omitted from the response.

**Extension implementation:**

Background-script handler opens the IDB via `indexedDB.open(database)`,
opens a readonly txn on `store`, calls `store.get(key)` per declared
key, awaits all, closes the DB, returns. No IndexedDB API permissions
needed (works from background-script context for cross-origin via
the cookies path? — actually IndexedDB is origin-bound so the lookup
must happen from a content-script context on a matching tab, same as
localStorage. Background can't see resy.com's IDB.)

So: extension background script sends a chrome.tabs.sendMessage to a
matching origin tab, content script opens IDB, reads keys, returns
values map. Mirror the localStorage path.

**Popup display:** add a sub-list under `Read IndexedDB`:

```
⚠ Read IndexedDB
  • resy/auth: userToken, userId
```

## C. JSON-pointer extraction in storage reads

HoneyBook's auth tokens live nested inside a single `localStorage`
value (`jStorage`, a 50KB JSON blob). Without JSON-pointer support
the MCP either fetches the whole 50KB and parses in Node, OR
declares each top-level key separately and parses in Node. With
JSON-pointer the bootstrap helper hands the MCP exactly the bits it
needs.

**Hello declaration extension:**

```jsonc
{
  "localStorageKeys": ["jStorage"],
  "localStoragePointers": [
    { "key": "jStorage", "jsonPointer": "/HB_AUTH_TOKEN" },
    { "key": "jStorage", "jsonPointer": "/HB_AUTH_USER_ID" },
    { "key": "jStorage", "jsonPointer": "/HB_CURR_USER/company/company_name" }
  ]
}
```

Same shape on `sessionStoragePointers`.

Validator rules:

- `localStoragePointers` / `sessionStoragePointers`: optional array,
  empty allowed.
- Each entry: `{ key: string, jsonPointer: string }`.
- `key` must be in declared `localStorageKeys` (resp. `sessionStorageKeys`).
- `jsonPointer` must match RFC 6901: starts with `/`, contains
  `/`-separated tokens. We support a conservative subset — tokens may
  contain `[A-Za-z0-9_\-.]` plus the escapes `~0` (for `~`) and `~1`
  (for `/`). Reject anything else.
- Duplicate `(key, jsonPointer)` rejected.

**Inner request init extension:**

```jsonc
{
  "op": "read_local_storage",
  "init": {
    "origin": "https://honeybook.com",
    "keys": ["jStorage"],
    "pointers": {
      "HB_AUTH_TOKEN":   { "storageKey": "jStorage", "jsonPointer": "/HB_AUTH_TOKEN" },
      "HB_AUTH_USER_ID": { "storageKey": "jStorage", "jsonPointer": "/HB_AUTH_USER_ID" }
    }
  }
}
```

`pointers` is `Record<string, { storageKey, jsonPointer }>`. The
output key (left side of the record) is what the response uses; the
storageKey + jsonPointer identifies the source.

Per-request pointers must each have a matching declared pointer
(`storageKey === decl.key`, `jsonPointer === decl.jsonPointer`).

**Inner response shape (unchanged at the protocol level):**

```jsonc
{
  "ok": true,
  "op": "read_local_storage",
  "values": {
    "HB_AUTH_TOKEN":   "ey...",
    "HB_AUTH_USER_ID": "u-123"
  }
}
```

Values are JSON-stringified versions of the pointer-extracted nodes
(strings, numbers, objects all become their JSON text). Missing
pointers (path doesn't resolve) → omitted from response (NOT an error
— consistent with missing-key handling for non-pointer reads).

**JSON-pointer evaluator:**

Tiny inline function, no new dep. Algorithm:

```ts
function evalJsonPointer(root: unknown, pointer: string): unknown {
  if (pointer === '') return root;
  if (!pointer.startsWith('/')) throw new Error('invalid pointer');
  const tokens = pointer.slice(1).split('/').map((t) =>
    t.replace(/~1/g, '/').replace(/~0/g, '~'),
  );
  let cur = root;
  for (const tok of tokens) {
    if (cur === null || cur === undefined) return undefined;
    if (Array.isArray(cur)) {
      const idx = Number(tok);
      if (!Number.isInteger(idx) || idx < 0 || idx >= cur.length) return undefined;
      cur = cur[idx];
    } else if (typeof cur === 'object') {
      const obj = cur as Record<string, unknown>;
      if (!(tok in obj)) return undefined;
      cur = obj[tok];
    } else {
      return undefined;
    }
  }
  return cur;
}
```

Lives in `packages/protocol/src/json-pointer.ts`. Used by the
extension content script when servicing pointer-extending storage
reads.

**Popup display:** sub-list shows `jStorage.HB_AUTH_TOKEN`,
`jStorage.HB_AUTH_USER_ID`, etc. — i.e. `storageKey` + the
slash-prefixed pointer with leading `/` rendered as `.`.

## D. Glob support in declared keys

Some declared key sets have repeated prefixes (HoneyBook ships
30+ `feh--*` cookies). Allow glob patterns in:

- `cookieKeys`
- `localStorageKeys`
- `sessionStorageKeys`

Glob rules:

- `*` matches any non-empty character sequence within a single key
  name. The match is over `/`-free, `;`-free, key-shape character
  classes.
- Patterns must have a non-empty literal prefix. `*foo` and bare `*`
  are rejected.
- Examples: `feh--*`, `auth_*`, `session.*` accept.
- Per-request keys must each be either an exact match to a declared
  literal OR match a declared glob.

Wire validation:

- `cookieKeys` entry `*foo` rejected (`hello.cookieKeys: glob pattern needs literal prefix`).
- Otherwise: same `SCOPE_KEY_RE` plus optional trailing `*`.

Extension trust matching:

- A declared list like `['hb_user_token', 'feh--*']` matches a
  per-request key `feh--12ab` (glob hit) or `hb_user_token` (literal
  hit). Comparison is case-sensitive.

Popup display: glob patterns shown literally (`feh--*`) — the user
sees the pattern they're approving.

## E. `@fetchproxy/bootstrap` ergonomics

**1. Auto disable env var.**

`bootstrap()` auto-checks an env var derived from `serverName`:
`${SERVER_NAME.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_DISABLE_FETCHPROXY`.
If set to any truthy value (`'1'`, `'true'`, anything non-empty),
`bootstrap()` immediately throws `BootstrapDisabledError`.

```ts
export class BootstrapDisabledError extends Error {
  constructor(serverName: string, envVar: string) {
    super(`fetchproxy bootstrap disabled by ${envVar}=1 (serverName: ${serverName})`);
    this.name = 'BootstrapDisabledError';
  }
}
```

Examples:

- `serverName: 'opentable-mcp'` → checks `OPENTABLE_MCP_DISABLE_FETCHPROXY`.
- `serverName: '@scope/honeybook-mcp'` → checks `SCOPE_HONEYBOOK_MCP_DISABLE_FETCHPROXY`.

Replaces the ad-hoc env-var plumbing in each downstream MCP.

**2. `onWaiting` callback.**

`BootstrapOpts` gains `onWaiting?: (hint: string) => void`. Fires
when a step would block on user interaction — primarily
`capture_request_header` since header capture only completes when
the user causes a matching request.

Hint shape: free-form human-readable string. Example:
`"waiting for next request to api.honeybook.com to capture hb-api-fingerprint — open the portal and click around"`.

Fires ONCE per capture decl, immediately before the capture call
goes out. After `bootstrap()` resolves or rejects, no further
callbacks.

**3. `onPairCode` callback.**

`BootstrapOpts` gains `onPairCode?: (code: string) => void`. Bridges
the new mutual-auth design (where the pair code can only be derived
after the extension hello arrives) into the existing `bootstrap()`
flow. MCPs that print the pair code to stderr should use this:

```ts
await bootstrap({
  ...,
  onPairCode: (code) => process.stderr.write(`PAIR CODE: ${code}\n`),
});
```

Without `onPairCode`, the pair code is silently consumed (only
visible in the popup); bootstrap still completes once the user
approves via the popup.

**4. Sharper error messages.**

When a declared key is missing from storage, OR a declared
captureHeader times out, OR a fetch returns sign-in HTML, the error
includes the actionable next step:

- `localStorage key "jStorage" not present — sign in to honeybook.com first`.
- `capture_request_header for hb-api-fingerprint timed out — open the portal and navigate to a panel that triggers an API call`.

Implementation point: error messages constructed in `bootstrap()`,
not down in the transport — transport-layer errors are too generic.

## F. Popup capability-diff display

On re-pair triggered by a scope change, the popup currently treats
the change identically to a fresh pair — same UI, no signal that
"the MCP previously had a smaller scope". This makes scope creep
hard to notice.

When `handleServerHello` returns `needs-pair` AND a trust record
already exists for the identity, the popup state gains a `previous`
field:

```ts
{
  mode: 'pending-pair',
  pending: { ... new scope ... },
  previous?: {
    capabilities: string[];
    cookieKeys: string[];
    localStorageKeys: string[];
    sessionStorageKeys: string[];
    captureHeaders: { urlPattern: string; headerName: string }[];
    indexedDbScopes: IndexedDbScopeDecl[];
    localStoragePointers: { key: string; jsonPointer: string }[];
    sessionStoragePointers: { key: string; jsonPointer: string }[];
  };
}
```

When `previous` is present, the popup heading changes to
"`<serverName>` wants to UPDATE its access to `<domain>`" and renders
three sub-lists:

- **Previously approved:** items in `previous`.
- **Now requesting (new):** items in `pending` but not in `previous`.
- **No longer requested:** items in `previous` but not in `pending`.

If a category is empty (e.g. nothing new), render `(none)`.

The `Approve` button label changes to `Approve update`. `Cancel`
stays. Clicking `Cancel` leaves the existing trust record in place
(MCP stays at its old scope until next re-pair attempt).

Implementation: `TrustRecord` gains an internal `lastScope` snapshot
that `popup.ts` reads when rendering the diff. `background.ts`
populates it on every successful pair.

## Implementation order

A → F. A is security; B and C are unblockers for Resy and HoneyBook
respectively; D is ergonomic; E is dev-experience; F is UX.

Each phase has a failing test first (TDD), then implementation, then
green. One commit per logical chunk.

## Versioning

- `@fetchproxy/protocol`: 0.3.0 → 0.4.0
- `@fetchproxy/server`: 0.3.0 → 0.4.0
- `@fetchproxy/extension-core`: 0.3.0 → 0.4.0
- `@fetchproxy/extension-chrome` (incl manifest.json): 0.3.0 → 0.4.0
- `@fetchproxy/bootstrap`: 0.3.0 → 0.4.0

Cross-package `dependencies` constraints (e.g. `@fetchproxy/server`'s
dependency on `@fetchproxy/protocol`) bump to `^0.4.0`. Once tagged
locally, the release workflow will publish all five together.

## Test baseline

341/341 vitest passing today. 0.4.0 adds protocol-validator tests
(~25), mutual-auth tests (~10), IDB tests (~8), JSON-pointer tests
(~12), glob tests (~10), bootstrap-env tests (~5), popup-diff tests
(~6), plus one new integration test (mutual-auth + read_indexed_db
end-to-end). Expected ballpark: 420+ tests.
