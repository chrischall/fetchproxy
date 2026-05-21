# fetchproxy 0.3.0 — Session-Bootstrap Primitives

**Status:** Approved 2026-05-21. Implementation begins immediately.

## Goal

Enable the "Pattern A" migration for downstream MCPs: call fetchproxy
once at startup, extract the user's signed-in session state (cookies,
localStorage values, captured request headers), then run all subsequent
API calls directly from Node with `fetch()`. fetchproxy stops being in
the hot path for these MCPs — it's a one-shot credential bootstrap, not
a per-request relay.

Seven of nine downstream MCPs surveyed (OFW, HoneyBook, Credit Karma,
Canvas, Splitwise, Zola, …) fit Pattern A — they authenticate via a
signed-in browser tab, then talk to public-ish JSON APIs that accept
bearer tokens or cookies directly. 0.3.0 gives all of them the same
30-line bootstrap helper instead of seven bespoke "scrape my cookies"
hacks.

## What this is NOT

- Not a breaking change. 0.2.x MCPs (single `fetch` capability, or
  `fetch + read_cookies` with the 0.2.0 cookie shape) continue to work
  on a 0.3.0 extension untouched. Hello frames just gain optional
  fields; old senders omit them, old validators reject unknown verbs,
  and the new verbs are gated through `capabilities`.
- Not a wire-protocol version bump. `PROTOCOL_VERSION` stays at `1`.
  All additions are wire-additive within v1.
- Not a port change. Still `127.0.0.1:37149` by default.

## Wire changes (additive)

### Hello frame from server

Two existing fields (`capabilities`, `domains`) carry over unchanged.
Four new optional fields declare the per-capability scope:

```jsonc
{
  "type": "hello",
  "protocolVersion": 1,
  "role": "server",
  "mcpId": "...",
  "serverName": "ofw-mcp",
  "version": "0.5.0",
  "domains": ["ourfamilywizard.com"],
  "capabilities": ["read_cookies", "read_local_storage", "capture_request_header"],

  // NEW in 0.3.0:
  "cookieKeys": ["MTOKEN", "CKAT", "usr"],
  "localStorageKeys": ["auth", "tokenExpiry"],
  "sessionStorageKeys": [],
  "captureHeaders": [
    { "urlPattern": "https://api.honeybook.com/api/v2/*", "headerName": "hb-api-fingerprint" }
  ],

  "identityX25519Pub": "...",
  "identityEd25519Pub": "...",
  "sessionNonce": "...",
  "sessionSig": "..."
}
```

Constraints (validator-enforced):

- `cookieKeys`, `localStorageKeys`, `sessionStorageKeys`: optional arrays
  of strings. Each string is 1–256 chars from `[A-Za-z0-9_\-\.]`. Empty
  array is allowed (declares "no keys"). Order is not significant.
  Duplicates are rejected.
- `captureHeaders`: optional array of `{ urlPattern, headerName }`
  objects. `urlPattern` is a `https://host/path` string with `*`
  wildcards permitted in the path segment only. `headerName` is a
  single HTTP header name (`[A-Za-z0-9\-_]+`, 1–128 chars). Empty array
  is allowed. No dupes per `(urlPattern, headerName)` pair.
- All four fields default to `[]` when absent.

### Capability strings

The `Capability` union gains three entries:

```
'fetch'                  (existing)
'read_cookies'           (existing — upgraded; see below)
'read_local_storage'     (NEW)
'read_session_storage'   (NEW)
'capture_request_header' (NEW)
```

`KNOWN_CAPABILITIES` is updated to match.

### Inner-frame verbs

Three new inner-request `op` values, each with its own `init` shape.

```jsonc
// read_local_storage / read_session_storage init:
{ "origin": "https://www.ourfamilywizard.com", "keys": ["auth", "tokenExpiry"] }

// capture_request_header init:
{
  "urlPattern": "https://api.honeybook.com/api/v2/*",
  "headerName": "hb-api-fingerprint",
  "timeoutMs": 30000
}
```

Response shapes:

```jsonc
// read_local_storage / read_session_storage success:
{
  "type": "response", "id": 7, "ok": true,
  "op": "read_local_storage",
  "values": { "auth": "ey...", "tokenExpiry": "1730000000000" }
}

// capture_request_header success:
{ "type": "response", "id": 8, "ok": true, "op": "capture_request_header", "value": "abc123..." }
```

Failure shape is the existing union: `{ ok: false, op?: Capability, error: string }`.

### `read_cookies` upgrade

Existing `read_cookies` keeps its inner op name, but the wire shape
changes from "raw `document.cookie` string" to "map of requested keys
to values":

**0.2.0 (deprecated, kept for back-compat on 0.3.0 extensions):**
```jsonc
{ "op": "read_cookies", "init": { "tabUrl": "https://x.com/" } }
// → { ok: true, op: "read_cookies", "cookies": "k1=v1; k2=v2" }
```

**0.3.0:**
```jsonc
{ "op": "read_cookies", "init": { "origin": "https://www.x.com", "keys": ["MTOKEN", "CKAT"] } }
// → { ok: true, op: "read_cookies", "values": { "MTOKEN": "ey...", "CKAT": "abc" } }
```

The validator accepts both inner-request shapes; the extension picks
the new shape when `keys` is present and uses the legacy code path when
`tabUrl` is present without `keys`. New `FetchproxyServer.readCookies(...)`
API only emits the new shape.

The backing implementation also changes: the 0.3.0 extension reads via
`chrome.cookies.get` (which sees HttpOnly cookies), not
`document.cookie`. This is the whole point of the upgrade — HoneyBook's
`hb_user_token` (the bearer-equivalent) is HttpOnly, and is invisible
under 0.2.0.

### `capture_request_header` semantics

The extension registers a `chrome.webRequest.onBeforeSendHeaders`
listener scoped to the declared `urlPattern`. The next outgoing request
matching the pattern surfaces its `headerName` value, the listener is
removed, and the response resolves. If `timeoutMs` (default 30000)
elapses without a match, the listener is removed and the response is
`{ ok: false, op: "capture_request_header", error: "timeout" }`.

Only the first match is returned. Concurrent capture requests on the
same pattern run independently (each MCP gets its own listener).

## Server-side enforcement (security gate #1)

`FetchproxyServer` rejects requests whose arguments fall outside the
declared scope, before the inner frame goes on the wire:

- `readCookies({ keys })`: every entry in `keys` must be in
  `cookieKeys`. Otherwise throw at the call site:
  `FetchproxyServer.readCookies: key "X" not in declared cookieKeys`.
- `readLocalStorage({ keys })`: same against `localStorageKeys`.
- `readSessionStorage({ keys })`: same against `sessionStorageKeys`.
- `captureRequestHeader({ urlPattern, headerName })`: must exactly
  match one of the entries in `captureHeaders`. (We don't try to be
  clever about "is this urlPattern a subset of a declared one" — exact
  string match keeps the trust boundary auditable.)

These guards predate the WS send so a misdeclared MCP gets a clear
stack trace at the offending call, not a generic transport error.

## Extension-side enforcement (security gate #2)

The extension re-checks every inbound inner request against the
trusted scope (which is what the user actually approved). Same checks
as server-side, but the failure mode is `{ ok: false, op, error: "..." }`
on the wire rather than throwing.

Re-checking on both sides isn't redundant: server-side catches bugs in
the MCP author's code, extension-side catches a compromised /
misbehaving server library trying to escalate beyond what the user
approved. Each side independently enforces the boundary.

## Trust prompt UI

The popup itemizes the declared scope so the user can see exactly what
they're approving. Example for ofw-mcp:

```
ofw-mcp wants to access ourfamilywizard.com
  - HTTP fetches
  - Read localStorage: auth, tokenExpiry
```

Example for honeybook-mcp:

```
honeybook-mcp wants to access honeybook.com, hbportal.co
  - HTTP fetches
  - Read cookies: hb_user_token, hb_session
  - Read localStorage: jStorage
  - Capture request header "hb-api-fingerprint" from api.honeybook.com/api/v2/*
```

Capability lines that involve elevated trust (anything reading
storage or sniffing request headers) get a `cap-warn` class so the
popup CSS can highlight them. The existing `read_cookies` warning
treatment carries over to the three new entries.

## Trust storage

`TrustRecord` gains the same four fields as the hello frame, keyed
under the same names:

```ts
interface TrustRecord {
  serverName: string;
  domains: string[];
  capabilities: string[];
  cookieKeys: string[];           // NEW
  localStorageKeys: string[];     // NEW
  sessionStorageKeys: string[];   // NEW
  captureHeaders: { urlPattern: string; headerName: string }[]; // NEW
  identityX25519Pub: string;
  identityEd25519Pub: string;
  pairedAt: number;
  extensionVersionAtPair: string;
}
```

Comparison is order-insensitive (same as `domains` and `capabilities`
today). Any difference between the stored scope and a new hello's
declared scope triggers re-pair, same conservative policy as the
existing capability-set change.

Pre-0.3.0 trust records lacking the new fields are normalized on read
to `[]`/`[]`/`[]`/`[]` so a 0.2.x record without storage scope keeps
working with the existing `fetch + read_cookies` setup.

## Manifest permissions

`packages/extension-chrome/manifest.json` gains two permissions:

- `cookies` — required for `chrome.cookies.get`, which is what backs
  the upgraded `read_cookies` verb (HttpOnly-visible).
- `webRequest` — required for `chrome.webRequest.onBeforeSendHeaders`,
  the backbone of `capture_request_header`.

`<all_urls>` host permission is already declared, which is what both
of these APIs need to operate cross-origin.

We deliberately do NOT add `webRequestBlocking` or `declarativeNetRequest`
— `capture_request_header` is read-only ("watch and report"), not
intercept-and-mutate, so the basic `webRequest` permission is enough.
The user's pair-approval is what gates which `urlPattern`s the
extension is willing to listen on.

## @fetchproxy/bootstrap (new package)

A thin helper package (`@fetchproxy/bootstrap`, first publish at
0.3.0) that wraps the lifecycle for Pattern A consumers. Public API:

```ts
import { bootstrap, type Session } from '@fetchproxy/bootstrap';

const session: Session = await bootstrap({
  serverName: 'ofw-mcp',
  version: '0.5.0',
  domains: ['ourfamilywizard.com'],
  declare: {
    cookies: [],                              // cookieKeys
    localStorage: ['auth', 'tokenExpiry'],    // localStorageKeys
    sessionStorage: [],
    captureHeaders: [],
  },
});

// session: {
//   cookies: Record<string, string>,
//   localStorage: Record<string, string>,
//   sessionStorage: Record<string, string>,
//   capturedHeaders: Record<string, string>,  // keyed by headerName
// }
```

Internally it:

1. Constructs a `FetchproxyServer` with the declared scope mapped onto
   the right opts (capabilities derived from which buckets are
   non-empty).
2. Calls `listen()`.
3. Reads each declared bucket sequentially: `readCookies`,
   `readLocalStorage`, `readSessionStorage`, then for each capture
   header `captureRequestHeader`. Empty buckets are skipped.
4. Calls `close()`.
5. Returns the captured blob.

~30 lines plus types. The MCP imports just `bootstrap` and `Session` —
it never sees `FetchproxyServer`.

The capability-derivation logic is explicit so the user sees in the
TypeScript that empty declarations don't pull in capabilities they
didn't ask for:

```ts
const capabilities: Capability[] = ['fetch']; // always; could be unused
if (declare.cookies.length > 0) capabilities.push('read_cookies');
if (declare.localStorage.length > 0) capabilities.push('read_local_storage');
if (declare.sessionStorage.length > 0) capabilities.push('read_session_storage');
if (declare.captureHeaders.length > 0) capabilities.push('capture_request_header');
```

If ALL declarations are empty, bootstrap just verifies the bridge is
healthy and returns `{ cookies: {}, localStorage: {}, sessionStorage: {}, capturedHeaders: {} }`.
(Pointless but well-defined.)

## Wildcard domain (regression coverage)

The existing `domains: ['instructure.com']` declaration already
matches `*.instructure.com` per `assertSubdomainLabel` + the URL host
check in `isUrlAllowedForAnyDomain`. We add a regression test that
arbitrary-depth subdomains work — Canvas serves
`a.b.c.instructure.com`-style observer endpoints — and that the
extension-side `isUrlAllowedForAnyDomain` agrees.

## Versioning

- `@fetchproxy/protocol` 0.2.2 → 0.3.0
- `@fetchproxy/server` 0.2.2 → 0.3.0
- `@fetchproxy/extension-core` 0.2.2 → 0.3.0
- `@fetchproxy/extension-chrome` 0.2.2 → 0.3.0 (`manifest.json` + `package.json`)
- `@fetchproxy/bootstrap` 0.3.0 (first publish)

Tag `v0.3.0` annotated, locally. Push and publish happen in a
follow-up workflow run.

## Out of scope (deliberately)

- Form-fill / DOM scraping. Pattern A is auth bootstrap; if a user
  needs page-content extraction they can use the existing `fetch`
  capability to GET the page and parse server-side.
- Persistent storage on the extension side. Captured values are
  returned to the MCP caller and forgotten by the extension. The MCP
  owns its session blob and refreshes via re-bootstrap.
- Per-key value sanitization / redaction in the popup. The user
  approves the *names* of keys/headers, not the values. Showing values
  in a popup would itself be a leakage risk.
