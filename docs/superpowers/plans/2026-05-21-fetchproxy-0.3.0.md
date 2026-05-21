# fetchproxy 0.3.0 — Session-Bootstrap Primitives Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add storage-extraction primitives + a shared bootstrap
helper so downstream MCPs can perform a one-shot session bootstrap and
then operate from Node directly. Wire-additive — 0.2.x consumers and
extensions interop with 0.3.0 unchanged.

**Tech Stack:** TypeScript, npm workspaces, vitest, esbuild,
Chrome Manifest V3.

**Spec:**
[`docs/superpowers/specs/2026-05-21-fetchproxy-0.3.0-design.md`](../specs/2026-05-21-fetchproxy-0.3.0-design.md).

---

## Phase A — Protocol additions

- [ ] **A1. Capability strings + `KNOWN_CAPABILITIES`.**
  - Extend `Capability` union in `packages/protocol/src/frames.ts` to
    add `read_local_storage`, `read_session_storage`,
    `capture_request_header`.
  - Update `KNOWN_CAPABILITIES` to match.
  - Failing test: `packages/protocol/tests/validate.test.ts` — a hello
    with the three new capabilities passes validation; a hello with an
    unknown capability still fails.
  - Implementation: edit `frames.ts`.

- [ ] **A2. Hello frame scope declarations.**
  - Add optional `cookieKeys`, `localStorageKeys`, `sessionStorageKeys`,
    `captureHeaders` fields on `HelloFrameFromServer`.
  - Add `CaptureHeaderDecl` interface (`{ urlPattern: string; headerName: string }`).
  - Failing tests in `validate.test.ts`:
    - hello carrying all four fields passes.
    - hello with only `localStorageKeys` passes (others default empty).
    - duplicate keys rejected (`hello.cookieKeys: duplicate "MTOKEN"`).
    - bad chars in key rejected (`hello.cookieKeys: invalid key`).
    - `captureHeaders` malformed entry rejected.
    - `captureHeaders` urlPattern with `*` in host (not path) rejected.
  - Implementation: extend `validateHello`.

- [ ] **A3. New inner-request init shapes.**
  - Add `ReadStorageInit` (`{ origin: string; keys: string[] }`).
  - Add `CaptureRequestHeaderInit` (`{ urlPattern: string; headerName: string; timeoutMs?: number }`).
  - Add `InnerRequestReadLocalStorage`, `InnerRequestReadSessionStorage`,
    `InnerRequestCaptureRequestHeader` types.
  - Extend `InnerRequest` discriminated union.
  - Failing tests in `validate.test.ts` for each new op:
    - happy-path valid.
    - missing `origin` rejected.
    - non-array `keys` rejected.
    - empty `keys` rejected.
    - duplicate keys rejected.
    - http (non-https) `origin` rejected for storage reads (cross-origin
      storage attack surface — refuse plaintext origins).
    - `capture_request_header` missing `urlPattern` rejected.
    - `timeoutMs` non-positive-integer rejected.
  - Implementation: extend `validateInnerRequest`.

- [ ] **A4. New inner-response ok shapes.**
  - `InnerResponseReadLocalStorageOk` (`{ ok: true; op: 'read_local_storage'; values: Record<string, string> }`).
  - `InnerResponseReadSessionStorageOk` (same shape, different op).
  - `InnerResponseCaptureRequestHeaderOk` (`{ ok: true; op: 'capture_request_header'; value: string }`).
  - Extend `InnerResponseOk` union.
  - Failing tests in `validate.test.ts`:
    - happy-path each new op.
    - `values` non-plain-object rejected.
    - `values` entry with non-string rejected.
    - `value` non-string rejected for capture op.
  - Implementation: extend `validateInnerResponse`.

- [ ] **A5. `read_cookies` shape upgrade (back-compat).**
  - New request init shape: `{ origin: string; keys: string[] }`.
  - New response shape: `{ ok: true; op: 'read_cookies'; values: Record<string, string> }`.
  - Validator accepts EITHER the legacy `tabUrl`-only shape OR the new
    `origin+keys` shape on requests; legacy `cookies: string` OR new
    `values: Record<string, string>` on responses.
  - Failing tests:
    - new request shape passes.
    - new response shape passes.
    - legacy 0.2.0 request still passes (no regression).
    - legacy 0.2.0 response still passes (no regression).
    - mixed shape (`origin` AND `tabUrl` on the same request) rejected.
  - Implementation: extend the `read_cookies` branches in
    `validateInnerRequest` / `validateInnerResponse`.

## Phase B — Server side

- [ ] **B1. `FetchproxyServer` opts: declared scope fields.**
  - Add `cookieKeys`, `localStorageKeys`, `sessionStorageKeys`,
    `captureHeaders` to `FetchproxyServerOpts`.
  - Each defaults to `[]` when absent.
  - `buildServerHello` includes them (only when non-empty, to keep the
    wire compact for the fetch-only common case).
  - Failing test in `packages/server/tests/host.test.ts` or a new file:
    when a server declares `localStorageKeys: ['auth']`, the hello frame
    on the wire carries them.
  - Implementation: thread through `FetchproxyServerOpts → ResolvedOpts → buildServerHello`.

- [ ] **B2. `FetchproxyServer.readCookies` upgrade.**
  - New signature: `readCookies(opts: { domain?: string; subdomain?: string; keys: string[] })`.
  - Returns `Record<string, string>` (not raw string).
  - Validates `keys` ⊆ declared `cookieKeys` at the call site; throws
    if not.
  - Emits inner request with new shape: `{ origin, keys }`.
  - Failing tests in `packages/server/tests/convenience.test.ts`:
    - new signature happy-path.
    - missing key in declared `cookieKeys` throws clearly.
    - `cookieKeys: []` with non-empty `keys` arg throws.
    - missing `read_cookies` capability still throws (existing guard).
  - Backward-compat: tag the existing `readCookies(): Promise<string>`
    overload as a deprecation-friendly shim that requires the legacy
    constructor path. We won't ship the legacy string shape in the new
    API surface; downstream MCPs on 0.2.x keep using the 0.2.x package
    version.
  - Implementation: edit `ws-server.ts`.

- [ ] **B3. `FetchproxyServer.readLocalStorage` + `readSessionStorage`.**
  - New methods mirroring `readCookies` shape.
  - Each requires the respective capability declared.
  - Each validates `keys` ⊆ declared keys at the call site.
  - Failing tests in `convenience.test.ts`:
    - happy-path stores returned.
    - bad key throws.
    - missing capability throws.
    - empty declared list + non-empty keys throws.
  - Implementation: extend `ws-server.ts` with shared helpers.

- [ ] **B4. `FetchproxyServer.captureRequestHeader`.**
  - New method: `captureRequestHeader(opts: { urlPattern: string; headerName: string; timeoutMs?: number })`.
  - Validates exact `(urlPattern, headerName)` match in declared
    `captureHeaders` array.
  - Returns the captured string value (not wrapped).
  - Failing tests in `convenience.test.ts`:
    - happy-path returns the captured value.
    - undeclared pair throws.
    - timeout response surfaces as `FetchproxyProtocolError('timeout')`.
  - Implementation: extend `ws-server.ts`.

- [ ] **B5. End-to-end integration test through real WS.**
  - New file: `packages/server/tests/integration/all-bootstrap-verbs.test.ts`.
  - Mock-extension responds to `read_cookies`, `read_local_storage`,
    `read_session_storage`, and `capture_request_header` in turn.
  - Asserts:
    - declared scope makes it onto the hello frame.
    - each verb round-trips through the real WS server.
    - the new `values`/`value` payload shapes are reconstructed.
  - Mirrors `read-cookies.test.ts` structure.

- [ ] **B6. `@fetchproxy/bootstrap` package skeleton.**
  - New workspace package at `packages/bootstrap/` with `package.json`,
    `tsconfig.json`, `src/index.ts`, `tests/bootstrap.test.ts`.
  - Depends on `@fetchproxy/server` ^0.3.0 and `@fetchproxy/protocol` ^0.3.0.
  - Public exports: `bootstrap`, `Session`, `BootstrapOpts`, `Declarations`.
  - Capability set is derived from non-empty buckets (see spec).
  - Failing tests:
    - empty declarations → all four returned buckets are `{}`.
    - non-empty `cookies` declaration → cookies are read; capability
      `read_cookies` is emitted.
    - the helper closes the underlying `FetchproxyServer` even when one
      of the reads throws (use a try/finally — tested with a stub
      `FetchproxyServer` impl injected via dependency).
  - Implementation: thin orchestrator (~30 lines) + types.
  - Mock the underlying `FetchproxyServer` via a constructor option so
    we don't need a live WS to exercise this layer.

## Phase C — Extension side

- [ ] **C1. Manifest permissions.**
  - Add `cookies`, `webRequest` to `packages/extension-chrome/manifest.json`.
  - No test (manifest); covered by a snapshot assertion if needed —
    keep this commit minimal.

- [ ] **C2. Trust record + trust-store scope fields.**
  - Extend `TrustRecord` in `packages/extension-core/src/trust-store.ts`
    with the four scope arrays.
  - `TrustStore.get` normalizes missing fields to `[]`.
  - `sameScopeSet` helper for set-equality on `captureHeaders` (compare
    by `urlPattern + ":" + headerName` canonical strings).
  - Failing tests in `trust-store.test.ts`:
    - pre-0.3.0 records normalize to empty scope arrays.
    - new records round-trip the scope fields.

- [ ] **C3. `handleServerHello` scope-aware re-pair.**
  - When a stored record exists, compare declared scope arrays
    set-wise; any difference → `needs-pair`.
  - `HandleHelloResult` (`auto-trust` / `needs-pair`) gains the four
    new arrays so the popup can render them.
  - Failing tests in `background.test.ts`:
    - identical hello scope → `auto-trust`.
    - new key appears → `needs-pair`.
    - new captureHeader appears → `needs-pair`.
    - permutation of same set → still `auto-trust`.

- [ ] **C4. Per-mcpId scope tables.**
  - Extension's request handler needs four new lookup tables matching
    `mcpDomains` / `mcpCapabilities`:
    `mcpCookieKeys`, `mcpLocalStorageKeys`, `mcpSessionStorageKeys`,
    `mcpCaptureHeaders`.
  - Populated on `auto-trust` and `onApproval`.
  - Cleared on WS close (same as the existing tables).
  - Failing tests in `background.test.ts`:
    - on a successful pair, scope tables are populated.
    - on disconnect, tables are cleared.

- [ ] **C5. `read_local_storage` + `read_session_storage` handlers.**
  - Background-script `handleReadLocalStorageRequest(mcpId, req, declared)`:
    - reject if `origin`'s host isn't in declared domains.
    - reject if any `req.init.keys` entry isn't in `mcpLocalStorageKeys`.
    - find a tab matching `${origin}/` (existing `isTabUrlMatch`).
    - send `{ kind: 'fetchproxy-read-local-storage', keys }` to content script.
    - relay response.
  - Same for session storage.
  - Content script (`content.ts`): handle both message kinds, read
    `localStorage.getItem(k)` / `sessionStorage.getItem(k)` for each
    key; null values are omitted from the returned object.
  - Failing tests:
    - `background.test.ts`: happy-path round-trip via the fake-chrome
      stubs already in place.
    - undeclared key rejected at the extension boundary.
    - undeclared origin rejected.

- [ ] **C6. `read_cookies` upgrade (extension side).**
  - Background-script `handleReadCookiesRequest` learns the new shape:
    when `req.init.keys` is present, call `chrome.cookies.get` for each
    key (scoped by the origin's URL/host) and return a `values` map.
  - When `req.init.tabUrl` is present without `keys`, fall back to the
    legacy `document.cookie` path through the content script.
  - Refresh the chrome stub in tests with a `chrome.cookies.get` mock
    so the new code path is exercised.
  - Failing tests in `background.test.ts`:
    - new shape with declared keys returns a map.
    - keys outside declared set rejected.
    - legacy shape still works (back-compat smoke).
  - Note: HttpOnly cookies become visible — call this out in a
    comment, not a test (the mock can't easily simulate the browser's
    HttpOnly bit, and the test would be testing chrome rather than us).

- [ ] **C7. `capture_request_header` handler.**
  - Background-script `handleCaptureRequestHeaderRequest`:
    - reject if `(urlPattern, headerName)` isn't in declared `captureHeaders`.
    - resolve `urlPattern` to a Chrome match-pattern (we already use
      `<all_urls>` host permission, so any https path is fine).
    - register a one-shot `chrome.webRequest.onBeforeSendHeaders`
      listener filtered to that URL.
    - on first match: pull the named header, remove the listener,
      respond.
    - on timeout (default 30s, overridable via `timeoutMs`): remove
      listener, respond `{ ok: false, op, error: 'timeout' }`.
  - Failing tests in `background.test.ts`:
    - listener registered, fires, returns value, removes itself.
    - timeout fires when no matching request arrives.
    - undeclared pair rejected before any listener registration.
    - listener removed if MCP disconnects mid-wait.

- [ ] **C8. Popup updates.**
  - `PendingPair` type gains the four scope arrays.
  - `renderPopup` renders sub-lists per capability:
    `Read cookies: A, B, C`
    `Read localStorage: X, Y`
    `Read sessionStorage: ...`
    `Capture request header "H" from <urlPattern>` (one line per entry).
  - The `cap-warn` class applies to every elevated-trust line.
  - Failing tests in `popup.test.ts`:
    - all four sub-lists rendered when present.
    - sub-lists omitted when their array is empty (so a fetch-only MCP
      still renders cleanly).
    - capture-header entries each on their own line.
  - Bootstrap reads `pendingPair.{cookieKeys,localStorageKeys,sessionStorageKeys,captureHeaders}`
    from chrome storage and threads through.

- [ ] **C9. Wildcard domain regression.**
  - New tests in `packages/extension-core/tests/url-match.test.ts`:
    - `a.b.c.instructure.com` matches `instructure.com`.
    - `instructure.com` itself matches.
    - `othersite.com` doesn't.
  - No code change expected — assertion-only test confirming the
    existing behavior, which is the regression net Canvas needs.

## Phase D — Cross-package smoke

- [ ] **D1. Bootstrap helper end-to-end test.**
  - Already covered by B6 with stub injection.
  - Add a second test in `packages/bootstrap/tests/` that drives
    bootstrap against a real `FetchproxyServer` + mock extension, all
    four buckets non-empty, asserting the returned `Session` has the
    expected shape. Skip if it would duplicate B5 — keep coverage
    proportional.

## Phase E — Bump + tag

- [ ] **E1. Version bumps in all four existing packages.**
  - `protocol/package.json`, `server/package.json`,
    `extension-core/package.json`, `extension-chrome/package.json` →
    `0.3.0`.
  - `extension-chrome/manifest.json` → `0.3.0`.
  - `package-lock.json` regenerated (`npm install --package-lock-only`).
  - One commit.

- [ ] **E2. `@fetchproxy/bootstrap` first publish version.**
  - `packages/bootstrap/package.json` → `0.3.0`.
  - Cross-package dep ranges updated to `^0.3.0`.
  - One commit (if not already in B6).

- [ ] **E3. Final `npm test` — confirm all green.**
  - Verification step before tagging.

- [ ] **E4. Annotated tag.**
  - `git tag -a v0.3.0 -m "0.3.0: session-bootstrap primitives"`.
  - Do NOT push.

## Done

- 244 + N tests green.
- Tag `v0.3.0` present locally.
- No push, no publish.
