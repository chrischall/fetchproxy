# fetchproxy 0.4.0 — Mutual Auth + Ergonomics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the MITM-as-extension authentication gap, add
`read_indexed_db`, add JSON-pointer extraction in storage reads, allow
glob patterns in declared keys, polish `@fetchproxy/bootstrap`
ergonomics, and add capability-diff display on re-pair.

**Tech Stack:** TypeScript, npm workspaces, vitest, esbuild, Chrome
Manifest V3.

**Spec:**
[`docs/superpowers/specs/2026-05-21-fetchproxy-0.4.0-design.md`](../specs/2026-05-21-fetchproxy-0.4.0-design.md).

**Wire-protocol break:** `PROTOCOL_VERSION` bumps 1 → 2. 0.3.0 ↔ 0.4.0
NOT interoperable; all packages release together.

---

## Phase A — Mutual authentication (the MITM fix)

- [ ] **A1. PROTOCOL_VERSION bump.**
  - Edit `packages/protocol/src/frames.ts`: change `PROTOCOL_VERSION`
    from `1` to `2`. Update the `HelloFrameFromServer` and
    `HelloFrameFromExtension` interfaces' `protocolVersion: 1` to
    `protocolVersion: 2`.
  - Failing tests in `validate.test.ts`:
    - hello with `protocolVersion: 1` rejected.
    - hello with `protocolVersion: 2` (plus all required fields)
      accepted.
  - Update all existing tests' fixture frames from `protocolVersion: 1`
    to `2`.
  - Implementation: edit `frames.ts` constant + validator error msg.

- [ ] **A2. Extension hello carries identity + signature.**
  - Extend `HelloFrameFromExtension` with `identityX25519Pub`,
    `identityEd25519Pub`, `sessionNonce`, `sessionSig` (all base64
    strings).
  - Failing tests in `validate.test.ts`:
    - hello missing `identityX25519Pub` rejected.
    - hello missing `sessionNonce` rejected.
    - hello with all four fields present accepted.
    - non-base64 sessionSig rejected.
  - Implementation: extend `validateHello` for `role === 'extension'`.

- [ ] **A3. `loadOrCreateExtensionIdentity` helper.**
  - New file `packages/extension-core/src/extension-identity.ts` with
    function reading/writing `extensionIdentity` in
    `chrome.storage.local`. Reuses `generateX25519` /
    `generateEd25519` and base64 encode/decode.
  - Failing tests in `extension-identity.test.ts` (new):
    - first call generates + persists fresh identity.
    - second call returns same identity.
    - identity has 32-byte raw priv + pub for both algorithms.
    - `createdAt` populated on first call only.
  - Implementation: factor on `TrustStore`'s storage shape.

- [ ] **A4. Extension sends identity-bearing hello on demand.**
  - Adjust `connect()` in `background.ts`: do NOT send extension hello
    on `open`. Instead, wait for the MCP's server hello to arrive in
    `onServerHello`, then construct + send the extension hello with
    fresh session nonce + signature over `mcpHelloSessionNonce || extSessionNonce`.
  - Add `pendingHellos: Map<mcpId, sessionNonce>` keyed by mcpId so
    the extension can sign one hello per MCP (relevant for multi-MCP).
  - Failing test in `background.test.ts`:
    - mock storage + identity, send a synthetic server hello,
      observe the extension hello includes identity pubs + a signature
      that verifies against the stored ed25519 pub.
  - Implementation: thread the new identity through `onServerHello`
    and `connect`.

- [ ] **A5. Pair code binds both identities.**
  - Add `derivePairCodeFromIds(mcpPub: Uint8Array, extPub: Uint8Array)`
    in `packages/protocol/src/pair-code.ts`. Keep the existing
    `derivePairCode(pub)` for the unit test of the SHA-256 path.
  - Failing tests in `pair-code.test.ts`:
    - two different `(mcpPub, extPub)` pairs produce different codes.
    - swapping the order produces a different code.
    - same inputs → same code.
  - Implementation: `derivePairCodeFromIds(a, b)` returns
    `derivePairCode(concatBytes(a, b))`.

- [ ] **A6. `handleServerHello` derives pair code from concat.**
  - Update `packages/extension-core/src/background.ts:handleServerHello`
    to (1) load the extension's identity from `loadOrCreateExtensionIdentity`
    (pass via `HandleHelloDeps`), (2) compute pair code via
    `derivePairCodeFromIds(mcpPub, extPub)`.
  - Failing tests in `background.test.ts`:
    - given fixed mcp identity + fixed extension identity, pair code
      matches expected derivation.
    - different extension identity → different pair code.
  - Implementation: thread `extensionIdentityX25519Pub` into `HandleHelloDeps`.

- [ ] **A7. Trust record stores extension identity.**
  - Extend `TrustRecord` and `TrustInput` interfaces in
    `trust-store.ts`: add `extensionIdentityX25519Pub` and
    `extensionIdentityEd25519Pub` (base64 strings).
  - Treat records missing these fields as null (force re-pair).
  - Failing tests in `trust-store.test.ts`:
    - record with new fields persists + retrieves intact.
    - record missing `extensionIdentityX25519Pub` returns null on get.
  - Implementation: extend `TrustStore.get/put` shapes + normalization.

- [ ] **A8. Auto-trust verifies extension session signature.**
  - In `handleServerHello`, when a trust record exists and the
    server-side fields match, ALSO verify the inbound hello's
    `sessionSig` against the stored `extensionIdentityEd25519Pub` —
    but wait, the *extension* is on the receiving side. Actually:
    the extension verifies the MCP's signature (already done) AND
    on auto-trust path, generates its own signed hello using stored
    extension identity.
  - The MCP-side verification of extension signature lives on the
    server (`host.ts`): on extension-hello receipt, if the server has
    a "remembered extension identity" for this MCP (loaded from disk),
    verify the hello's `sessionSig` against that pub. Mismatch → close
    1008.
  - Failing tests in `host.test.ts`:
    - extension hello with valid `sessionSig` proceeds normally.
    - extension hello with invalid signature → WS closed with 1008.
    - host with no remembered extension identity (first pair) accepts
      any extension hello with a valid self-signature.
  - Implementation: persist + load `extensionIdentityX25519Pub` /
    `extensionIdentityEd25519Pub` in `Identity` (server-side JSON
    file), reuse `ed25519Verify`.

- [ ] **A9. MCP-side pair-code reporting via `onPairCode`.**
  - Add `onPairCode(cb)` method on `FetchproxyServer` AND
    `BootstrapOpts.onPairCode`. The MCP-side derives the pair code on
    receipt of the extension hello (post-A8 changes) and fires the
    callback once per pair.
  - Failing tests:
    - `ws-server.test.ts` (or new `pair-code.test.ts`): mock-host
      receives extension hello → `onPairCode` fires with the joint
      code.
    - `bootstrap.test.ts`: when `onPairCode` provided, called with the
      code from the stubbed server.
  - Implementation: thread the callback through `FetchproxyServer` →
    `host.ts`. Host computes pair code = `derivePairCodeFromIds(mcpPub, extPub)`
    once the extension hello arrives.

- [ ] **A10. Popup shows extension identity fingerprint.**
  - Add `extensionFingerprint: string` to `PopupState` for both
    `status` and `pending-pair` modes. Format: `XXXX-XXXX` (first
    4 bytes of SHA256(extX25519Pub) as hex, with dash in middle).
  - Failing tests in `popup.test.ts`:
    - status mode renders fingerprint.
    - pending-pair mode renders fingerprint.
  - Implementation: derive in popup bootstrap, render under header.

- [ ] **A11. Migration: 0.3.0 trust records become null.**
  - `TrustStore.get()` treats records missing
    `extensionIdentityX25519Pub` as `null`. (Same mechanism as A7.)
  - Failing test:
    - persist a 0.3.0-shaped record (no extension identity fields) →
      get returns null.
  - Implementation: A7's normalization already covers this — verify
    the test passes.

## Phase B — `read_indexed_db` capability

- [ ] **B1. Capability + scope decl in protocol.**
  - Add `'read_indexed_db'` to `Capability` union + `KNOWN_CAPABILITIES`.
  - Add `IndexedDbScopeDecl` interface: `{ origin, database, store, keys }`.
  - Add `indexedDbScopes?: IndexedDbScopeDecl[]` on `HelloFrameFromServer`.
  - Failing tests in `validate.test.ts`:
    - hello with `indexedDbScopes` passes.
    - hello with empty `indexedDbScopes` passes.
    - duplicate scope rejected.
    - bad chars in `database` / `store` rejected.
    - non-https `origin` rejected.
    - missing `keys` rejected.
  - Implementation: extend validator.

- [ ] **B2. Inner request + response shapes.**
  - Add `ReadIndexedDbInit`, `InnerRequestReadIndexedDb`,
    `InnerResponseReadIndexedDbOk` types.
  - Extend `InnerRequest` / `InnerResponseOk` unions.
  - Failing tests in `validate.test.ts`:
    - valid request accepted.
    - request with extra fields rejected.
    - response with non-plain `values` rejected.
    - response values may carry any JSON type (string/number/bool/obj/arr/null).
  - Implementation: extend `validateInnerRequest` / `validateInnerResponse`.

- [ ] **B3. `FetchproxyServer.readIndexedDb()` method.**
  - Add method signature `readIndexedDb({ origin?, subdomain?, database, store, keys })` resolving `Record<string, unknown>`.
  - Subset-check requested `(database, store, keys)` against declared
    `indexedDbScopes`.
  - Failing tests in `ws-server.test.ts`:
    - undeclared capability → throws.
    - undeclared `(database, store)` → throws.
    - requested key outside declared set → throws.
  - Implementation: model on `readLocalStorage` + new `pendingIdb` map.

- [ ] **B4. Extension-side handler.**
  - In `background.ts`, dispatch `'read_indexed_db'` op. Resolve a tab
    matching the origin, send a message to content script with the
    `(database, store, keys)`.
  - Content script (`content.ts`) opens IDB, reads keys, returns
    values.
  - Failing tests in `background.test.ts`:
    - request with origin outside declared domains → error.
    - request with undeclared scope → error.
  - Content-script handler tested separately (jsdom env? for now,
    just trust the existing localStorage path style).
  - Implementation: extend the request dispatcher.

- [ ] **B5. Popup display.**
  - Add `indexedDbScopes` field to `PendingPair`. Render under a
    "Read IndexedDB" subheading: one line per scope, `database/store:
    key1, key2`.
  - Failing tests in `popup.test.ts`:
    - declared IDB scope renders.
    - empty `indexedDbScopes` omits the section.
  - Implementation: add a sub-list appender.

- [ ] **B6. Bootstrap support.**
  - Extend `BootstrapOpts.declare` with optional `indexedDb: IndexedDbScopeDecl[]`.
  - When non-empty, capability includes `'read_indexed_db'`.
  - Add `Session.indexedDb: Record<string, Record<string, unknown>>`,
    keyed by `database/store` joined.
  - Failing tests in `bootstrap.test.ts`:
    - declared IDB scope round-trips through stub factory.
    - empty declaration → empty `session.indexedDb`.
  - Implementation: mirror localStorage path.

## Phase C — JSON-pointer extraction

- [ ] **C1. JSON-pointer evaluator in protocol.**
  - New file `packages/protocol/src/json-pointer.ts`:
    `evalJsonPointer(root, pointer): unknown`.
  - Failing tests in `json-pointer.test.ts`:
    - `''` returns root.
    - `/foo` accesses property.
    - `/foo/bar` nested.
    - `/0` array index.
    - `/foo/~1bar` escapes `/`.
    - `/foo/~0bar` escapes `~`.
    - missing path returns `undefined`.
    - non-object/array intermediate returns `undefined`.
    - invalid pointer (no leading `/`) throws.
  - Implementation: see spec.

- [ ] **C2. Pointer decls on hello.**
  - Add `localStoragePointers?: { key: string; jsonPointer: string }[]`
    and same for sessionStorage on `HelloFrameFromServer`.
  - Validator:
    - `key` must match an entry in declared `localStorageKeys` (resp.
      `sessionStorageKeys`).
    - `jsonPointer` must start with `/` and contain valid tokens.
    - duplicate `(key, jsonPointer)` rejected.
  - Failing tests:
    - happy path declared.
    - pointer with bad chars rejected.
    - duplicate rejected.
  - Implementation: extend `validateHello`.

- [ ] **C3. Pointer init on storage read.**
  - Extend `ReadStorageInit` with optional `pointers?: Record<string, { storageKey, jsonPointer }>`.
  - Validator: each pointer's `storageKey` ∈ `init.keys`. `jsonPointer`
    matches the pointer-validity rule.
  - Failing tests:
    - request with pointer field passes.
    - pointer pointing to undeclared storage key rejected.
  - Implementation: extend `validateInnerRequest`.

- [ ] **C4. Content-script pointer evaluation.**
  - In `content.ts`, when servicing
    `'fetchproxy-read-local-storage'` / `'fetchproxy-read-session-storage'`
    with pointers: read the raw value, JSON.parse it (skip if not
    JSON), eval each pointer, JSON.stringify back, return in `values`
    map keyed by the output key.
  - Failing tests in `content.test.ts` (new, jsdom env):
    - mock localStorage value `'{"a":{"b":1}}'`, pointer `/a/b`
      returns `'1'`.
    - missing path → omitted.
    - non-JSON storage value → omitted.
  - Implementation: extend message handler.

- [ ] **C5. Server-side `readLocalStorage` accepts `pointers`.**
  - Extend the method opts with `pointers?: Record<string, ...>`.
    Plumb through to inner request init. Defaults to undefined (no
    pointers).
  - Failing test in `ws-server.test.ts`:
    - declared pointer request resolves to mock response values map.
  - Implementation: pass through.

- [ ] **C6. Popup display.**
  - Render pointer rows in the storage sub-list as
    `<storageKey>.<jsonPointer>` (slashes preserved in pointer).
  - Failing test in `popup.test.ts`:
    - declared `localStoragePointers` rendered.
  - Implementation: extend the sub-list appender.

- [ ] **C7. Bootstrap pointer support.**
  - `BootstrapOpts.declare.localStoragePointers` array of
    `{ outputKey, storageKey, jsonPointer }`. When present, bootstrap
    issues the pointer-form request and returns extracted values
    keyed by `outputKey` (rather than `storageKey`).
  - Failing test:
    - declared pointer returns the extracted output keys.
  - Implementation: branch in bootstrap orchestration.

## Phase D — Glob support

- [ ] **D1. Glob-aware key validator.**
  - In `validate.ts:assertScopeKeyArray`, allow trailing `*` after the
    existing SCOPE_KEY chars. Reject bare `*` and patterns without a
    literal prefix.
  - Failing tests:
    - `feh--*` accepted.
    - `*foo` rejected.
    - bare `*` rejected.
    - `foo*bar` rejected (only trailing `*`).
  - Implementation: extend regex.

- [ ] **D2. Glob-aware scope matching in `handleReadCookiesV3` /
      `handleReadStorageRequest` / `read_indexed_db` handler.**
  - Helper `matchesDeclaredKey(requested, declared[])`: returns true
    if `requested` exactly equals a declared literal OR matches a
    declared glob (`prefix + '*'` matches any `prefix + suffix`).
  - Failing tests in `background.test.ts`:
    - request `feh--12ab` matches declared `feh--*`.
    - request `auth_x` matches declared `auth_*`.
    - request `weirdo` doesn't match `auth_*`.
  - Implementation: replace `Set` lookup with `matchesDeclaredKey`.

- [ ] **D3. Server-side glob match in scope-subset check.**
  - `FetchproxyServer.assertScopeSubset` must accept declared globs.
  - Failing test in `ws-server.test.ts`:
    - declared `['feh--*']`, requested `['feh--12ab']` → no throw.
  - Implementation: replace `Set` lookup.

## Phase E — Bootstrap ergonomics

- [ ] **E1. `BootstrapDisabledError` + env-var check.**
  - New exported class `BootstrapDisabledError`.
  - `bootstrap()` first computes
    `envVar = serverName.toUpperCase().replace(/[^A-Z0-9]/g, '_') + '_DISABLE_FETCHPROXY'`,
    then if `process.env[envVar]` truthy → throw.
  - Failing tests in `bootstrap.test.ts`:
    - env var set → throws `BootstrapDisabledError` synchronously.
    - env var unset → no throw.
    - scoped serverName resolves to expected env-var name.
  - Implementation: top of `bootstrap()`.

- [ ] **E2. `onWaiting` callback.**
  - `BootstrapOpts.onWaiting?: (hint: string) => void`.
  - Fires before each capture call (one per declared captureHeader).
  - Failing tests in `bootstrap.test.ts`:
    - declared capture → callback fires once per header with a hint
      mentioning the URL host + header name.
    - no `onWaiting` provided → no-op (no throw).
  - Implementation: add `onWaiting?.(...)` call sites.

- [ ] **E3. Actionable error messages.**
  - When `readLocalStorage` returns an empty value for a declared
    key, wrap the response with a clearer error stating "key X not
    in localStorage on origin Y — sign in first".
  - Similarly for cookies / IDB / capture timeouts.
  - Failing tests in `bootstrap.test.ts`:
    - stub returns empty map for declared keys → bootstrap throws with
      mention of "sign in".
  - Implementation: post-process bucket reads in bootstrap.

## Phase F — Capability-diff popup

- [ ] **F1. Trust record keeps last scope.**
  - `TrustRecord` gains `lastScope: {capabilities, cookieKeys, ...}`.
    Populated by `TrustStore.put` from the input. (`put`'s input
    already has all the fields — we just snapshot them.)
  - Failing test:
    - put then get → record carries lastScope.
  - Implementation: snapshot in `put`.

- [ ] **F2. `handleServerHello` returns `previous` in needs-pair when
      a known record exists.**
  - Existing branch already detects scope mismatch and triggers
    needs-pair; extend that branch to attach the existing record's
    scope as `previous`.
  - Failing tests in `background.test.ts`:
    - re-pair triggered by new scope → result has `previous` matching
      stored.
    - first pair → result has no `previous`.
  - Implementation: extend `needs-pair` payload.

- [ ] **F3. Popup renders diff when `previous` set.**
  - `PopupState.pending-pair` gains optional `previous`. When present,
    renders three sub-lists.
  - Failing tests in `popup.test.ts`:
    - first pair (no previous) → standard "Approve new MCP" heading.
    - re-pair (previous set, scope diff) → "UPDATE" heading + three
      sub-lists.
    - new capability appears under "Now requesting".
    - removed capability appears under "No longer requested".
  - Implementation: extend `renderPopup`.

## Phase G — Version bump + integration test + tag

- [ ] **G1. Bump versions across packages.**
  - `package.json` in each of: protocol, server, extension-core,
    extension-chrome, bootstrap — `0.3.0` → `0.4.0`.
  - `extension-chrome/manifest.json` → `0.4.0`.
  - Cross-package `dependencies` constraints
    (`@fetchproxy/server`'s pin on `@fetchproxy/protocol`,
    `@fetchproxy/bootstrap`'s pins) bump to `^0.4.0`.
  - `package-lock.json` regenerated (`npm install --package-lock-only`).

- [ ] **G2. Integration test: mutual auth + read_indexed_db.**
  - New file `packages/server/tests/integration/mutual-auth-idb.test.ts`.
  - Mock extension generates identity keys, dials host, sends valid
    `sessionSig`. Verifies (a) pair-code derivation matches MCP-side,
    (b) round-trips a `read_indexed_db` call with canned response,
    (c) subsequent connection with a different extension identity
    after first pair-and-trust gets rejected.
  - Implementation: shadow `all-bootstrap-verbs.test.ts` structure.

- [ ] **G3. Whole-tree green.**
  - `npm test` — every test passes, count ≥ 420.

- [ ] **G4. Tag locally `v0.4.0`.**
  - `git tag -a v0.4.0 -m "v0.4.0 — mutual auth, IDB, JSON pointers, globs, bootstrap polish"`.
  - Don't push. Don't publish.

## Out of scope (deferred to future)

- Subagent dispatch.
- Auto-prune unused declared keys.
- Identity-rotation flow (currently a wholesale re-pair).
- Trust-store export/import for backup.
- Capability per-call narrowing (today the full declared set is
  available; finer-grain runtime gates are future work).
