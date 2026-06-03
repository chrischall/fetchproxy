# Multi-instance pairing + non-blocking scope growth + connection indicator — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use `- [ ]` checkboxes.

**Goal:** Make `@fetchproxy/extension-core` (1) collapse concurrent same-identity pairing into one approval, (2) stop force-blocking when a paired MCP gains capabilities (serve the approved scope + offer a non-blocking update), and (3) show a connection-status dot per trusted MCP in the popup.

**Architecture:** All changes live in `packages/extension-core`. The trust record (keyed by `identityHash`) and the wire protocol are unchanged. The pending-pair store moves from `mcpId`-keyed to `(identityHash + scopeHash)`-keyed; the hello decision computes `granted = approved ∩ declared` and emits a non-blocking `scope-update` instead of a blocking `needs-pair` when an already-trusted identity declares new capabilities; the popup gains a presence dot fed by the set of connected `identityHash`es.

**Tech Stack:** TypeScript, vitest, Chrome MV3 extension (`chrome.storage.local`), pnpm workspaces. Pure render/normalisation helpers are unit-tested; `background.ts` integration is covered by its existing test harness.

**Security invariant (must hold in every task):** granted scope ≤ approved scope. A capability is never granted without an explicit `[Grant]`. Parts 1–2 change *failure mode and approval grouping*, never the set of granted capabilities.

---

## Conventions (read once)
- Run a package's tests: `pnpm --filter @fetchproxy/extension-core test` (or `pnpm -C packages/extension-core test`). Typecheck: `pnpm -r typecheck` (or `tsc -p packages/extension-core`).
- TDD: failing test → run (fail) → minimal code → run (pass) → commit.
- Commit trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.
- Branch is `feat/multi-instance-pairing-and-scope-growth` (already checked out).
- **Confirm-before-edit anchors:** the integration points below cite the current symbol to modify; open the file and match its real signature/imports rather than assuming.

---

## Part A — Scope hashing + intersection helpers (pure, foundational)

These pure helpers back Parts 1 and 2. `background.ts` already has `sameCapabilitySet` / `sameScopeArrays` / `sameCaptureHeaders` etc. — reuse their normalisation; add hashing + intersection beside them in a new pure module so they're unit-testable in isolation.

**Files:**
- Create: `packages/extension-core/src/lib/scope.ts`
- Test: `packages/extension-core/src/lib/scope.test.ts`

Define the shared scope shape (mirror the fields compared in `background.ts`'s `scopeChanged`):
```ts
export interface Scope {
  capabilities: string[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: { urlPattern: string; headerName: string }[];
  indexedDbScopes: { origin: string; database: string; store: string; keys: string[] }[];
  localStoragePointers: { key: string; jsonPointer: string }[];
  sessionStoragePointers: { key: string; jsonPointer: string }[];
}
```

- [ ] **A1 — test `scopeHash` is stable + order-independent.** `scope.test.ts`:
```ts
import { describe, it, expect } from 'vitest';
import { scopeHash, intersectScope, isScopeSubset } from './scope.js';

const base = (): import('./scope.js').Scope => ({
  capabilities: ['fetch', 'read_cookies'], cookieKeys: ['sid', 'cf'],
  localStorageKeys: [], sessionStorageKeys: [], captureHeaders: [],
  indexedDbScopes: [], localStoragePointers: [], sessionStoragePointers: [],
});

describe('scopeHash', () => {
  it('is order-independent', () => {
    const a = base();
    const b = { ...base(), capabilities: ['read_cookies', 'fetch'], cookieKeys: ['cf', 'sid'] };
    expect(scopeHash(a)).toBe(scopeHash(b));
  });
  it('differs when a capability is added', () => {
    expect(scopeHash(base())).not.toBe(scopeHash({ ...base(), capabilities: ['fetch', 'read_cookies', 'capture_request_header'] }));
  });
});
```
- [ ] **A2 — run → FAIL** (`scope.ts` missing). `pnpm -C packages/extension-core test scope`
- [ ] **A3 — implement `scope.ts`.** A deterministic JSON canonicaliser (sort every array + object keys) hashed with the package's existing hash util (reuse `@fetchproxy/protocol`'s sha256/`toB64`, or `crypto.subtle.digest` already used in `background.ts`). Plus:
```ts
// granted = approved ∩ declared, field by field.
export function intersectScope(approved: Scope, declared: Scope): Scope { /* per-field set intersection */ }
// true when declared introduces nothing beyond approved (declared ⊆ approved).
export function isScopeSubset(declared: Scope, approved: Scope): boolean { /* every declared member ∈ approved */ }
```
  For `captureHeaders`/`indexedDbScopes`/pointers, intersect by deep-equality of the entry objects (reuse the equality already in `background.ts`'s `sameCaptureHeaders`/`sameIndexedDbScopes` — extract those into `scope.ts` and re-import them in `background.ts` to stay DRY).
- [ ] **A4 — test `intersectScope` + `isScopeSubset`.** Add:
```ts
describe('intersect/subset', () => {
  it('intersect drops capabilities not in approved', () => {
    const approved = base();
    const declared = { ...base(), capabilities: ['fetch', 'read_cookies', 'capture_request_header'] };
    expect(intersectScope(approved, declared).capabilities.sort()).toEqual(['fetch', 'read_cookies']);
  });
  it('isScopeSubset false when declared adds a capability', () => {
    expect(isScopeSubset({ ...base(), capabilities: ['fetch', 'read_cookies', 'capture_request_header'] }, base())).toBe(false);
  });
  it('isScopeSubset true when declared ⊆ approved', () => {
    expect(isScopeSubset({ ...base(), capabilities: ['fetch'] }, base())).toBe(true);
  });
});
```
- [ ] **A5 — run → PASS**, `tsc` clean.
- [ ] **A6 — refactor `background.ts` to import the extracted equality helpers** from `scope.ts` (replace the local `sameCaptureHeaders`/`sameIndexedDbScopes`/… definitions with imports; keep behavior identical). Run the full `extension-core` suite → green.
- [ ] **A7 — commit** `feat(extension): add scope hashing + intersection helpers`.

---

## Part 1 — Per-identity pending-pair keying

**Files:**
- Modify: `packages/extension-core/src/lib/pending-pair.ts` (keying + `mcpIds` set + `kind`)
- Modify: `packages/extension-core/src/background.ts` (queue write ~L762–793; approval handler; peer replay)
- Test: `packages/extension-core/src/lib/pending-pair.test.ts`, plus background tests

- [ ] **1.1 — test the new pending shape + dedup.** In `pending-pair.test.ts`, assert `normalisePendingPair` keys by a composite and that legacy per-`mcpId` and single-record inputs migrate. Concrete entry shape:
```ts
interface PendingPairRecord {
  key: string;            // `${identityHash}:${scopeHash}`
  kind: 'pair' | 'scope-update';
  identityHash: string;
  serverName: string;
  version: string;
  scope: import('../scope.js').Scope;
  mcpIds: string[];       // processes currently waiting on THIS identity+scope
  // … existing render fields (pairCode, domains, previousScope?, sessionNonce per-mcp as needed)
}
```
  Test: two records same `key` → one entry with both `mcpId`s in `mcpIds`; a legacy `{mcpId, …}` single record and a `Record<mcpId,…>` dict both normalise without throwing.
- [ ] **1.2 — run → FAIL.**
- [ ] **1.3 — implement** the composite keying + `mcpIds` merge + legacy migration in `pending-pair.ts` (extend `normalisePendingPair`'s generic to key on `key`, fold legacy entries by deriving a key, union `mcpIds`).
- [ ] **1.4 — run → PASS.**
- [ ] **1.5 — wire `background.ts` queue write** (currently ~L762–793, `const pending: PendingPairRecord = {…}` then `existing[pending.mcpId] = pending`): compute `key = \`${hash}:${scopeHash(scope)}\``; if `existing[key]` exists, push `hello.mcpId` into its `mcpIds` (dedup) instead of overwriting; else create the entry with `mcpIds: [hello.mcpId]`. Badge/auto-popup logic keyed off entry count unchanged.
- [ ] **1.6 — wire the approval handler**: on approve of a `key`, call `trustStore.put(identityHash, …)` (already), then **delete the whole `key` entry** and replay/notify every `mcpId` in its `mcpIds` set so each re-derives a session (reuse the existing per-`mcpId` post-approval path, looping the set). Find the approval handler via `grep -n "APPROVED_PAIR_KEY\|approve" background.ts`.
- [ ] **1.7 — background test:** two helloes, same identity+scope, both unpaired → one pending entry, `mcpIds` length 2; approve → both get sessions; pending cleared. Use the existing background test harness (see `background.test.ts` patterns).
- [ ] **1.8 — run full suite → PASS; commit** `feat(extension): collapse concurrent same-identity pairing into one approval`.

---

## Part 2 — Non-blocking scope growth

**Files:**
- Modify: `packages/extension-core/src/background.ts` (the hello decision ~L300–400; request handler capability check; a new `scope-update` pending kind + approval path)
- Modify: `packages/extension-core/src/popup/popup.ts` + `popup.html`
- Test: background tests + popup render tests

- [ ] **2.1 — test the decision: declared adds a capability ⇒ auto-trust on intersection + queue `scope-update` (not block).** In the background/decision test: given a trust record approved for `['fetch']` and a hello declaring `['fetch','capture_request_header']`, expect the result kind to be `auto-trust` with granted capabilities `['fetch']` AND a `scope-update` pending entry queued (not `needs-pair`).
- [ ] **2.2 — run → FAIL.**
- [ ] **2.3 — change the hello decision** (the `scopeChanged` branch, ~L306–356): replace "scopeChanged ⇒ needs-pair" with:
  - compute `granted = intersectScope(approved, declared)`;
  - if `isScopeSubset(declared, approved)` → `auto-trust` with `granted` (unchanged path);
  - else → **`auto-trust` with `granted`** AND emit a `scope-update` pending record (kind `'scope-update'`, scope = declared, `previousScope` = approved) via the Part-1 keyed queue. Keep the existing `auto-trust` session-key derivation; just feed it `granted` instead of `declared`.
  - The session/`mcpCapabilities` map for the `mcpId` stores `granted` (so the request handler enforces it).
- [ ] **2.4 — run → PASS.**
- [ ] **2.5 — request-handler test:** a verb requiring `capture_request_header` when only `['fetch']` is granted → returns the existing capability-denied error path (find via `grep -n "capabilities\|not declared\|capability" background.ts` near the request handler), NOT a hang. (This path likely already exists for undeclared capabilities — confirm it fires for *declared-but-ungranted* too; if it keys off `mcpCapabilities` (granted), it already works since granted excludes it.)
- [ ] **2.6 — run → PASS; commit** `feat(extension): serve approved scope + offer non-blocking update when an MCP gains capabilities`.
- [ ] **2.7 — popup `scope-update` rendering test** (`popup.test.ts`): a `pending` state with `kind:'scope-update'` renders the "also wants" diff (reuse the existing 0.4.0 added/removed diff renderer ~L217–320) with `[Grant]` and `[Keep as is]` buttons (the latter dismisses without trusting).
- [ ] **2.8 — run → FAIL → implement popup branch → run → PASS.** `[Keep as is]` posts a "dismiss" message that removes the `scope-update` entry without writing trust; `[Grant]` follows the normal approve path (grows approved scope).
- [ ] **2.9 — dismiss-suppression:** a dismissed `scope-update` should not re-badge until the declared scope changes again — store the dismissed `scopeHash` per identity and skip queuing when it matches. Test + implement. Commit `feat(extension): scope-update popup with grant/keep-as-is + dismiss suppression`.

---

## Part 3 — Connection-status indicator (independent; can be its own PR)

**Files:**
- Modify: `packages/extension-core/src/popup/popup.ts` (`TrustedSummary.connected`, render dot) + `popup.html` (styles)
- Modify: `packages/extension-core/src/background.ts` (track `mcpId → identityHash`; expose connected set; `connections-changed` broadcast)
- Test: `popup.test.ts`, background tests

- [ ] **3.1 — popup render test:** `renderPopup` with a `status` entry `connected: true` includes an element `.status-dot.connected`; `connected: false` → `.status-dot.offline`; both carry an `aria-label` of "connected"/"not connected".
- [ ] **3.2 — run → FAIL.**
- [ ] **3.3 — implement:** add `connected: boolean` to `TrustedSummary` (interface ~L93) and, in the status-list loop (~L381), prepend `elem('span', { class: \`status-dot ${t.connected ? 'connected' : 'offline'}\`, 'aria-label': t.connected ? 'connected' : 'not connected', title: … })`. Add `.status-dot{...}` `.connected{background:#2ecc71}` `.offline{background:#bbb}` to `popup.html`'s style block.
- [ ] **3.4 — run → PASS; commit** `feat(extension): connection-status dot in trusted list (render)`.
- [ ] **3.5 — background: track identity per session.** Add `const mcpIdentityHash = new Map<string, string>()` set at hello-accept (where `sessions.set(result.mcpId, …)`, ~L731, and where `identityHash: hash` is known) and deleted alongside session teardown. Add a helper `connectedIdentityHashes(): Set<string>` = `new Set([...sessions.keys()].map(id => mcpIdentityHash.get(id)).filter(Boolean))`.
- [ ] **3.6 — background: feed the popup + live updates.** Where the popup's `status` state is assembled (grep the message handler that returns trusted summaries to the popup), set each `TrustedSummary.connected = connectedIdentityHashes().has(t.identityHash)`. On session add/remove, `chrome.runtime.sendMessage({ type: 'connections-changed' })`; the popup subscribes and re-requests status. Test: with one live session for identity X, the trusted summary for X has `connected:true`, others `false`; after session close + `connections-changed`, X flips to `false`.
- [ ] **3.7 — run full suite → PASS; commit** `feat(extension): drive connection dot from live sessions + connections-changed`.

---

## Final
- [ ] Run `pnpm -r typecheck` + `pnpm --filter @fetchproxy/extension-core test` → all green.
- [ ] Update `packages/extension-core/CHANGELOG`-adjacent notes / README pairing docs: the behavior change (scope growth no longer blocks; granted ≤ approved preserved), the per-identity approval, and the new connection dot.
- [ ] Open PR(s): Parts 1+2+A as one (cohesive pairing change), Part 3 optionally separate.

## Self-review
- **Spec coverage:** Part 1 → Tasks 1.x; Part 2 → Tasks 2.x (+ A for intersection/hash); Part 3 → Tasks 3.x; data-shape (composite key, `mcpIds`, migration) → 1.1–1.3; security invariant (granted ≤ approved) → A3/2.3 + the request-handler test 2.5. No gaps.
- **Placeholder scan:** new pure logic (scope.ts, pending keying, dot render) has concrete code/tests; integration steps cite exact symbols/line-anchors in `background.ts`/`popup.ts` to match rather than vague "handle it."
- **Type consistency:** `Scope`, `scopeHash`, `intersectScope`, `isScopeSubset`, `PendingPairRecord.{key,kind,mcpIds,scope}`, `TrustedSummary.connected`, `connectedIdentityHashes()` are used identically across tasks.
