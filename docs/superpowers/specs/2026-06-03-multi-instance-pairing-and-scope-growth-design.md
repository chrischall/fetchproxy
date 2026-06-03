# Design: multi-instance pairing + non-blocking scope growth

**Date:** 2026-06-03
**Status:** Draft for review
**Package:** `@fetchproxy/extension-core` (the bridge/extension). No protocol wire change.

## Problem

Two related failure modes in the pairing/trust flow, both observed live with the
`musescore-mcp` server running in two Claude surfaces at once:

1. **Concurrent same-identity instances churn the pairing popup.** Two processes
   of the same server share one cryptographic `Identity` (keyed off `serverName`)
   but have distinct `mcpId`s. When both take the `needs-pair` path, the
   `pendingPair` store (keyed by `mcpId` since 0.5.2) queues **two** entries for
   the same identity; the user must approve each, and they fight over a single
   popup slot — the bridge never settles.
2. **A scope change blocks an already-paired MCP entirely.** The hello handler is
   deliberately conservative: *any* change to the declared scope vs the trust
   record forces `needs-pair`, which **blocks** the MCP until re-approved. So an
   MCP that gains a capability in a new version becomes unusable until the user
   re-pairs — and with two live instances, that re-pair churns (see #1). This
   caused a full bridge outage when `musescore-mcp` 0.3.0 added the
   `capture_request_header` capability: every tool hung.

## Background (current model)

- **Identity:** X25519/Ed25519 keypair persisted per `serverName` at
  `~/.fetchproxy/identity/<serverName>.json`. The extension's **trust record is
  keyed by `identityHash` = SHA-256(x25519Pub)** — stable across all instances and
  restarts of a given `serverName`.
- **`mcpId` = `<serverName>:<version>:<16-hex-rand>`** — the random block
  disambiguates processes/restarts.
- The extension keys per-`mcpId` maps for sessions, domains, capabilities, and the
  0.3.0/0.4.0 scope arrays (cookieKeys, captureHeaders, indexedDbScopes, …).
- **`pendingPair`** in `chrome.storage.local`: `Record<mcpId, PendingPairRecord>`
  (0.5.2+), normalised by `lib/pending-pair.ts`.
- **Hello decision** (`background.ts`): if a trust record for the `identityHash`
  exists, the extension pubkey matches, **and the declared scope is unchanged** →
  `auto-trust` (derive a session key for this `mcpId`). Otherwise → `needs-pair`
  (queue a pending entry by `mcpId`; the MCP is blocked until approval).

## Part 1 — Per-identity pairing (concurrent instances → one approval)

Key the pending queue and approval by **`(identityHash + scopeHash)`** instead of
`mcpId`:

- `scopeHash` = a stable hash over the normalised declared scope (capability set +
  every scope array), order-independent.
- On a `needs-pair` hello, if a pending entry with the same `identityHash` **and**
  the same `scopeHash` already exists, **add this `mcpId` to that entry's `mcpIds`
  set** rather than create a second entry. The popup shows **one** approval per
  identity+scope, with the affected instance count.
- **On approval:** write the trust record by `identityHash` (current behavior),
  **clear all pending entries for that `identityHash`+`scopeHash`**, and
  replay/notify so every connected `mcpId` of that identity re-derives its session
  and auto-trusts. No second popup.
- Genuinely different scopes for the same identity (e.g., two different versions
  declaring different capabilities) keep **separate** pending entries — the
  `scopeHash` differs — so nothing is silently merged.

## Part 2 — Non-blocking scope growth ("update or remain paired")

Replace "any scope change → blocking re-pair" with an **intersection-grant** model
plus a **non-blocking update offer**:

- The trust record stores the **approved scope** (already does). On every hello,
  the **granted scope = approved ∩ declared** (intersect the capability set and
  each scope array).
- **Declared ⊆ approved** (no new capabilities) → `auto-trust`, granted = declared.
  Unchanged.
- **Declared introduces capabilities/scope not in approved** → **still `auto-trust`
  on `approved ∩ declared`** (the MCP keeps working with everything previously
  granted — "remain paired"), AND queue a **non-blocking `scope-update`** pending
  entry (distinct from initial `pair`), keyed per `(identityHash + scopeHash)`,
  surfaced via the toolbar badge + popup: *"<serverName> now also wants:
  `<new caps>` — [Grant] / [Keep as is]."*
- **Request handler:** a verb that needs an **un-granted** capability returns a
  typed, actionable error (`capability "<x>" not granted — approve the pending
  fetchproxy update to enable it`) instead of stalling the bridge.
- **[Grant]** → grow the approved scope in the trust record → new capability
  granted; replay sessions so it takes effect. **[Keep as is]** → dismiss; the MCP
  keeps running on the old scope; the offer may re-surface on a later hello.

**Security invariant (preserved):** the granted scope is **always ≤ approved**; a
new capability is **never** granted without an explicit `[Grant]`. This is not
silent widening — it changes the *failure mode* from "block everything" to "serve
the already-approved scope and offer an upgrade." This is a deliberate softening of
the current conservative block, and it must be called out in the changelog.

**Composition:** the `scope-update` offer is keyed per `(identityHash + scopeHash)`
just like Part 1, so multiple instances of the same identity produce **one** update
offer, not one per process.

This change alone would have prevented the `musescore-mcp` 0.3.0 outage: the bridge
would have kept serving fetch-only with a dismissible "grant `capture_request_header`?"
offer, instead of hanging.

## Data-shape changes

- **`pendingPair` store:** keyed by a composite `${identityHash}:${scopeHash}`
  (not `mcpId`). Each entry carries: `kind: 'pair' | 'scope-update'`, the scope,
  the `identityHash`, `serverName`, `version`, and an `mcpIds: string[]` set (the
  processes currently waiting). `lib/pending-pair.ts` normalisation updated; on
  read, **migrate** legacy per-`mcpId` records (0.5.2 dict and ≤0.5.1 single) into
  the new keying (or drop them — a stale pending entry is non-destructive).
- **Trust record:** shape unchanged (stores approved scope by `identityHash`); add
  a helper to *grow* the approved scope on `[Grant]`.
- **Protocol/wire:** no change expected — confirm the existing host→peer
  `pair-pending` replay path can also carry a `scope-update` notification.

## Components touched

- `packages/extension-core/src/background.ts` — hello decision (intersection-grant;
  `needs-pair` vs `scope-update`), pending-queue keying/dedup, approval handlers for
  both kinds, peer replay, request-handler ungranted-capability error.
- `packages/extension-core/src/lib/pending-pair.ts` — composite keying,
  `mcpIds` set per entry, `kind`, legacy migration.
- `packages/extension-core/src/popup/popup.ts` + `popup.html` — one entry per
  identity+scope; instance count; `[Grant]`/`[Keep as is]` for `scope-update`;
  "update available" styling.
- `packages/extension-core/src/trust-store.ts` — unchanged record shape; add
  `growApprovedScope` helper.
- `packages/protocol`, `packages/server` — likely unchanged; verify the replay path.

## Error handling

- Ungranted capability → typed protocol error to the MCP (actionable), never a hang.
- Corrupt/legacy `pendingPair` → normalise to `{}` / migrate on read.
- Concurrent approvals for the same identity → idempotent (clear by
  `identityHash`+`scopeHash`; replay is safe to repeat).

## Testing (`extension-core` vitest)

- Two `needs-pair` helloes, same identity+scope → **one** pending entry whose
  `mcpIds` set has both; approve once → both auto-trust; pending cleared.
- Existing trust + a hello declaring a **new** capability, two live instances →
  granted = intersection (old scope still served), **one** `scope-update` entry;
  `[Grant]` → both granted the new capability; `[Keep as is]` → dismissed, both
  still served on the old scope.
- Same identity, two **different** scopes → two separate pending entries.
- A verb needing an un-granted capability → typed error, bridge still serves other
  verbs.
- Legacy `pendingPair` (single-record and per-`mcpId` dict) migrates/normalises.

## Risks / open decisions

- **Behavior change** from "block on scope change" to "serve old scope + offer
  update." Deliberate and security-preserving (granted ≤ approved); call out
  prominently in the changelog and README pairing docs.
- **`scopeHash`** must be a stable, order-independent hash of the normalised
  capability set + scope arrays (reuse `sameCapabilitySet`/`sameScopeArrays`
  normalisation).
- **Re-offer cadence** for a dismissed `scope-update`: re-queue on each hello where
  declared ⊄ approved, but dedupe to a single badge/entry so it isn't noisy.
- Decide whether a `scope-update` that the user has dismissed should suppress the
  badge until the declared scope changes again (avoid nagging).
