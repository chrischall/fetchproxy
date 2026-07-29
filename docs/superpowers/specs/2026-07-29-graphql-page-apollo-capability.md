# Spec: `graphql` capability — route GraphQL through the tab's own Apollo client

**Date:** 2026-07-29
**Status:** Plan (Milestone 0 gates the rest)
**Origin:** opentable-mcp `opentable_find_slots` fails with HTTP 409 on the
`RestaurantsAvailability` endpoint. Root cause is in fetchproxy, so the fix
starts here.

## Problem

fetchproxy relays every fetch through the content script's **isolated world**
(`content.ts` → native `window.fetch`, `credentials: 'include'`). That inherits
cookies + the user's TLS fingerprint, but the isolated world has a *pristine,
un-instrumented* `fetch`/`XHR`. Akamai Bot Manager's per-request telemetry is
injected inside the page's **MAIN-world** request path (specifically inside
OpenTable's Apollo link chain — not a global `fetch` monkeypatch).

Evidence (opentable-mcp diagnosis, 2026-07-29):

- The extension's isolated-world availability fetch → 403 (no csrf) / 409 (csrf).
- A manual replay from the page's **MAIN world** (DevTools console) → also fails.
  ⇒ Simply moving the fetch to MAIN world is NOT enough; the sensor lives in
  Apollo's link, not on `window.fetch`.
- The page's **organic Apollo call** to the identical endpoint → 200.
- A deliberately wrong persisted-query hash → the same empty-body 409.
  ⇒ Rejection happens at Akamai's edge before GraphQL runs. Not the hash, not
  CSRF, not a missing static header.

The v0.3 companion-extension design *intended* "same behavioral telemetry" by
running in the page context; the implementation delivered cookies+TLS only.
OpenTable's availability endpoint just escalated to require the telemetry the
isolated-world path never carried. Other endpoints (search, dashboard, booking)
still pass on cookies+TLS.

## Approach (option b): invoke the page's real Apollo client

Route the availability query through `window.__APOLLO_CLIENT__` in the MAIN
world. Whatever Akamai link OpenTable wired into their client runs
automatically — we don't need to reverse-engineer the sensor. This is by
definition the path that returns 200 (it *is* the organic path).

Rejected alternatives:
- **(a) capture/replay the sensor header** (`captureRequestHeader` already
  exists): the sensor is a per-request nonce; a captured value replayed on a
  different request is stale → 409. Also needs the user to organically trigger
  the exact query. Fragile-to-nonviable.
- **generic `page_eval` (arbitrary MAIN-world JS)**: maximal power, maximal
  security surface, breaks the narrow-capability ethos (`read_dom`,
  `read_cookies`, … are each specific). Rejected in favor of a declarative,
  operation-allowlisted `graphql` verb.

## The MAIN-world foothold already exists

`manifest.json` already ships `capture-logger.js` as a `world: MAIN`,
`run_at: document_start` content script, and the `scripting` permission is
present. We extend that MAIN-world script into a request/response RPC bridge
(isolated ⇄ MAIN via `window.postMessage` with strict origin/type checks),
rather than inventing a new injection path. **No new manifest permission is
required.**

## Milestone 0 — live PoC — ✅ DONE (2026-07-29, driven in real Chrome)

Ran against a signed-in opentable.com tab on La Belle Hélène's page
(`/r/la-belle-helene-charlotte-2`, rid 1175428), Apollo Client 3.10.8.
Method: hooked `client.link.request` at the top of the composed link chain,
triggered an organic `RestaurantsAvailability` call by nudging the
party-size `<select>`, captured the **live DocumentNode object** and the
organic variables, then invoked `client.query(...)`.

**Results (all conclusive):**

1. **Routing through `client.query({ query: capturedDoc, variables,
   fetchPolicy: 'no-cache' })` returns 200** — 5 available Standard slots for
   2026-07-31 / 17:00 / party 2 (offsets −30/−15/0/+15/+30 → 16:30–17:30). No
   409. **This proves option (b).**
2. **Session tokens are irrelevant.** Blanking `attributionToken` (null),
   `correlationId` (zero-UUID), and `restaurantAvailabilityTokens` (the MCP's
   existing placeholder) → still 200 / 5 slots. It is the Apollo-link routing
   alone that clears Akamai, not any rich per-request payload.
3. **The MCP's CURRENT `buildAvailabilityVariables()` output works unchanged.**
   Sending exactly the MCP's minimal variable shape through `client.query`
   → 200 / 5 slots. **No variable changes needed in opentable-mcp.**
4. Only 5 variables are NonNull/required: `restaurantIds, date, time,
   partySize, databaseRegion` — all already supplied by the MCP. The rest
   (`restaurantAvailabilityTokens, slotDiscovery, useCBR, forwardDays, …`) are
   optional.
5. The DocumentNode has **no `loc.source.body`** (can't lift query text) and at
   the top of the chain carries **no persisted hash** (a lower link adds it).
   ⇒ We neither hardcode query text nor a hash. We **reuse the live
   DocumentNode object** captured from the page's link.

**Design consequences (locked):**

- The extension carries NO hardcoded query text and NO sha256 hash. It captures
  the `RestaurantsAvailability` DocumentNode by hooking `client.link.request`
  and reuses it. This **auto-adapts** when OpenTable revises the query — the
  existing `RESTAURANTS_AVAILABILITY_HASH` maintenance burden disappears.
- The MCP keeps building its own variables; the extension supplies only the
  document + routing.
- **Limitation:** the invocation requires the page's Apollo client to have
  *observed* a `RestaurantsAvailability` op (so the DocumentNode is cached).
  That happens on any OpenTable restaurant-page load. If it hasn't been
  observed yet, the bridge returns a typed "operation not yet observed on this
  tab — open a restaurant's OpenTable page and retry" error. The MAIN-world
  hook installs at `document_start` and polls for `__APOLLO_CLIENT__`, so it
  catches essentially every organic call.

## Wire contract (finalized by Milestone 0)

New capability string `'graphql'` added to `Capability` union +
`KNOWN_CAPABILITIES` (`protocol/src/frames.ts`).

ServerHello gains a declared allowlist (approved at pair time, diffed on
change like every other capability). **No `sha256Hash`, no `path`** — the page
owns the document and its hashing:

```ts
graphqlOps?: {
  name: string;          // logical handle the MCP references per-call
  operationName: string; // e.g. 'RestaurantsAvailability' — the doc to reuse
}[]
```

Inner request/response (`protocol/src/frames.ts`, validated in
`protocol/src/validate.ts`):

```ts
interface InnerRequestGraphqlQuery {
  op: 'graphql_query';
  init: {
    name: string;                         // must match a declared graphqlOps[].name
    variables: Record<string, unknown>;   // the MCP's full variables object
    tabUrl?: string;
  };
}
interface InnerResponseGraphqlQuery {
  op: 'graphql_query';
  // ok:true → data (the GraphQL `data` object, e.g. { availability: [...] });
  // ok:false → error (includes the typed "not yet observed" case)
}
```

Per-call `name` MUST match a declared `graphqlOps[].name`; per-call
`variables` are supplied by the MCP. The extension resolves `name` →
`operationName` → cached DocumentNode, then invokes `client.query`. Declarative:
the extension only ever invokes operations the user approved at pair time.

## Task breakdown (TDD; each task is a fresh agent with full task text)

Sequential unless noted. Gate each with a reviewer (spec compliance + quality);
fix-loop until pass.

**fetchproxy (this repo):**

1. **protocol** — add `'graphql'` to `Capability`/`KNOWN_CAPABILITIES`; add
   `graphqlOps` to ServerHello; add `InnerRequestGraphqlQuery` /
   `InnerResponseGraphqlQuery` + union members; add validators in
   `validate.ts` (reject unknown op, malformed `graphqlOps`, oversized
   variables). Tests: validator accept/reject matrix.
2. **extension MAIN-world bridge** — extend `capture-logger.ts` into an RPC
   responder: on a `postMessage` of the agreed type from the isolated world,
   call `window.__APOLLO_CLIENT__` per the Milestone-0 mechanism, post the
   result back. Strict `event.source === window` + origin + type guards; time
   out; never expose beyond the declared operation. Tests: vitest with a mocked
   `window.__APOLLO_CLIENT__` + postMessage.
3. **extension isolated content script** — `content.ts`: handle
   `fetchproxy-graphql-query`, relay to MAIN world, await the reply, return the
   typed payload. Tests: mocked postMessage round-trip.
4. **extension background** — `background.ts`: dispatch `op:'graphql_query'`,
   with the pure gate (capability present + `name` in declared set + domain
   allow + host-or-subdomain tab match, mirroring `read_dom`) + popup capability
   label. Tests: gate accept/reject, tab-match, unknown-name reject.
5. **server** — `ws-server.ts`: `graphqlQuery({ name, variables, ... })` public
   method with capability gate + declared-set gate; thread `graphqlOps` through
   `build-server-hello.ts`. Tests: gate throws when undeclared; happy path over
   the in-memory WS.
6. **docs** — `SECURITY.md` (new verb + MAIN-world execution threat note),
   `PROTOCOL.md`, extension `README.md` manifest/highlights, root `CLAUDE.md`
   workspace notes. Bump nothing (release-please owns versions).

**mcp-utils:** bump `@fetchproxy/server` to the cohort version so
`createFetchproxyTransport(...).server` is typed with `graphqlQuery`. Likely no
code change (the adapter already exposes `.server`). Verify + a type-level test.

**opentable-mcp:**

7. **transport** — extend `OpenTableTransport` with a `graphqlQuery` path (or
   call `inner.server.graphqlQuery` directly from `transport-fetchproxy.ts`);
   declare `graphqlOps` (RestaurantsAvailability) + `'graphql'` capability in
   the `createFetchproxyTransport` opts.
8. **find_slots** — switch `opentable_find_slots` to `graphqlQuery` instead of
   the raw `fetchJson(AVAILABILITY_PATH, …)`; keep `parseAvailabilityResponse`
   unchanged (same `data.availability` shape). Fallback: if `graphql` is
   unavailable (older extension), surface the option-(c) clear botwall error
   rather than a bare 409. Tests: `FetchproxyServer` mock (`@fetchproxy/test-helpers`)
   asserting the graphql path + variables.
9. **live verify** — La Belle Hélène (1175428), 2026-07-31 17:00, party 2:
   `opentable_find_slots` returns slots, no 409. Also re-confirm search +
   booking still work (unchanged transport path).

## Release / rollout notes

- All fetchproxy packages bump in lockstep via release-please; **do not**
  hand-bump. A new capability is `feat:`.
- opentable-mcp's find_slots only gains the new behavior once the user reloads
  the rebuilt extension AND the `@fetchproxy/server` bump ships. Task 8's
  fallback keeps old extensions from hard-failing.
- `graphqlOps` is a capability *widening* → forces a re-pair with the diff UI.
  Call this out in the opentable-mcp changelog so users know to re-approve.
