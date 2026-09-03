# CLAUDE.md — fetchproxy

Guidance for Claude working in this repo.

## TL;DR

Browser-relay bridge that lets a Node-side MCP make authenticated
HTTP fetches through the user's signed-in browser tab, plus read
declared cookie / localStorage / sessionStorage / IndexedDB scopes,
capture per-request headers, and invoke a declared, page-owned
GraphQL operation through the tab's own Apollo client (`graphql`
capability). Concentrator architecture: the first MCP to boot binds
`127.0.0.1:37149`, subsequent MCPs dial in as peers, the host
multiplexes all of them through one WebSocket to one browser
extension. Each MCP ↔ extension session has its own AES-256-GCM key
derived via X25519 ECDH at handshake. Trust is identity-keyed
(Ed25519) with a 6-digit pair code the user confirms on first contact.

Current line: **1.x** (mutual auth + JSON-pointer storage extraction
+ MV3 SW keepalive + storageDomain selector + host-or-subdomain tab
matching + `graphql` capability for MAIN-world Apollo-client
invocation). All packages stay in lockstep on one version (see root
`package.json` → `version`).

## Workspaces

| Package | What it does |
|---|---|
| `@fetchproxy/protocol` | Wire format: frame validators, crypto wrappers (X25519, Ed25519, HKDF, AES-GCM, SHA-256), mcp-id parsing, pair-code derivation, JSON-pointer evaluator. Pure functions, no I/O. Smallest dep surface — every other workspace depends on it. |
| `@fetchproxy/server` | `request()` accepts `viaTab` to name the tab that relays a call — needed for API-only hosts (`api.example.com` serves no page, so its implied tab can never exist; route through the signed-in `www` tab instead). Guarded against the declared domains: it widens which tab performs the fetch, never which origins are reachable. Throws `FetchproxyScopeError` (with `.hint`) for gate-#2 scope rejections, so consumers that re-wrap bridge errors can still surface the re-pair remedy — build extension errors with `protocolErrorFrom()`, never `new FetchproxyProtocolError()` directly. MCP-side WebSocket bridge. `FetchproxyServer` class with `listen()`, `request()`, `fetch()`, `readCookies()`, `readLocalStorage()`, `readSessionStorage()`, `captureRequestHeader()`, `readIndexedDb()`, `graphqlQuery()`, `writeCookies()` (1.12+, the only write verb — see `docs/SECURITY.md` §T-cookie-write). Handles concentrator role-election (host vs peer), identity loading, session-key derivation. Persists per-MCP identity to `~/.fetchproxy/identity/<server-name>.json`. |
| `@fetchproxy/bootstrap` | `createSessionLifter(opts)` returns a **repeatable** lift (declare scope → spin up `FetchproxyServer` → read everything → close, per call) — use it whenever the session can expire, wiring it straight into a session manager's `login`. `bootstrap(opts)` is one invocation of that lifter, kept for genuinely one-shot callers (a user-invoked `capture_session` tool that persists the token). Used by Pattern A MCPs (HoneyBook, OFW, Resy auth-refresh path) that just need a session blob then operate from Node. `storageDomain` selector for multi-domain MCPs. Returns `missing.{cookies,localStorage,sessionStorage}` — declared keys the browser did not return, so a **partial** lift can't masquerade as a clean one (reading the apex when the cookies live on `www` is the classic way to get a half-populated session that fails later somewhere unrelated). |
| `@fetchproxy/extension-core` | Pure-ish business logic of the browser extension: `handleServerHello` (security-critical pair/auto-trust decision), trust-store, session-keys, popup rendering, badge logic. Designed to be testable under vitest with mocked `chrome.*` globals. `private` (not published). |
| `@fetchproxy/extension-chrome` | Thin Chrome-MV3 wrapper around extension-core. Just bundling, manifest, icons. Produces `packages/extension-chrome/dist/` for unpacked sideload + GitHub-release `.zip`. `private` (not published). |
| `@fetchproxy/test-helpers` | Published vitest mock helpers for consumers of `@fetchproxy/server` — a drop-in `FetchproxyServer` mock that captures constructor opts and exposes spy-able `request`/`fetch`/`captureRequestHeader`/`bridgeHealth`. Lets cohort MCPs unit-test their fetchproxy usage without a live bridge. |

`extension-core` and `extension-chrome` are `private: true` (bundled into
the extension, never published to npm); the other four publish to npm.

## Commands

| | |
|---|---|
| `npm test` | `vitest run` across the whole monorepo (865 tests), all mocked, no network. Must stay green. `vitest.config.ts` excludes `**/.claude/**` and `**/dist/**` so stale agent worktrees don't poison discovery. |
| `npm run build` | `npm run build --workspaces --if-present` — TS build (`tsc -b`) for protocol → server → bootstrap → extension-core → test-helpers, then extension-chrome's esbuild bundle (`tsx build.ts`). **Order matters** — downstream workspaces import `@fetchproxy/protocol` via its `exports`→`dist/`, so protocol/dist must exist first. |
| `npm run typecheck` | `tsc -b` over protocol, server, bootstrap, extension-core, test-helpers. extension-chrome is typechecked by its esbuild build instead. |
| `npm run build --workspace=@fetchproxy/extension-chrome` | Rebuild just the unpacked extension after a source edit. Drop into `chrome://extensions/` → fetchproxy → reload. |
| `npm test --workspace=@fetchproxy/<pkg>` | Run just one package's tests when iterating. |

No top-level `npm run dev`; for a watch loop use `npm run test:watch` (root `vitest`) or vitest `--watch` per workspace.

## Architecture

```
┌─────────────┐  stdio  ┌──────────────┐    WS    ┌────────────────┐  fetch()  ┌────────┐
│ MCP client  │◀───────▶│  MCP (Node)  │◀────────▶│  fetchproxy    │◀────────▶│ Site   │
│ (Claude)    │         │              │  :37149  │  extension     │ (real    │ (tab)  │
└─────────────┘         └──────────────┘          │  (Chrome/      │  TLS +   └────────┘
                              ▲                   │   Safari)      │  cookies)
                              │ dials as peer     └────────────────┘
                       ┌──────┴──────┐
                       │  other MCPs │
                       │  (multiplex)│
                       └─────────────┘
```

**Concentrator (host vs peer).** `electRole()` in `server/src/election.ts`
tries to bind 37149; if it succeeds, that MCP is the **host** —
accepts the extension's WebSocket + accepts other MCPs dialing in. If
the bind fails with `EADDRINUSE`, the MCP dials the existing host as a
**peer**. The host multiplexes inner frames keyed by `mcpId`.

**Security model summary (see `docs/SECURITY.md` for the threat model).**

1. Per-MCP **identity** = long-term X25519 + Ed25519 keys at
   `~/.fetchproxy/identity/<server-name>.json` (mode 0600).
2. Per-session **AES-256-GCM** key derived via X25519 ECDH +
   HKDF-SHA256, scoped to one WS connection.
3. **Pair code** = `SHA256(mcpPub || extPub)[0..3] mod 1_000_000`
   formatted as `XXX-XXX`. Binds both identities so a relay can't
   pose as the extension to a real MCP (or vice versa). 0.4.0+.
3b. **The MCP pins the extension too** (1.12.0+, #208) —
   `~/.fetchproxy/identity/<server-name>.extension-trust.json`, TOFU,
   written only after the ready signature verifies, refused with 1008
   on a mismatch. The mirror of `trustedMcps`. Ways out:
   `fpx trust list|clear <server>`, or
   `FETCHPROXY_TRUST_NEW_EXTENSION=1` for an MCP you don't own.
   The same change makes PEERS verify the ready signature — until
   1.12.0 they verified nothing at all. The host now relays the
   extension hello to peers so they CAN check; a peer behind a
   pre-1.12.0 host warns and proceeds unless `requireExtensionIdentity`
   is set. 2.0.0 (GHSA-j6jv-w774-77m6) extends the signature to
   `(mcpNonce || extNonce || extensionSessionPub)` via
   `readySignaturePayload()`, which is what finally closes
   `T-host-MITM`: under v2 a relay could forward genuine frames and swap
   the ephemeral pub. Wire break, PROTOCOL_VERSION 2 → 3, v2 refused at
   the hello (no negotiated downgrade — a rewriting relay would pick
   it), so every package AND the extension ship together.
4. **Capabilities** declared in hello frame, approved at pair time,
   stored in the trust record. Tightening (or widening) the
   capability set forces a re-pair with diff UI. `graphql` is one
   such capability — it invokes a page-declared GraphQL operation
   through the tab's own Apollo client (MAIN world), gated by an
   `graphqlOps: [{ name, operationName }]` allowlist approved at pair
   time. It does NOT add arbitrary page-JS execution — only
   operations the page already exposes are reachable. See
   `docs/SECURITY.md` §T-graphql-misuse.
5. **Domain allowlist** — per-MCP `domains: string[]`. Every fetch
   URL, cookie origin, captureHeader URL, storage tab match has
   to be on a declared domain (or subdomain of one).

## Conventions

### Versioning + releases

All packages share **one version** kept in lockstep by **release-please**
(`.github/workflows/release-please.yml`, config `release-please-config.json`,
state `.release-please-manifest.json`). The umbrella `version` lives in the
root `package.json`; each sub-package's `version` is propagated via the
config's `extra-files` list (which also includes
`packages/extension-chrome/manifest.json`).

The end-to-end release cycle (canonical release-please monorepo shape):
release-please-action runs on every push to `main`, accumulating
Conventional-Commit subjects into **one combined release PR**
(`separate-pull-requests: false`). When that PR merges, the action cuts a
single `v<NEXT>` tag (`include-component-in-tag: false`). The same workflow's
second job (gated on `tag_name`) then checks out the tag, fixes up the
inter-package `@fetchproxy/*` caret-range deps (release-please bumps each
`version` but not the cross-dep ranges), publishes the non-private packages
to npm via Trusted-Publisher OIDC, builds the Chrome-extension `.zip`, and
attaches it to the GitHub Release.

**Do not bump versions or create tags manually unless explicitly asked.**
release-please owns the lockstep arithmetic; manual edits to a `version`
field create drift its diff then fights.

**Pre-release channel.** `release-please-next.yml` is a separate manual
(`workflow_dispatch`) flow that publishes `<base>-rc.<N>` builds under the
npm `next` dist-tag — used so consumer cohort MCPs can validate against an
unpublished `@fetchproxy/server` before the canonical release PR merges. It
rewrites versions **in memory only** and never commits back; `release-please.yml`
stays the sole writer of versions on `main`.

### npm publish via Trusted Publisher / OIDC

The `release-please.yml` publish job uses `--provenance` with GitHub OIDC
against each `@fetchproxy/*` package's Trusted Publisher trust on npm. **No
`NPM_TOKEN` secret is configured.** The workflow strips only
`always-auth` from `.npmrc` (deprecated in npm 11); the
`_authToken=${NODE_AUTH_TOKEN}` line setup-node writes is kept
intact. `NODE_AUTH_TOKEN` is unset, so the placeholder is empty;
`npm publish --provenance` then takes the OIDC path. Mirrors the
working pattern across compass-mcp, honeybook-mcp, opentable-mcp.

Do NOT strip `_authToken` — that removes the registry-entry npm
needs to even attempt Trusted Publisher, and `npm publish` errors
with `ENEEDAUTH`. (An earlier version of this doc described
stripping it as the fix; that was the bug.)

### PRs + auto-merge

Default workflow: branch + PR. The merge itself is automated by the
`chrischall/workflows` pipeline (see "Pull requests & releases" below) —
don't run `gh pr merge` yourself. The repo allows **squash merges only**
(no merge commit, no rebase). Direct pushes to `main` skip auto-generated
release notes (only merged PRs are sectioned); use direct push only when
the user explicitly asks.

Label conventions for release notes (`.github/release.yml`) — apply one per PR:

| Label | Section |
|---|---|
| `enhancement` / `feature` | Features |
| `bug` / `fix` | Bug Fixes |
| `security` | Security |
| `refactor` | Refactor |
| `documentation` | Documentation |
| `test` | Tests |
| `dependencies` | Dependencies |
| `ci` / `github_actions` | CI & Build |
| *(any other)* | Other Changes |
| `ignore-for-release` | excluded |

## Testing

Tests live next to source in `packages/<pkg>/tests/`. Always mocked:
the WS is in-memory, `chrome.*` is stubbed, `node:fs` paths use
overrides. No live network calls anywhere in vitest.

Live testing happens out of band — the cohort MCPs (opentable-mcp,
honeybook-mcp, resy-mcp, …) exercise fetchproxy against real sites,
and the unpacked extension's `chrome://extensions` reload + a manual
MCP tool call is the integration test.

## Hot spots / gotchas

- **MV3 service-worker eviction.** Chrome kills idle SWs after ~30s.
  `keepalive.ts` registers `chrome.alarms` firing every 24s; each
  alarm wakes the SW and re-runs `connect()` (idempotent). Without
  this, the bridge silently dies between bursts of MCP traffic. PR #2
  added the alarm; reload the extension after pulling.
- **Re-publishing a tag after a failed publish.** release-please's
  publish job is gated on `tag_name` from the merge. If the tag was
  cut but the npm/zip publish failed (e.g. wrong Node version), fire
  `release-please.yml` via `workflow_dispatch` with the `republish_tag`
  input (e.g. `v1.3.3`) to re-run *only* the publish job against the
  existing tag — no new release PR, no version bump.
- **`chrome.action.openPopup()` is restricted.** Chrome 127+ allows
  it from background in some contexts; older Chromes throw sync or
  async. `background.ts` wraps it in try/catch; the **badge** is the
  reliable surface.
- **Trusted-publisher OIDC + `setup-node`.** See "npm publish"
  above. If a publish fails with `ENEEDAUTH`, do NOT add an
  `_authToken` strip — that breaks OIDC. The likely culprits are
  (a) a workflow filename mismatch with the Trusted Publisher
  config on npmjs.com, (b) a missing `id-token: write` permission
  on the publish job, or (c) the package's TP trust never having
  been configured.
- **Multi-domain MCPs need `storageDomain`.** A MCP that declares
  `domains: ['x.com', 'y.com']` and calls `readLocalStorage(...)`
  must specify which declared domain to read from, or
  `FetchproxyServer.resolveBaseDomain` throws. Bootstrap helper
  threads `storageDomain` / `storageSubdomain` for this.
- **Tab match for storage reads = host-or-subdomain, not strict
  prefix.** Vendor-specific subdomains (HoneyBook's `*.hbportal.co`,
  Canvas's `*.instructure.com`) require the extension to accept any
  tab on the declared apex. `isTabUrlOnOrigin()` (added in PR #4)
  is the right helper.
- **Writes prefer a relay tab that can inject `x-csrf-token`** (#286).
  The content script injects the header from `data-fetchproxy-csrf`,
  copied from `window.__CSRF_TOKEN__` by the MAIN-world logger — and
  only a site's *app* pages define that global (OpenTable's homepage
  doesn't; its `/r/`, `/booking/`, `/user/` pages do). Because the
  relay walk takes tabs in `chrome.tabs.query` order, a homepage tab
  opened first used to 403 every write while a usable tab sat open.
  `handleFetchRequest` now sends non-GETs with `requireCsrf` first;
  a token-less tab answers the typed soft miss (`lib/csrf-soft-miss.ts`)
  and the walk continues; only if EVERY tab misses does a second pass
  re-send without the marker. GETs never walk. If a site 403s writes
  through the bridge, check which tab relayed them before suspecting
  the isolated world — that was the #267 misdiagnosis.
- **TODOs about multi-domain tab opening.** `ensureDomainTab(domains[0])`
  is called on pair approval — only opens a tab for the FIRST declared
  domain. HoneyBook spans two; only `honeybook.com` gets a tab. The
  user usually has a vendor portal tab already, so the limitation
  hasn't bitten anyone. Two TODOs marked in `background.ts`.

## What to *not* do

- Don't bump a workspace's version directly. release-please handles all
  bumps; manual edits create lockstep drift its diff then fights.
- Don't introduce new `chrome.*` API usage without adding the
  permission to `packages/extension-chrome/manifest.json` AND
  documenting it in `packages/extension-chrome/README.md`'s manifest
  highlights.
- Don't add direct dependencies between workspaces using literal
  versions (`"1.3.3"`) — always caret (`"^1.3.3"`). The release publish
  job rewrites caret ranges to the new cohort version; literals get
  left behind.
- Don't add `NPM_TOKEN` as a secret. The publish pipeline is OIDC.
- Don't write to `chrome.storage.local` without going through the
  TrustStore / SessionKeys helpers — they handle the
  serialization + migration shape.
- Don't make the `handleServerHello` function impure. It's the
  security-critical decision point and stays under unit-test discipline.
- Don't merge feature work that adds protocol fields without updating
  `packages/protocol/src/validate.ts` validators (every inbound
  frame is validated before dispatch).
- Don't use `console.log` / `console.debug` / `console.info` in any
  code that runs inside an MCP process — Node routes all of those to
  stdout, which is the MCP JSON-RPC channel, and a stray write
  corrupts the framing. Use `console.error` / `console.warn` (stderr)
  for all logging. See `host.ts` for the pattern. Round-3 PR #68
  shipped a `console.debug` keep-alive log that wedged stdio in the
  field before this rule was tightened.

<!-- pr-workflow:v3 -->
## Pull requests & release notes

Fleet policy — Conventional-Commit PR titles, labels, the auto-review /
auto-merge ladder, auto-review follow-up issues, PR timing, and release PRs —
lives in `~/.claude/CLAUDE.md`. Don't restate it here; the copies drifted.

Shared technical conventions (publishing, bundling, versioning guards,
write-verification, transport archetypes, testing traps) live in
[`chrischall/workflows`](https://github.com/chrischall/workflows):
`docs/fleet-conventions.md`, plus `README.md` for the CI pipeline contract.

