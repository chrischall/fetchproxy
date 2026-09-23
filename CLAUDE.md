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
derived at handshake by X25519 ECDH between two per-session
ephemerals. Trust is identity-keyed (Ed25519) with an 8-digit pair code
the user confirms on first contact.

Current line: **3.x** — protocol 4: a per-session ephemeral on each
side, a session key salted with the handshake transcript, and
`mcpId || seq || direction` in the AEAD's additional data, on top of
2.x's mutual auth + JSON-pointer storage extraction + MV3 SW keepalive
+ storageDomain selector + host-or-subdomain tab matching + `graphql`
capability for MAIN-world Apollo-client invocation. The package major
and the protocol number are off by one — package 2.x spoke protocol 3,
package 3.x speaks protocol 4 — and `packages/protocol/src/frames.ts`
says why. All packages stay in lockstep on one version (see root
`package.json` → `version`).

## Workspaces

| Package | What it does |
|---|---|
| `@fetchproxy/protocol` | Wire format: frame validators, crypto wrappers (X25519, Ed25519, HKDF, AES-GCM, SHA-256), mcp-id parsing, pair-code derivation, JSON-pointer evaluator. Pure functions, no I/O. Smallest dep surface — every other workspace depends on it. |
| `@fetchproxy/server` | `request()` accepts `viaTab` to name the tab that relays a call — needed for API-only hosts (`api.example.com` serves no page, so its implied tab can never exist; route through the signed-in `www` tab instead). Guarded against the declared domains: it widens which tab performs the fetch, never which origins are reachable. Throws `FetchproxyScopeError` (with `.hint`) for gate-#2 scope rejections, so consumers that re-wrap bridge errors can still surface the re-pair remedy — build extension errors with `protocolErrorFrom()`, never `new FetchproxyProtocolError()` directly. MCP-side WebSocket bridge. `FetchproxyServer` class with `listen()`, `request()`, `fetch()`, `readCookies()`, `readLocalStorage()`, `readSessionStorage()`, `captureRequestHeader()`, `readIndexedDb()`, `graphqlQuery()`, `writeCookies()` (1.12+, the only write verb — see `docs/SECURITY.md` §T-cookie-write). Handles concentrator role-election (host vs peer), identity loading, session-key derivation. Persists per-MCP identity to `~/.fetchproxy/identity/<server-name>.json`. |
| `@fetchproxy/bootstrap` | `createSessionLifter(opts)` returns a **repeatable** lift (declare scope → spin up `FetchproxyServer` → read everything → close, per call) — use it whenever the session can expire, wiring it straight into a session manager's `login`. `bootstrap(opts)` is one invocation of that lifter, kept for genuinely one-shot callers (a user-invoked `capture_session` tool that persists the token). Used by Pattern A MCPs (HoneyBook, OFW, Resy auth-refresh path) that just need a session blob then operate from Node. `storageDomain` selector for multi-domain MCPs. Returns `missing.{cookies,localStorage,sessionStorage}` — declared keys the browser did not return, so a **partial** lift can't masquerade as a clean one (reading the apex when the cookies live on `www` is the classic way to get a half-populated session that fails later somewhere unrelated). |
| `@fetchproxy/cli` | `fpx` — a one-shot CLI over the same bridge: authenticated fetches and session reads through the user's signed-in browser tab, scoped by per-service **profiles** (each profile connects as `fpx-<name>` with its own identity, so ten services look like ten MCPs to the extension). Published, and it ships v4 changes like any other consumer — `src/bridge-errors.ts` is what names which half of the bridge is behind on a version mismatch. It is also how an operator debugs a straggler during a protocol rollout, without standing an MCP up. |
| `@fetchproxy/extension-core` | Pure-ish business logic of the browser extension: `handleServerHello` (security-critical pair/auto-trust decision), trust-store, session-keys, popup rendering, badge logic. Designed to be testable under vitest with mocked `chrome.*` globals. `private` (not published). |
| `@fetchproxy/extension-chrome` | Thin Chrome-MV3 wrapper around extension-core. Just bundling, manifest, icons. Produces `packages/extension-chrome/dist/` for unpacked sideload + GitHub-release `.zip`. `private` (not published). |
| `@fetchproxy/test-helpers` | Published vitest mock helpers for consumers of `@fetchproxy/server` — a drop-in `FetchproxyServer` mock that captures constructor opts and exposes spy-able `request`/`fetch`/`captureRequestHeader`/`bridgeHealth`. Lets cohort MCPs unit-test their fetchproxy usage without a live bridge. |

`extension-core` and `extension-chrome` are `private: true` (bundled into
the extension, never published to npm); the other five publish to npm.
Seven workspaces, and `ls packages` is the authority — this table has run
behind it before.

## Commands

| | |
|---|---|
| `npm test` | `vitest run` across the whole monorepo, all mocked, no network. (No test count here on purpose — a hard-coded one drifted; the run prints the current figure.) Must stay green. `vitest.config.ts` excludes `**/.claude/**` and `**/dist/**` so stale agent worktrees don't poison discovery. |
| `npm run build` | `npm run build --workspaces --if-present` — all **seven**: a `tsc -b` for protocol, server, bootstrap, cli, extension-core and test-helpers, plus extension-chrome's esbuild bundle (`tsx build.ts`). npm runs them in workspace order, which is alphabetical (`bootstrap` first, `protocol` fifth), so the build order is NOT the dependency order; what makes that safe is each package's `tsc -b` following its own `references`, so `protocol/dist` is built before anything that imports it via its `exports`→`dist/`. Don't demote a package to a bare `tsc` — that is the thing the references are carrying. |
| `npm run typecheck` | `tsc -b` over protocol, server, bootstrap, **cli**, extension-core, test-helpers — the script's own project list, cli included. extension-chrome is typechecked by its esbuild build instead. |
| `npm run build --workspace=@fetchproxy/extension-chrome` | Rebuild just the unpacked extension after a source edit. Drop into `chrome://extensions/` → fetchproxy → reload. **No sourcemaps** — this is the command the release workflow zips, so release is the default. |
| `npm run build:dev --workspace=@fetchproxy/extension-chrome` | Same, with inline sourcemaps, for debugging the extension in DevTools. Never what ships. |
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
   HKDF-SHA256, scoped to one **extension session** — not, on a peer, to
   one WS connection: a peer's own socket to the host closing is a
   teardown obligation and does not end the extension's session
   (`packages/server/src/peer.ts:285-289`; `docs/PROTOCOL.md` §The
   ephemeral's lifetime carries the invariant). Since 3.0.0 (protocol 4)
   the ECDH is EPHEMERAL × EPHEMERAL — the MCP contributes `sessionPub`
   on its hello, the extension its own on the `ready` — HKDF is salted
   with `transcriptHash(mcpNonce || extNonce || mcpSessionPub ||
   extSessionPub)` and personalised `fetchproxy/4.0.0/session`, and each
   frame is sealed under additional data `'fetchproxy/4/frame' || NUL ||
   mcpId || NUL || seq || NUL || direction` (`frameAad()`), which is
   authenticated and never transmitted, so a frame cannot be moved to
   another MCP, another counter or the other direction and the wire size
   is unchanged. Up to protocol 3 the MCP's half of the ECDH was its
   LONG-TERM identity key, so whoever held an identity plus a recording
   decrypted that traffic afterwards, passively and retroactively; under
   v4 the identity authenticates and nothing more, and the ephemeral's
   private half is zeroed when it is dropped or displaced
   (`dropOwnSessionAndEphemeral` / `installOwnEphemeral` in `host.ts`,
   `dropSessionEphemeral` / `installSessionEphemeral` in `peer.ts`). What
   forward secrecy does NOT buy is in `docs/SECURITY.md` §What protocol 4
   does not fix — read it before repeating the claim anywhere.
3. **Pair code** = `pairTranscript(...)` — the first 8 bytes of
   `SHA256('fetchproxy/4/pair' || NUL || mcpPub || extPub ||
   mcpHelloNonce || extHelloNonce || mcpSessionPub)` as a big-endian
   BigInt `mod 100_000_000`, formatted `XXXX-XXXX`. Binds both
   identities so a relay can't pose as the extension to a real MCP (or
   vice versa) — 0.4.0+ — and, since 3.0.0 (protocol 4), binds the
   SESSION too: both fresh nonces and the MCP's ephemeral are in the
   hash, so the number differs on every pairing attempt. v3's six
   digits over two long-term public keys could be ground ONCE offline
   (~10⁶) and reused against that MCP forever; this makes the grind
   online, per-pairing and ~10⁸. It does not abolish it — a party
   posing as the extension picks its own side of the inputs.
3b. **The MCP pins the extension too** (1.12.0+, #208) —
   `~/.fetchproxy/identity/<server-name>.extension-trust.json`, TOFU,
   written only after the ready signature verifies, refused with 1008
   on a mismatch. The mirror of `trustedMcps`. Ways out:
   `fpx trust list|clear <server>`, or
   `FETCHPROXY_TRUST_NEW_EXTENSION=1` for an MCP you don't own.
   `FETCHPROXY_TRUST_DIR` / `trustDir` moves the pin off the identity
   directory — a host that PROVISIONS the identity mounts it read-only,
   and the pin is the one file this package writes, so without it the
   write is logged and every boot is first-use.
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
   3.0.0 (protocol 4) widens both signatures again and symmetrically:
   the hello's covers the MCP's ephemeral and the `answersExtNonce` echo
   the host's forwarding gate reads (`helloSignaturePayload()`), the
   ready's covers the MCP's ephemeral beside the extension's
   (`readySignaturePayload()`), so neither side's contribution to the
   ECDH can be substituted by a relay. Because that ECDH no longer
   proves possession of a pinned key, the extension's half of the mirror
   had to be tightened to match: a trust record is found by the SHA-256
   of `identityX25519Pub`, and `handleServerHello` now falls through to
   needs-pair unless the record's `identityEd25519Pub` matches too —
   under v3 that comparison was belt-and-braces, since deriving a
   working key was itself the proof of possession. Wire break,
   PROTOCOL_VERSION 3 → 4, v3 refused AT THE HELLO in both directions
   with a reason naming both versions rather than left to time out.
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
single `v<NEXT>` tag (`include-component-in-tag: false`).

That release half now runs in
[`chrischall/workflows`](https://github.com/chrischall/workflows)'
`reusable-release-please.yml`, called from this repo's thin
`release-please.yml` stub (chrischall/workflows#283 — the copies drifted into
18 variants and the `republish_tag` escape hatch invented here never reached
any of them). What stays in this repo is what depends on its identity or its
monorepo shape: the **publish** job (npm Trusted-Publisher OIDC binds
provenance to this repository's workflow identity) and the
**`sync-cross-deps`** job, which fixes up the inter-package
`@fetchproxy/*` caret-range deps on the release PR — release-please bumps
each `version` through `extra-files` but never the cross-dep ranges. Publish
is gated on the reusable workflow's `publish` output, NOT on
`release_created`, because the latter is false on a republish, which is the
one run that exists to publish; it checks out the resolved tag, publishes the
non-private packages to npm, builds the Chrome-extension `.zip`, and attaches
it to the GitHub Release.

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

Both publish jobs (`release-please.yml` → `publish`,
`release-please-next.yml` → `publish-rc`) run in the **`npm-publish`
environment** and carry an `if: github.ref == 'refs/heads/main'` guard.
Trusted Publishing trusts a workflow *filename*, so without that binding
anyone who can push a branch and dispatch could publish the branch's code
under valid provenance. The YAML guard is editable from a branch; the
environment's deployment-branch policy (main only, set on GitHub) and the
environment name on each package's npm Trusted Publisher are not — those
two are what actually enforce it. `tests/publish-jobs-are-bound-to-main.test.ts`
fails if a publish job loses either line.

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
| `enhancement` | Features |
| `bug` | Bug Fixes |
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
- **Reloading the extension after a pull is a REQUIREMENT across a
  protocol major, not the hygiene the line above makes it sound.**
  Chrome keeps running the bundle "Load unpacked" loaded, so a pull that
  crosses 2.x → 3.x leaves a protocol-3 extension talking to the
  protocol-4 packages the same pull installed — and that pair is refused
  at the hello rather than degraded: every call fails at once with
  `protocol version mismatch`, in both directions, naming both versions.
  Rebuild `dist/`, then Reload. Both READMEs carry this as the
  requirement it is (`README.md` §Install and
  `packages/extension-chrome/README.md` §Install (developer / sideload)),
  and `tests/install-walkthroughs-name-the-cohort.test.ts` holds the
  numbers they print to the ones the refusal actually uses.
- **Re-publishing a tag after a failed publish.** The publish job only
  fires when the reusable release workflow says there is something to
  publish, and on the ordinary path that means release-please just cut a
  release. If the tag was cut but the npm/zip publish failed (e.g. wrong
  Node version) — or release-please lost its own `release_created` output
  after tagging, which is the failure chrischall/workflows#283 was opened
  for and which no amount of re-running fixes — fire `release-please.yml`
  via `workflow_dispatch` with the `republish_tag` input (e.g. `v1.3.3`)
  — dispatched **from `main`** (the publish job is bound to main; see
  "npm publish" above) — to re-run *only* the publish job against the existing tag: the
  release-please step is skipped, the version is derived from the tag, and
  the tag is confirmed to exist before anything publishes. No new release
  PR, no version bump. Idempotency makes a re-run SAFE; it does not make
  it RUN — dispatch instead.
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
  The content script injects the header with `window.__CSRF_TOKEN__`,
  asked of the MAIN-world logger on demand for each approved fetch
  (`readPageCsrfToken` ⇄ `installCsrfBridge`; the token is never written
  to the DOM — it used to sit in `data-fetchproxy-csrf` on every site) — and
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
- **Multi-domain tab opening — every declared domain, one tab each.**
  `background/server-hello.ts` and `background/approval.ts` both loop over
  `result.domains` calling `ensureDomainTab(d)` fire-and-forget, so a
  two-domain profile like HoneyBook gets a tab per domain. (This entry
  used to say `ensureDomainTab(domains[0])` opened only the FIRST — that
  was true of an older `background.ts` and has not been for some time.)
  The fan-out is why the cold-open registry is keyed by HOST rather than
  by "something is opening": one domain loading must not make a request
  for a different one wait, or be told a tab is arriving for it (#293).

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

