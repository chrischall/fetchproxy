# CLAUDE.md — fetchproxy

Guidance for Claude working in this repo.

## TL;DR

Browser-relay bridge that lets a Node-side MCP make authenticated
HTTP fetches through the user's signed-in browser tab, plus read
declared cookie / localStorage / sessionStorage / IndexedDB scopes and
capture per-request headers. Concentrator architecture: the first MCP
to boot binds `127.0.0.1:37149`, subsequent MCPs dial in as peers, the
host multiplexes all of them through one WebSocket to one browser
extension. Each MCP ↔ extension session has its own AES-256-GCM key
derived via X25519 ECDH at handshake. Trust is identity-keyed
(Ed25519) with a 6-digit pair code the user confirms on first contact.

Current line: **0.4.x** (mutual auth + JSON-pointer storage extraction
+ MV3 SW keepalive + storageDomain selector + host-or-subdomain tab
matching). All packages stay in lockstep.

## Workspaces

| Package | What it does |
|---|---|
| `@fetchproxy/protocol` | Wire format: frame validators, crypto wrappers (X25519, Ed25519, HKDF, AES-GCM, SHA-256), mcp-id parsing, pair-code derivation, JSON-pointer evaluator. Pure functions, no I/O. Smallest dep surface — every other workspace depends on it. |
| `@fetchproxy/server` | MCP-side WebSocket bridge. `FetchproxyServer` class with `listen()`, `request()`, `fetch()`, `readCookies()`, `readLocalStorage()`, `readSessionStorage()`, `captureRequestHeader()`, `readIndexedDb()`. Handles concentrator role-election (host vs peer), identity loading, session-key derivation. Persists per-MCP identity to `~/.fetchproxy/identity/<server-name>.json`. |
| `@fetchproxy/bootstrap` | One-shot helper: declare scope → spin up `FetchproxyServer` → read everything in one call → close. Used by Pattern A MCPs (HoneyBook, OFW, Resy auth-refresh path) that just need a session blob then operate from Node. `storageDomain` selector for multi-domain MCPs. |
| `@fetchproxy/extension-core` | Pure-ish business logic of the browser extension: `handleServerHello` (security-critical pair/auto-trust decision), trust-store, session-keys, popup rendering, badge logic. Designed to be testable under vitest with mocked `chrome.*` globals. |
| `@fetchproxy/extension-chrome` | Thin Chrome-MV3 wrapper around extension-core. Just bundling, manifest, icons. Produces `packages/extension-chrome/dist/` for unpacked sideload + GitHub-release `.zip`. |

## Commands

| | |
|---|---|
| `npm test` | Vitest across all workspaces — 453 tests, all mocked, no network. Must stay green. |
| `npm run build --workspaces --if-present` | TS build for protocol → server → bootstrap → extension-core, then extension-chrome's esbuild bundle. **Order matters** — extension-chrome bundles via the workspace symlink and needs protocol/dist on disk first. |
| `npm run build --workspace=@fetchproxy/extension-chrome` | Rebuild just the unpacked extension after a source edit. Drop into `chrome://extensions/` → fetchproxy → reload. |
| `npm test --workspace=@fetchproxy/<pkg>` | Run just one package's tests when iterating. |

There is no top-level `npm run dev`, and no watch mode wired up — vitest's `--watch` works per workspace if needed.

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

**Concentrator (host vs peer).** `electRole()` in `server/src/role.ts`
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
4. **Capabilities** declared in hello frame, approved at pair time,
   stored in the trust record. Tightening (or widening) the
   capability set forces a re-pair with diff UI.
5. **Domain allowlist** — per-MCP `domains: string[]`. Every fetch
   URL, cookie origin, captureHeader URL, storage tab match has
   to be on a declared domain (or subdomain of one).

## Conventions

### Versioning + releases

All five published packages share **one version** kept in lockstep by
the **Tag & Bump** workflow (`.github/workflows/tag-and-bump.yml`).
**Main is always one version ahead of the latest tag.**

The end-to-end release cycle: GitHub Actions → **Tag & Bump** (manual
`workflow_dispatch`) → tags current commit as `v$CURRENT` → bumps
patch across all workspaces + the Chrome extension manifest + the
internal `@fetchproxy/*` cross-dep ranges → commits + pushes main +
tag → push of `v*` tag triggers **Release** (`release.yml`) → publish
to npm + pack `.zip` for unpacked sideload + create GitHub release.

**Do not bump versions or create tags manually unless explicitly
asked.** Tag & Bump handles all the lockstep arithmetic.

**The Tag & Bump bump-file list must include every workspace with any
`@fetchproxy/*` dep.** Missing one (like bootstrap was through 0.4.2)
causes its cross-deps to lag the rest of the cohort and downstream
consumers end up with mixed-version lockfiles. Lesson tagged in PR #7.

### npm publish via Trusted Publisher / OIDC

`Release` uses `--provenance` with GitHub OIDC. **No `NPM_TOKEN`
secret is configured** — the workflow strips both `always-auth` and
`_authToken` from the `.npmrc` `setup-node` writes so npm publish
takes the OIDC path. Without that strip, `setup-node` leaves
`_authToken=${NODE_AUTH_TOKEN}` in `.npmrc` and the masked empty
placeholder (`XXXXX-XXXXX-XXXXX-XXXXX`) gets tried as a static token,
which npm rejects with a privacy-preserving 404. PR #6 fixed this.

### PRs + auto-merge

Default workflow: branch + PR + `gh pr merge --auto --merge` (the
repo allows merge commits only — no squash, no rebase). Direct
pushes to `main` skip auto-generated release notes (the auto-merge
workflow tags PRs into release sections); use direct push only when
the user explicitly asks.

Label conventions for release notes (`.github/release.yml`):

| Label | Section |
|---|---|
| `enhancement` | Features |
| `bug` | Bug Fixes |
| `security` | Security |
| `refactor` | Refactor |
| `documentation` | Documentation |
| `dependencies` | Dependencies |

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
- **Tag-vs-version conflict on re-runs.** If Tag & Bump partially
  succeeds (push main, fail to push tag), main ends up at the
  next version but the tag never landed. Re-running T&B then tries
  to tag the *bumped* version, which is fine — but if the original
  tagged version was already on remote pointing elsewhere, the run
  fails with "tag already exists." Move main forward (or
  fast-forward the local tag) and retry.
- **`chrome.action.openPopup()` is restricted.** Chrome 127+ allows
  it from background in some contexts; older Chromes throw sync or
  async. `background.ts` wraps it in try/catch; the **badge** is the
  reliable surface.
- **Trusted-publisher OIDC + `setup-node`.** See "npm publish" above.
  If a future release fails with 404 PUT, check `.npmrc` for any
  `_authToken` line that survived the strip.
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
- **TODOs about multi-domain tab opening.** `ensureDomainTab(domains[0])`
  is called on pair approval — only opens a tab for the FIRST declared
  domain. HoneyBook spans two; only `honeybook.com` gets a tab. The
  user usually has a vendor portal tab already, so the limitation
  hasn't bitten anyone. Two TODOs marked in `background.ts`.

## What to *not* do

- Don't bump a workspace's version directly. Tag & Bump handles all
  bumps; manual edits create lockstep drift.
- Don't introduce new `chrome.*` API usage without adding the
  permission to `packages/extension-chrome/manifest.json` AND
  documenting it in `packages/extension-chrome/README.md`'s manifest
  highlights.
- Don't add direct dependencies between workspaces using literal
  versions (`"0.4.2"`) — always caret (`"^0.4.2"`). Tag & Bump
  rewrites caret ranges; literals get left behind.
- Don't add `NPM_TOKEN` as a secret. The publish pipeline is OIDC.
- Don't write to `chrome.storage.local` without going through the
  TrustStore / SessionKeys helpers — they handle the
  serialization + migration shape.
- Don't make the `handleServerHello` function impure. It's the
  security-critical decision point and stays under unit-test discipline.
- Don't merge feature work that adds protocol fields without updating
  `packages/protocol/src/validate.ts` validators (every inbound
  frame is validated before dispatch).
