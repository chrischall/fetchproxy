# ContextMint Bridge — repo split + rebrand (implementation plan)

**Spec:** [`docs/superpowers/specs/2026-09-25-contextmint-bridge-chrome-safari-design.md`](../specs/2026-09-25-contextmint-bridge-chrome-safari-design.md)
**Covers spec steps 1–3** (create `nullnet-app/contextmint-bridge`, remove the extension
from fetchproxy, rebrand + platform seam). Chrome Web Store submission (step 4, blocked
on the ContextMint mark), the Safari spike (step 5, needs a human at Safari) and the
Safari build (step 6) get their own plans.

**Order:** Tasks 1 → 2 → 3 → 4 run sequentially in the bridge repo; Task 5 runs in
fetchproxy only after Task 4 has merged. Nothing here is parallel.

**Standing rules for every task** (each task's agent sees only its own text, so these
are repeated by reference — read them):

- TDD: write the failing test first, watch it fail, then make it pass.
- Before calling a task done, run `npm test` **and** `npm run typecheck` (vitest does
  not typecheck) and `npm run build`, all green.
- Never merge a PR, never add `ready-to-merge` / `release-ready`, never hand-bump a
  version or create a tag. PR titles are Conventional Commits and are the release
  decision; on a one-commit PR the commit subject must match the title.
- A PR can auto-merge within ~15 minutes of opening: verify everything before
  `gh pr create`, and re-check `gh pr view <N> --json state` before any later push.
- End commit messages with the session's Co-Authored-By / Claude-Session lines.

---

## Task 1 — Create `nullnet-app/contextmint-bridge` with history

**Goal:** a public nullnet repo holding `extension-core` and `extension-chrome` with
their git history, building and testing green against `@fetchproxy/protocol` from npm,
with no behaviour change and no rebrand yet.

**Owner authorization (given 2026-09-25):** create the repo as **public** in the
`nullnet-app` org, named `contextmint-bridge`.

Steps:

1. In a scratch directory, `git clone --no-local ~/git/fetchproxy bridge-filter` and run
   `git filter-repo` (install with `brew install git-filter-repo` if missing) keeping
   only: `packages/extension-core/`, `packages/extension-chrome/`, `docs/PRIVACY.md`,
   `docs/store-assets/`, `tests/privacy-policy-names-every-network-path.test.ts` (it
   reads only `docs/PRIVACY.md`), `LICENSE`. Confirm `git log --oneline | wc -l` is non-trivial
   and `git log --follow packages/extension-core/src/background/socket.ts` shows history.
2. Add root scaffolding (new commit):
   - `package.json`: `"name": "contextmint-bridge"`, `private`, `type: module`,
     `workspaces: ["packages/*"]`, scripts `build` (`npm run build --workspaces
     --if-present`), `test` (`vitest run`), `typecheck` (`tsc -b packages/extension-core`),
     devDependencies copied from fetchproxy's root `package.json` (`@types/node`,
     `@vitest/coverage-v8`, `typescript`, `vitest`, `prettier` — same ranges).
   - `tsconfig.base.json` and `vitest.config.ts` copied from fetchproxy unchanged.
   - `packages/extension-core/package.json` and `packages/extension-chrome/package.json`:
     `@fetchproxy/protocol` stays at `^3.2.2` but now resolves from npm; nothing else.
   - `packages/extension-core/tsconfig.json`: delete the `references: [{ path:
     "../protocol" }]` entry (the protocol now comes from `node_modules` with its own
     published `.d.ts`).
3. `packages/extension-core/tests/cross-version/refusal.test.ts` imports
   `../../../server/tests/cross-version/v3-fixtures.js`, which does not exist here.
   Copy that fixture file from fetchproxy into
   `packages/extension-core/tests/cross-version/v3-fixtures.ts` verbatim (it is a frozen
   protocol-3 recording; add a header comment saying it was vendored from
   `chrischall/fetchproxy` `packages/server/tests/cross-version/v3-fixtures.ts` and must
   not be edited) and fix the import. If that fixture itself imports other server
   internals, vendor only what it needs.
4. `npm install`, then `npm run build`, `npm test`, `npm run typecheck` — all green,
   with the same test count the two packages report in fetchproxy (`npx vitest run
   packages/extension-core packages/extension-chrome` in fetchproxy gives the baseline).
5. Fleet wiring, mirroring an existing nullnet repo (read `nullnet-app/mcp-host-app`'s
   `.github/` first and copy its shape): `.github/workflows/ci.yml` calling
   `chrischall/workflows/.github/workflows/reusable-mcp-ci.yml@main` (node 26,
   `build-command: npm run build`, `test-command: npm test`, `gate-mode: status`),
   `pr-auto-review.yml`, `auto-merge.yml`, `claude.yml`, dependabot stub,
   `.github/release.yml`. Apply fleet labels with `chrischall/workflows`'
   `ensure-labels.sh`. External actions pinned to exact release tags, never SHAs.
6. A `CLAUDE.md` holding only what is true of this repo: what it is (ContextMint
   Bridge, the fetchproxy browser extension), the two packages, the commands, the
   "protocol comes from npm; protocol changes land in fetchproxy first" rule, and the
   extension-specific gotchas moved from fetchproxy's CLAUDE.md (MV3 SW eviction +
   keepalive, reload-after-pull across a protocol major, `openPopup` restriction,
   CSRF relay-tab preference, multi-domain tab opening, the "don't put
   security-relevant data in `chrome.storage.local`", "`handleServerHello` stays pure"
   and "new `chrome.*` API ⇒ manifest permission + README" rules). Do not restate
   fleet policy from `~/.claude/CLAUDE.md`.
7. `gh repo create nullnet-app/contextmint-bridge --public`, push `main`, then set
   squash-only merges, auto-merge allowed, and the repo ruleset requiring `ci-gated`
   the way other nullnet repos do (check `gh api repos/nullnet-app/mcp-host-app/rulesets`).

Release-please is **not** added in this task (Task 4 does it).

**Done when:** the repo exists, `main` builds and tests green in CI, history is
preserved, and no file in it references a path outside the repo.

---

## Task 2 — Platform seam (`platform` from the build, not hardcoded)

**Repo:** `nullnet-app/contextmint-bridge`. Branch, PR titled
`refactor(extension): take the hello's platform from the build target`.

`packages/extension-core/src/background/socket.ts` hardcodes `platform: 'chrome'` in
the extension hello. A Safari build must say `'safari'` (the protocol validator in
`@fetchproxy/protocol` already accepts `'chrome' | 'safari' | 'firefox'`).

1. Test first (extension-core): the hello built by socket.ts carries the platform the
   module was configured with. Choose the seam so it is testable without esbuild: a
   `declare const __FETCHPROXY_PLATFORM__: Platform` read through one small accessor
   module (e.g. `src/platform.ts` exporting `currentPlatform()`), with the test stubbing
   the global via `vi.stubGlobal`. Default when undefined: throw at build time, not
   silently `'chrome'` — a missing define must fail loudly.
2. `packages/extension-chrome/build.ts`: pass `define: { __FETCHPROXY_PLATFORM__:
   '"chrome"' }` to every esbuild entry.
3. A test in extension-chrome that builds (or reads the built `dist/background.js`
   after `npm run build`, following the pattern of the existing
   `tests/release-bundle-sourcemaps.test.ts`) and asserts the literal `"chrome"` was
   substituted and no `__FETCHPROXY_PLATFORM__` identifier survives in the bundle.

**Done when:** tests above pass, `npm test`/`typecheck`/`build` green, PR open with CI green.

---

## Task 3 — Rebrand to ContextMint Bridge

**Repo:** `nullnet-app/contextmint-bridge`. PR titled
`feat(extension): rename the extension to ContextMint Bridge`.

1. Test first — a brand guard in `packages/extension-core/tests/` (or a root `tests/`):
   no file under `packages/extension-core/src/popup/`, `packages/extension-chrome/manifest.json`,
   `packages/*/README.md`, `docs/PRIVACY.md` or `docs/store-assets/` contains the string
   `Transporter`. Code comments elsewhere in `src/` may keep historical mentions only if
   they are clearly historical ("formerly Transporter").
2. `manifest.json`: `name` → `ContextMint Bridge`, add `short_name` → `Bridge`,
   `description` → a ≤132-char line that says it connects ContextMint and local MCP
   tools to your signed-in browser tabs (add a test asserting ≤132 chars).
3. Popup copy (`extension-core/src/popup/popup.html`, `popup.ts`) and any other
   user-visible string in extension-core (`grep -rn Transporter packages`).
4. `docs/store-assets/listing-description.md` and `permission-justifications.md`:
   rebrand; say it works with ContextMint **and** any fetchproxy-based MCP or `fpx`;
   add justifications for `downloads` and `tabGroups`, which the manifest requests but
   the file omits (read `extension-core/src/background/handlers/download.ts` and
   `extension-core/src/ensure-domain-tab.ts` to describe what they are actually used for).
5. `docs/PRIVACY.md` and the package READMEs: rebrand, keep every technical claim.
6. Root `README.md` for the new repo: what it is, the bridge sentence ("In the stores
   it's ContextMint Bridge; the protocol and npm packages are fetchproxy"), sideload
   install steps (moved from fetchproxy's `packages/extension-chrome/README.md`), and a
   link to `chrischall/fetchproxy` for the protocol and server.

Icons stay as they are (the ContextMint mark is a separate dependency).

**Done when:** guard passes, no user-facing `Transporter` left, all green, PR open.

---

## Task 4 — Releases for the bridge repo

**Repo:** `nullnet-app/contextmint-bridge`. PR titled `ci: release the extension with release-please`.

1. `release-please-config.json` + `.release-please-manifest.json`: one root package,
   `release-type: node`, `extra-files` for both workspace `package.json`s and
   `packages/extension-chrome/manifest.json` `$.version` (copy the shape from
   fetchproxy's config). The first release is **1.0.0** per the spec: set the manifest
   to `0.0.0`-equivalent starting state and `"release-as": "1.0.0"` in the config,
   with a comment that it must be deleted after the first release. Do not edit any
   `version` field by hand beyond what that requires.
2. `.github/workflows/release-please.yml`: thin stub calling `chrischall/workflows`'
   `reusable-release-please.yml` (as fetchproxy does, with `NULLNET_RELEASE_PAT`),
   plus a job that, when the reusable workflow reports a publish, checks out the tag,
   builds `extension-chrome`, zips `dist/` as `contextmint-bridge-chrome-${VERSION}.zip`,
   and attaches it and its SHA-256 digest to the GitHub Release. Port the
   attach-artifacts logic from fetchproxy's `release-please.yml` (lines ~288–380),
   including its "asset already exists → leave it, re-hash what is published" rule.
   No npm publish — nothing here is published to npm.
3. CI matrix: add a job (or a second ci.yml invocation) that installs
   `@fetchproxy/protocol@next` over the locked version and runs `npm test`, so an
   unreleased protocol change shows red here. If fetchproxy has no current `next`
   dist-tag, the job must fall back to `latest` and say so in its log rather than fail.
4. Test first where testable: a `tests/release-workflow.test.ts` that parses the
   workflow YAML and asserts the zip step builds from the tag checkout and that no job
   runs `npm publish`.

**Done when:** all green, PR open. The first release PR that release-please then opens
is the owner's to label — do not label it.

---

## Task 5 — Remove the extension from fetchproxy; fix bridge wording in server/cli

**Repo:** `chrischall/fetchproxy`. Starts only after Task 4 has merged. PR titled
`fix(server,cli): point bridge errors at ContextMint Bridge and name protocol versions`.
Label `bug`.

1. Tests first:
   - Brand guard: no string literal in `packages/server/src/` or `packages/cli/src/`
     contains `Transporter`.
   - Version-message guard: `FetchproxyProtocolVersionError` for `peer: 'extension'`
     names the protocol number the extension must speak and tells the user to update
     ContextMint Bridge; it does **not** print a `@fetchproxy/server` package version as
     the extension's target (today `session-ready.ts:110` says "update Transporter … to
     `${MIN_VERSION}`", a server version). The `peer: 'host'` branch keeps naming the
     `@fetchproxy/server` version, which is still correct.
   - `cli/src/bridge-errors.ts`'s extension branch no longer claims "both halves of the
     bridge ship as one release"; it says to update ContextMint Bridge from its store
     or the `nullnet-app/contextmint-bridge` releases, and to reload it.
2. Update the strings in `server/src/session-ready.ts`, `cli/src/bridge-errors.ts`,
   `cli/src/main.ts`, `cli/README.md`, and any other user-facing `Transporter`
   (`grep -rn Transporter packages/server/src packages/cli`). Existing tests that
   assert on the old wording are updated, not deleted.
3. Delete `packages/extension-core` and `packages/extension-chrome`. Then:
   - root `package.json` `typecheck`: drop `packages/extension-core`.
   - `.github/workflows/ci.yml` comment, `release-please.yml` (remove the extension
     build/zip/attach steps; keep npm publish intact), `release-please-next.yml`
     (drop the extension packages from its loops and build list).
   - `release-please-config.json`: drop the two extension `package.json`s and the
     manifest from `extra-files`.
   - root doc-guard tests: `tests/install-walkthroughs-name-the-cohort.test.ts` and
     `tests/security-docs-match-the-main-world-bridge.test.ts` read extension files —
     keep whatever they assert about files that remain in fetchproxy, drop the rest;
     `tests/published-packages-ship-no-tests.test.ts` loses its extension carve-out.
   - `docs/PRIVACY.md`, `docs/store-assets/` and
     `tests/privacy-policy-names-every-network-path.test.ts` are deleted here (Task 1
     moved all three).
   - `README.md`: the install section links the bridge repo's releases (store links
     come later); add the bridge sentence. `docs/SECURITY.md`: extension source paths
     become `nullnet-app/contextmint-bridge` paths.
   - `CLAUDE.md`: workspace table and counts ("seven" → five), commands, the
     release-flow paragraphs that mention the zip, and the extension-only gotchas
     (now in the bridge repo's CLAUDE.md — replace with one line pointing there).
   - `docs/PROTOCOL.md` and `.gitignore`: drop or re-point extension paths.
   - Server source comments and tests that cite extension files
     (`server/src/error-kind.ts`, `server/src/host.ts`,
     `server/tests/classify-fetch-error.test.ts`,
     `server/tests/cross-version/refusal.test.ts`): name
     `nullnet-app/contextmint-bridge` beside each path so it is not read as local.
   - Regenerate `package-lock.json` (`npm install` after the deletes) so the two
     workspaces drop out of it; commit the lockfile.
4. `npm ci && npm run build && npm test && npm run typecheck` green; the npm publish
   job still publishes protocol, server, bootstrap, test-helpers, cli.

**Done when:** all green, PR open, and:

- `packages/extension-core` and `packages/extension-chrome` no longer exist;
- `git grep -n "packages/extension-" -- package.json package-lock.json
  release-please-config.json .release-please-manifest.json .github .gitignore
  'tsconfig*.json'` returns nothing (build, release and lockfile wiring is gone);
- every other hit of `git grep -n "extension-core\|extension-chrome" -- .
  ':!docs/superpowers' ':!docs/plans' ':!*CHANGELOG*'` is a reference into
  `nullnet-app/contextmint-bridge` — checked by reading each hit, not by a grep
  filter, since `docs/SECURITY.md`'s rewritten links and the server comments
  legitimately keep the `packages/extension-core/...` path and a line-based filter
  cannot see a repo name on the line above.
