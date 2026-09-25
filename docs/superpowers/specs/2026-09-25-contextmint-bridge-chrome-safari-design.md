# ContextMint Bridge — store-ready Chrome + Safari extensions (design)

**Date:** 2026-09-25
**Status:** Approved by owner 2026-09-25 (decisions at the end); ready for an implementation plan
**Supersedes:** the *Identity* section of
[`2026-05-21-transporter-cws-launch-design.md`](./2026-05-21-transporter-cws-launch-design.md).
That spec's permission, privacy and release-artifact reasoning still holds; its
store name (`Transporter`) does not. It also sequenced Firefox before Safari —
this spec reverses that; Firefox stays a follow-up.

---

## Goal

Ship the fetchproxy browser extension as two listed, signed, auto-updating
products under one store-facing name, **ContextMint Bridge**:

1. **Chrome Web Store** — covers Chrome, Edge, Arc and Brave (all install from CWS).
2. **Mac App Store** — a Safari Web Extension inside a minimal macOS container app.

Today the only install path is `git clone` → `npm run build` → Load Unpacked. The
README already links a CWS listing that was never published
(`EXTENSION_ID_PLACEHOLDER`), and ContextMint's designed onboarding
(`nullnet-design-system/system/ui_kits/contextmint/HANDOFF.md` Part 2) already
promises *"Install the ContextMint extension — Chrome, Edge, Arc or Safari — 400 KB,
no account"*. This spec makes that line true.

## Identity

**Store-facing: `ContextMint Bridge`.** The extension is ContextMint's "browser
bridge" (the name the ContextMint UI kit already uses throughout), not a separate
Mint-family product. It replaces `Transporter` everywhere a user reads it:

- `manifest.json` `name` / `short_name` (`Bridge`) / `description`
- CWS and App Store listing titles
- popup headings and copy (`extension-core/src/popup/`)
- **user-facing error strings in published packages** — `server/src/session-ready.ts`
  and `cli/src/bridge-errors.ts`, `cli/src/main.ts` tell people to "open the
  Transporter extension popup". These ship in `@fetchproxy/server` and
  `@fetchproxy/cli`, so the rename is a `fix:` release of those packages, not just an
  extension change. Code comments naming Transporter are updated opportunistically.

**Dev-facing stays `fetchproxy`** — repo, npm scope, `fpx`, the protocol, storage keys,
alarm names, `mcpId` shapes. One bridge sentence in the README:

> In the Chrome Web Store and Mac App Store it's **ContextMint Bridge**; the protocol
> and npm packages are **fetchproxy**. It works with ContextMint and with any
> fetchproxy-based MCP or `fpx` running on your machine.

That last clause also goes in both store descriptions: a user of a standalone
stdio MCP (`opentable-mcp`, `resy-mcp`) is installing a ContextMint-branded
extension without using ContextMint, and the listing must say that is supported.

**Mark: the Cursor C** (chosen 2026-09-25, chrischall/nullnet-design-system#21). The
nullnet cursor parked in the mouth of a C; the Bridge's own icon is two Cs facing with
the cursor laid flat between them as the link. The design system owns the masters in
`system/assets/`: `contextmint-bridge-icon.svg` with the Chrome 16/32/48/128 PNGs,
`contextmint-bridge-toolbar.svg` (Safari's monochrome toolbar template),
`contextmint-icon.svg` / `-1024.png` and `contextmint-wordmark.svg`. The extension copies
the PNGs into `extension-chrome/icons/`; the macOS `AppIcon` set is rendered from the SVG
when the Safari app is built. Still to make for the CWS listing: the 440×280 promo tile and
screenshots.

## Repository split

The extension leaves `chrischall/fetchproxy` for a new **`nullnet-app/contextmint-bridge`**
repo (owner decision, 2026-09-25). It is a product with a store listing, a signing
team and a release cadence of its own; fetchproxy stays the library, CLI and protocol.

**Why the split is clean.** `extension-core` and `extension-chrome` import exactly one
fetchproxy package — `@fetchproxy/protocol`, already on npm — and nothing in
fetchproxy imports them. The remaining coupling is prose: comments that cite
`extension-core/src/...` paths, three root doc-guard tests that read extension READMEs
or source (`install-walkthroughs-name-the-cohort`, `security-docs-match-the-main-world-bridge`,
`published-packages-ship-no-tests`), and the two release workflows that build and zip
the extension.

**What moves** (with history — `git filter-repo --path packages/extension-core
--path packages/extension-chrome` plus the docs below — so blame and the long
rationale comments survive):

- `packages/extension-core`, `packages/extension-chrome`, and the extension half of
  the cross-version refusal tests (`extension-core/tests/cross-version/`)
- `docs/PRIVACY.md` (it is the extension's privacy policy; store listings link it)
  and `docs/store-assets/`
- the extension build/zip steps of `release-please.yml` / `release-please-next.yml`

**What stays in fetchproxy:** protocol, server, bootstrap, cli, test-helpers,
`docs/PROTOCOL.md`, `docs/SECURITY.md` (the threat model spans both halves; its
extension sections point at the new repo's paths), `docs/REACHING-AN-API.md`.

**Versioning decouples, and the protocol number becomes the contract.** Today every
package, the extension included, shares one lockstep version, and user-facing
messages lean on that: `server/src/session-ready.ts` says "update Transporter to
`${MIN_VERSION}`" (a *server* package version), `cli/src/bridge-errors.ts` says "both
halves of the bridge ship as one release", and `extension-core/src/lib/version-mismatch.ts`
pins `MIN_SERVER_VERSION = '3.0.0'`. After the split the extension has its own
release-please line starting at **1.0.0** (a first store release is a fresh product,
not fetchproxy 3.x), so every one of these messages must speak in **protocol
numbers** ("needs a ContextMint Bridge that speaks fetchproxy protocol 4 — update it
from the Chrome Web Store / App Store") and never compare an extension version to a
server version. That is a `fix:` release of `@fetchproxy/server` and `@fetchproxy/cli`,
shipped together with the rename.

**Dev loop across two repos.** A protocol change now lands in fetchproxy first and
reaches the extension as a dependency bump (a first-party bump, so `feat:`/`fix:`, never
`chore(deps)`). fetchproxy's existing `next` prerelease channel
(`release-please-next.yml`) is how an unreleased protocol change is tried in the
extension: the bridge repo's CI runs its suite against both `@fetchproxy/protocol@latest`
and `@next`, so a breaking protocol change shows up red in the bridge before it ships.
Local iteration across both uses `npm link`.

**Visibility: public.** The extension's security claim — the relay cannot read your
traffic; the extension only touches declared domains — is checkable only if the code
that ships to the stores is readable, and the GitHub-release zip exists for exactly
that reproducibility audit. The nullnet default is private; this repo is the exception.

**Fleet wiring** as for any nullnet repo: `chrischall/workflows` reusable CI,
auto-review, release-please with `NULLNET_RELEASE_PAT`, fleet labels. Its CLAUDE.md
carries only what is true of this repo.

## Architecture (in `nullnet-app/contextmint-bridge`)

```
packages/
  extension-core/        shared TS (moved; gains a platform seam)
  extension-chrome/      MV3 manifest + esbuild → dist/ → CWS zip (moved)
  extension-safari/      NEW: manifest overlay + esbuild → Resources/
    xcode/               xcodegen project.yml → macOS container app + .appex
```

- **`extension-safari`** reuses `extension-chrome`'s esbuild entry points against
  `extension-core`; it owns only its manifest, the platform constant, and the Xcode
  project. No forked source.
- **Xcode project is generated** from a checked-in `project.yml` (xcodegen, as
  `nullnet-app/mcp-host-app/ios` already does), not a committed `.xcodeproj` from
  `safari-web-extension-packager`. The packager is used once, to learn the shape,
  then discarded.
- **Container app** is a single SwiftUI window: what the bridge is, a live
  "enabled in Safari?" check (`SFSafariExtensionManager.getStateOfSafariExtension`),
  and a button that opens Safari's extension settings
  (`SFSafariApplication.showPreferencesForExtension`). No networking, no account,
  no data.
- **Platform seam.** `background/socket.ts` hardcodes `platform: 'chrome'` in the
  hello. It becomes a build-time define (`__FETCHPROXY_PLATFORM__`) set by each
  target's `build.ts`; the protocol validator already accepts `'safari'`.
- **Capability seam.** The extension advertises only capabilities whose browser
  APIs exist at runtime. A Safari MCP that needs an unsupported capability must
  get a typed refusal at pair/hello time, not a mid-request `undefined is not a
  function`. Whether the protocol already carries an extension-side capability
  list, or this needs a (minor, additive) protocol change, is the plan's first
  question.

## Safari: what has to be proven first (spike, before any build work)

MV3 in Safari is close to Chrome but not equal, and fetchproxy leans on the parts
most likely to differ. Each row is **unverified** until the spike runs it on the
current Safari on this Mac:

| Concern | Used by | Risk |
|---|---|---|
| Service-worker lifetime with an open `ws://127.0.0.1:37149` socket; `alarms` at 0.4 min (`keepalive.ts`) | everything | Safari may terminate the worker more aggressively than Chrome; the keepalive may not hold |
| `ws://` loopback from an extension worker; origin sent is `safari-web-extension://<uuid>` | concentrator origin gate (`server/src/host.ts` already admits it) | low, but untested end to end |
| `wss://` remote bridge targets (2.1.0+) | ContextMint hosted MCPs | should work; needs a real gateway round trip |
| `scripting.executeScript` with `world: 'MAIN'` | `graphql` capability | Safari support/version floor unknown |
| `cookies` incl. HttpOnly, partitioned | `read_cookies`, `writeCookies` | Safari's cookie API has historically lagged |
| `webRequest` `onBeforeSendHeaders` with `requestHeaders` | `captureRequestHeader` (`handlers/capture.ts`) | likely limited or absent |
| `downloads` | `handlers/download.ts` | likely absent |
| `tabGroups` | `ensure-domain-tab.ts` | absent in Safari |
| Per-site permission grants for `<all_urls>` | tab routing | Safari asks the user per site unless they choose "all websites" — onboarding copy must cover it |

**Spike output:** a table of the above marked works / degraded / absent, and a go /
no-go. Absent APIs feed the capability seam; a failing keepalive is a no-go until
solved (e.g. reconnect-on-wake semantics) and gets its own design note.

## Chrome: what changes

- Manifest rename + description (≤132 chars); `version` driven by the bridge
  repo's release-please (`extra-files` on `extension-chrome/manifest.json`, as
  fetchproxy's config does today).
- **Permissions stay as they are for first submission** (`storage`, `tabs`,
  `scripting`, `cookies`, `webRequest`, `alarms`, `downloads`, `tabGroups`,
  `<all_urls>`). `docs/store-assets/permission-justifications.md` gains the two it
  lacks (`downloads`, `tabGroups`) and is rebranded. Narrowing to
  `optional_host_permissions` requested at pair time is the right long-term shape
  (the pair flow already knows the declared domains) but is a follow-up — it is a
  behaviour change with its own security review, and CWS accepts the broad set
  with justification.
- **Publisher: a nullnet group publisher** on the Chrome Web Store (approved
  2026-09-25), so the listing belongs to the org, not a personal account.
- **First upload is manual** (it mints the extension ID). Then the bridge repo's
  `release-please.yml` gains a CWS publish job (Chrome Web Store API, OAuth
  client + refresh token as repo secrets), gated on the release, idempotent, and
  followed by a check that the listed version matches the tag — the "green tag is
  not a green publish" rule applied to CWS.
- The GitHub-release `.zip` stays (sideload, audit, future Firefox).

## Safari: signing, distribution, release

- **Distribution: Mac App Store** (auto-update, no Gatekeeper friction). Developer
  ID + notarization is the fallback if App Review rejects the permission set.
- **Team: nullnet.** The shared distribution cert and CI dev cert already exist for
  nullnet apps, and the org secrets reach `nullnet-app/contextmint-bridge` with no
  copying. Bundle IDs (approved 2026-09-25): `app.nullnet.contextmint.bridge` (app)
  and `app.nullnet.contextmint.bridge.extension` (appex).
- **CI** runs on the shared `[self-hosted, macOS]` runner with the temp-keychain
  hygiene the other Apple release jobs use. Version: `CFBundleShortVersionString`
  = the release-please version; build number = `run_number*100+run_attempt`
  (fleet convention). Upload via `asc`; submission for review stays a human step
  until the first review passes.
- **iOS/iPadOS** is out of scope. Note for later: a universal container app could
  ship the same extension to iOS Safari, where it would be useful **only** with a
  remote (`wss://`) ContextMint bridge target, since no local MCP runs on a phone.

## Migration for existing sideload users

A store install is a new extension ID with an empty `chrome.storage` — new
extension identity, no trust records. Every paired MCP pins the old extension
identity, so each will see a different extension and prompt to re-pair. The plan
must verify that path is a clean re-pair prompt, not a hard refusal, for both
local MCPs and mcp-host's hosted rows, and README/PRIVACY must say "remove the
unpacked Transporter, install ContextMint Bridge, re-approve each MCP once".

## Out of scope

- **Account-level pairing** (`mcp-host/docs/BRIDGE-ACCOUNT-PAIRING.md`, still a
  design). ContextMint's onboarding step "Open it and hit Pair — the extension asks
  your context for this code" depends on it. Until then a ContextMint user adds
  the gateway as a remote bridge (URL + `mcpb_*` credential) in the popup's
  Bridges section, as today.
- Narrowing host permissions; Firefox/AMO; Edge Add-ons store (Edge installs from
  CWS); iOS Safari; renaming repo, npm packages, or protocol.
- Designing the ContextMint mark (done in the design system; see Identity → Mark).

## Testing (TDD throughout)

- Manifest parity test: Chrome and Safari manifests agree on name, version,
  description; Safari's permission list is Chrome's minus the spike's "absent"
  set, and nothing more.
- Platform define: built bundle's hello carries `platform: 'safari'` / `'chrome'`.
- Capability seam: with `chrome.downloads` / `tabGroups` / `webRequest` undefined,
  the extension does not advertise them, and a request for one yields the typed
  refusal.
- Brand guard, one per repo: no user-facing string in the bridge's popup, or in
  fetchproxy's `server/src/session-ready.ts` / `cli/src`, contains `Transporter`.
- Version-message guard (fetchproxy): no server/cli message compares an extension
  version to a package version; mismatch messages name protocol numbers only.
- `xcodebuild` build of the container app in CI (no signing on PRs).
- Manual live check per store build: fresh install → pair `opentable-mcp` →
  `opentable_list_reservations` returns data; and one hosted round trip through
  the ContextMint gateway (`alltrails`, per mcp-host's 2026-09-09 check).
- `npm test` **and** `npm run typecheck` green in both repos.

## Success criteria

1. ContextMint Bridge is live on the Chrome Web Store and the Mac App Store, and
   each auto-publishes from a release-please release (Safari: to review).
2. Both pass the live local and hosted checks above.
3. README, `packages/*/README.md`, `docs/PRIVACY.md`, store-assets and user-facing
   error strings say ContextMint Bridge; the README install link is real.
4. The cohort-MCP README sweep (separate follow-up) points at the two listings.

## Sequencing

Each step leaves both repos shippable; the extension is never absent from both.

1. **Create `nullnet-app/contextmint-bridge`** from a history-preserving filter of
   fetchproxy; `@fetchproxy/protocol` from npm; CI green against `latest` and `next`.
2. **Remove the extension from fetchproxy**: delete the packages, re-aim the doc-guard
   tests and release workflows, repoint README install steps. Same PR ships the
   protocol-number messaging and the ContextMint Bridge wording in server/cli
   (`fix:`).
3. **Rebrand + platform/capability seams** in the bridge repo; release 1.0.0 as a
   GitHub-release zip.
4. **Chrome Web Store** listing under the nullnet publisher (icons from the design system; promo tile + screenshots to make).
5. **Safari spike** → go/no-go.
6. **Safari build** → Mac App Store.

## Decisions (owner, 2026-09-25)

1. Bundle IDs `app.nullnet.contextmint.bridge[.extension]` — approved.
2. Extension packages **move** to `nullnet-app/contextmint-bridge`.
3. CWS publisher of record: **nullnet** group publisher.
