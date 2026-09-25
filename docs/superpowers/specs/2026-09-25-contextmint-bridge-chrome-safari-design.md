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

Ship the fetchproxy browser extension, under the store-facing name **ContextMint
Bridge**, to:

1. **Chrome Web Store** — covers Chrome, Edge, Arc and Brave (all install from CWS).
2. **Safari, inside the ContextMint app** — a Safari Web Extension embedded in
   ContextMint's own Apple apps (`nullnet-app/mcp-host-app`, bundle ID
   `app.nullnet.mcphost`): a **ContextMint for Mac v0** built for it (scoped in by the
   owner, 2026-09-25, so the Safari extension can be tested on this Mac), then the
   **iOS/iPadOS app**. Everything goes under `mcphost`.
   There is no standalone "ContextMint Bridge" Apple app.

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
- the CWS listing title, and the extension's name in Safari's extension settings
- popup headings and copy (`extension-core/src/popup/`)
- **user-facing error strings in published packages** — `server/src/session-ready.ts`
  and `cli/src/bridge-errors.ts`, `cli/src/main.ts` tell people to "open the
  Transporter extension popup". These ship in `@fetchproxy/server` and
  `@fetchproxy/cli`, so the rename is a `fix:` release of those packages, not just an
  extension change. Code comments naming Transporter are updated opportunistically.

**Dev-facing stays `fetchproxy`** — repo, npm scope, `fpx`, the protocol, storage keys,
alarm names, `mcpId` shapes. One bridge sentence in the README:

> In the Chrome Web Store (and in Safari, inside the ContextMint app) it's **ContextMint Bridge**; the protocol
> and npm packages are **fetchproxy**. It works with ContextMint and with any
> fetchproxy-based MCP or `fpx` running on your machine.

That last clause also goes in the CWS description: a user of a standalone
stdio MCP (`opentable-mcp`, `resy-mcp`) is installing a ContextMint-branded
extension without using ContextMint, and the listing must say that is supported.

**Mark: the Cursor C** (chosen 2026-09-25, chrischall/nullnet-design-system#21). The
nullnet cursor parked in the mouth of a C; the Bridge's own icon is two Cs facing with
the cursor laid flat between them as the link. The design system owns the masters in
`system/assets/`: `contextmint-bridge-icon.svg` with the Chrome 16/32/48/128 PNGs,
`contextmint-bridge-toolbar.svg` (Safari's monochrome toolbar template),
`contextmint-icon.svg` / `-1024.png` and `contextmint-wordmark.svg`. The extension copies
the PNGs into `extension-chrome/icons/`; the Safari extension uses the same PNGs plus the
toolbar template, and needs no app icon of its own (its container is ContextMint). Still to make for the CWS listing: the 440×280 promo tile and
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
  extension-safari/      NEW: manifest overlay + esbuild → safari-resources zip
```

- **`extension-safari`** reuses `extension-chrome`'s esbuild entry points against
  `extension-core`; it owns only its manifest and the platform constant. No forked
  source, **no Xcode**. Its output — the web-extension resources (manifest, JS,
  popup, icons) — is attached to each bridge release as
  `contextmint-bridge-safari-${VERSION}.zip` with its SHA-256, like the Chrome zip.
- **The Apple side lives in `nullnet-app/mcp-host-app`.** Its xcodegen
  `project.yml` gains a Safari Web Extension target (`.appex`) embedded in the
  ContextMint macOS app (first) and the iOS app. The appex's `Resources/` is the
  safari-resources zip at a **pinned bridge version**, fetched and hash-checked at
  build time; bumping the pin is an ordinary first-party dependency bump (`feat:`/
  `fix:`). The extension therefore ships with, and is versioned by, ContextMint app
  releases.
- **Pairing hand-off through the app.** Because the extension lives inside
  ContextMint, the app can give it the gateway bridge target (URL + `mcpb_*`
  credential) directly: the app writes it to the shared App Group container, the
  appex's `SafariWebExtensionHandler` reads it, and the extension asks for it with
  `browser.runtime.sendNativeMessage`. On Apple platforms that replaces pasting a URL
  and token into the popup, and it is the first concrete piece of the designed
  "Open it and hit Pair" step. The credential stays in the Keychain/App Group, never
  in `storage.local` (the extension's own rule).
- **App surface** in ContextMint: the existing Browser bridge rows (HANDOFF Part 2)
  gain the Safari state ("enabled in Safari?" via
  `SFSafariExtensionManager.getStateOfSafariExtension` on macOS; on iOS, which has
  no such API, a status the extension reports back through the App Group) and a
  button to Safari's extension settings.
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

The spike runs on macOS Safari **and** iOS Safari (iPhone and iPad).

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
| **iOS: how long the worker and its `wss://` socket survive** — Safari foreground, Safari backgrounded while ContextMint or Claude is in front, screen locked | live relay on iOS | expected: suspended within seconds of Safari leaving the screen, which would make live relay impossible on iPhone |
| **iOS: iPad Split View / Stage Manager** with Safari visible beside another app | live relay on iPad | may keep the worker alive; unknown |
| **iOS: session lift** (`read_cookies`, storage reads) triggered by the user in the popup, pushed to the gateway | Pattern-A MCPs (bootstrap) | should work — it needs Safari only for the moment of the lift |
| **App Group hand-off**: app → App Group → `SafariWebExtensionHandler` → `sendNativeMessage` | pairing | standard on both platforms; confirm on iOS |

**Spike output:** a table of the above marked works / degraded / absent, and a go /
no-go. Absent APIs feed the capability seam; a failing keepalive is a no-go until
solved (e.g. reconnect-on-wake semantics) and gets its own design note.

### Spike results — macOS (2026-09-25, Safari 27 / Xcode 27, fetchproxy 3.2.2 bundle)

Run live on the owner's Mac: container from `safari-web-extension-packager`, a
persistent `@fetchproxy/server` host on `127.0.0.1:37149`, profile
`fpx-safari-spike` on `wikipedia.org`, a signed-in `en.wikipedia.org` tab.

| Concern | Result | Consequence for `extension-safari` |
|---|---|---|
| Code signing | **Ad-hoc signing does not run.** The toolbar icon appears but neither popup nor background ever executes — same for a hello-world extension. An Apple Development identity (team `5A673K24X6`) makes both run. | Local dev builds must be Apple-Development-signed; the Mac app plan already signs. Unsigned mode is not a usable dev loop on Safari 27. |
| MV3 service worker (`background.service_worker`, module **or** classic) | **Did not run**, in our bundle and in a hello-world. | Ship the background as an **event page**: `"background": {"scripts": ["background.js"], "persistent": false}`. |
| ES-module background (`"type": "module"`) | Unsupported (packager warns; confirmed). | Bundle `background.js` as a **classic script** (esbuild `format: 'iife'`, no trailing `export {}` — today's Chrome bundle only exports for tests). |
| Event-page lifetime with an open loopback socket | **Stayed connected 10/10** — one fetch a minute for 10 minutes, 84–403 ms each, Safari open but idle. The first connect dropped once after ~18 s during pairing and reconnected on the next keepalive. | Keepalive design holds on macOS; no go-blocker. Behaviour with Safari quit / Mac asleep not measured. |
| `ws://127.0.0.1:37149` from the extension; `safari-web-extension://` origin | **Works**; the concentrator's origin gate admits it. | None. |
| Pairing + protocol-4 session (X25519 ECDH, Ed25519 signatures, AES-GCM) | **Works** once identity storage is fixed (next row). | None. |
| Identity in the IndexedDB vault | **Broken: WebKit IndexedDB silently stores an X25519 `CryptoKey` as `null`** — and nulls any object containing one. No error on `put`. Ed25519 `CryptoKey`s and `Uint8Array`s round-trip fine. Result: `loadOrCreateExtensionIdentity` throws "extension identity missing from the vault", the extension never connects. | Safari-safe identity storage is required (design note below). The spike stored the X25519 private key as PKCS#8 bytes and re-imported it non-extractable on load — proven to work, but it leaves the key extractable at rest, so it is not the shipping design. |
| Detached API call (`const q = api().tabs.query; q({})`) | Returns `undefined` in Safari. | Fixed for all targets in contextmint-bridge #7. |
| `fetch` via content script | **200**, 212 ms. | None. |
| `fetch` with `inPage: true` (MAIN world via `scripting.executeScript`) | **200**, 92 ms — runtime MAIN-world injection works even though the manifest `world` key is unsupported. | `fetch_in_page` / `graphql` viable; keep MAIN-world scripts runtime-registered, not manifest-declared. |
| `read_cookies`, legacy no-keys shape (`document.cookie`) | Works (returns the page's non-HttpOnly cookie string — by design, as on Chrome). | None. |
| `read_cookies` with declared keys (`chrome.cookies`, HttpOnly) | **Works, scoped**: returned exactly the two declared keys (`GeoIP`, `WMF-Last-Access`) and nothing else; needs no open tab. | None. |
| `read_local_storage` | Answered (`{}` — the declared key does not exist on Wikipedia, so this proves the path, not the content). | — |
| `downloads` | **Absent** (`chrome.downloads` undefined). | Capability seam: refuse `download` at pair time on Safari. |
| `tabGroups` | Absent (packager); relay tab grouping is already `?.`-guarded. | None. |
| `webRequest` header capture | **Inconclusive**: timed out after 20 s because no tab was open to make the request it listens for — not evidence either way about Safari's `webRequest`. | Re-run with a live tab; until then treat `capture_request_header` / `capture_redirect` as unproven on Safari. |
| Popup | Renders once the background runs; it was stuck on "Loading…" only because `get-connected-identities` had no live background to answer. | None. |

**Go** for macOS, with the three required changes: event-page background as a classic
script, Apple Development signing for dev builds, Safari-safe X25519 storage. iOS rows
remain open.

### Design note — Safari-safe X25519 identity storage

The vault's promise is that the private keys are non-extractable `CryptoKey`s at rest.
WebKit breaks that for X25519 only. Preferred fix, pending one more Safari check: a
non-extractable **AES-GCM wrapping key** generated once and stored in the vault (if
AES `CryptoKey`s round-trip in Safari's IndexedDB, as Ed25519 ones do), and the X25519
private key stored as `wrapKey('pkcs8', …)` output, unwrapped to a non-extractable key
on load. The raw key material then exists only transiently in memory — the same exposure
Chrome has during generation. Fallback if AES keys also null out: keep the PKCS#8 bytes
as the spike did and document the at-rest weakening in `docs/SECURITY.md` for the
Safari build only. Either way the vault stays one code path with a feature check
(round-trip a throwaway X25519 key once, pick the storage form), never a user-agent
sniff.

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

## ContextMint for Mac — v0

Scoped in 2026-09-25 as the Safari extension's macOS container and the first
ContextMint desktop surface. `mcp-host/docs/MOBILE_APPS.md` never considered a Mac
app; it gets a paragraph recording this.

- **Native macOS SwiftUI**, a second application target in `mcp-host-app`'s xcodegen
  `project.yml`, macOS 27, Apple silicon. **Not Mac Catalyst**: `:shared` is
  Kotlin/Native, which has no Catalyst target, so the iOS app's framework cannot link
  into a Catalyst build. **Not "Designed for iPad"** on Apple-silicon Macs: that runs
  the iOS binary, and a Safari extension embedded in it is not expected to load in
  macOS Safari (the spike confirms). So `:shared` gains `macosArm64()` beside its two
  iOS targets, and generated client, view models and contract pin are reused as-is.
- **v0 screens, and only these:** sign in (the existing auth callback flow), the
  **Browser bridge** screen from HANDOFF Part 2 (status; "enabled in Safari?" via
  `SFSafariExtensionManager.getStateOfSafariExtension`; "Open Safari settings" via
  `SFSafariApplication.showPreferencesForExtension`; the App Group hand-off of the
  gateway bridge target), and Settings/sign-out. Menu-bar presence is a candidate for
  v1, not v0.
- **Shared SwiftUI where it compiles.** 8 of the iOS app's 53 Swift files touch
  UIKit; those are the port surface for parity later. Views that build unchanged on
  both platforms join both targets from the start rather than being copied.
- **Look:** the base look from the design system, the Cursor C app icon
  (`contextmint-icon.svg`), dark pinned as on iOS.
- **Distribution:** TestFlight for macOS from mcp-host-app's existing release job on
  the `[self-hosted, macOS]` runner; App Store later, as a platform of the same
  record.

## Safari: signing, distribution, release

- **Distribution: inside ContextMint's App Store listings.** No separate Apple
  product, so no separate App Store record; the extension reaches users as a
  ContextMint app update. App Review sees the extension's permissions as part of
  ContextMint's submission.
- **Bundle IDs** (owner, 2026-09-25 — everything under `mcphost`): the extension
  appex is **`app.nullnet.mcphost.bridge`**, inside `app.nullnet.mcphost`. Apple
  requires an appex ID to be prefixed by its containing app's, which is why the
  earlier `app.nullnet.contextmint.bridge[.extension]` pair was withdrawn before
  anything was registered. The macOS app shares `app.nullnet.mcphost` (universal
  purchase: one App Store Connect record gains a macOS platform) and embeds the same
  `app.nullnet.mcphost.bridge`.
- **App Group** shared by app and appex: `group.app.nullnet.mcphost`.
- **Signing and CI** are mcp-host-app's existing ones: nullnet team, the shared
  distribution cert, the `[self-hosted, macOS]` runner, its versioning
  (`run_number*100+run_attempt`), TestFlight then review. The bridge repo signs
  nothing for Apple.
- **What iOS is for.** No MCP runs on a phone, so iOS uses only the remote
  (`wss://`) ContextMint gateway target, and iOS suspends Safari's extensions when
  Safari leaves the screen. Until the spike says otherwise, iOS v1 is scoped to
  **session lift** — the user opens Safari, taps Sync in the extension, and it
  pushes the declared session (cookies/tokens) to the gateway so hosted Pattern-A
  MCPs run server-side — plus **live relay where the spike shows the worker stays
  alive** (likely iPad Split View). Live relay for bot-walled sites on iPhone is not
  promised.

## Migration for existing sideload users

A store install is a new extension ID with an empty extension-origin IndexedDB
vault — the extension's identity keys and its trust records (`trustedMcps`,
`remoteBridges`, `dismissedScopeHashes`) live there, not in `chrome.storage` (see
`docs/SECURITY.md` Defense 4). So it mints a new extension identity and has no
trust records. Every paired MCP pins the old extension identity, and the MCP side
does **not** offer a re-pair for a different one: `decideExtensionTrust`
(`packages/server/src/extension-trust.ts`) returns `refused` unless the pin is
cleared or the MCP runs once with `FETCHPROXY_TRUST_NEW_EXTENSION=1`. That refusal
is deliberate (a different identity may be something else answering as the
browser), so the migration steps must include clearing the pin rather than expect
a prompt:

1. Remove the unpacked Transporter; install ContextMint Bridge from the store.
2. For each local MCP, clear its extension pin — `fpx trust clear <server-name>`
   (or `fpx trust clear --all`) — or start it once with
   `FETCHPROXY_TRUST_NEW_EXTENSION=1`.
3. Re-approve each MCP's pair code in the ContextMint Bridge popup once.

README/PRIVACY must carry those three steps. The plan must also verify what
mcp-host's hosted rows do when the extension identity changes (whether its pin
refuses the same way and how a user clears it) and document that path next to the
local one.

## Out of scope

- **Account-level pairing** (`mcp-host/docs/BRIDGE-ACCOUNT-PAIRING.md`, still a
  design). ContextMint's onboarding step "Open it and hit Pair — the extension asks
  your context for this code" depends on it. Until then a ContextMint user adds
  the gateway as a remote bridge (URL + `mcpb_*` credential) in the popup's
  Bridges section, as today.
- Narrowing host permissions; Firefox/AMO; Edge Add-ons store (Edge installs from
  CWS); renaming repo, npm packages, or protocol.
- **ContextMint for Mac beyond v0** — the context list, the add flow, Discover and
  Admin on the Mac. v0 is the Safari container plus what the bridge needs; parity with
  iOS is its own spec in `mcp-host-app`.
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
- Bridge repo: the safari-resources zip's manifest carries `platform` `'safari'`
  in its bundle and only the permissions the spike kept.
- mcp-host-app: `xcodebuild` of the iOS app with the embedded appex in CI (no signing
  on PRs); a test that the pinned resources zip's SHA-256 matches the release's
  published digest; App Group hand-off unit-tested on the Swift side.
- Manual live check per store build: fresh install → pair `opentable-mcp` →
  `opentable_list_reservations` returns data; and one hosted round trip through
  the ContextMint gateway (`alltrails`, per mcp-host's 2026-09-09 check).
- `npm test` **and** `npm run typecheck` green in both repos.

## Success criteria

1. ContextMint Bridge is live on the Chrome Web Store (auto-published from a
   release-please release), and the Safari extension ships inside ContextMint for
   Mac (TestFlight first) and a ContextMint iOS release.
2. Both pass the live local and hosted checks above.
3. README, `packages/*/README.md`, `docs/PRIVACY.md`, store-assets and user-facing
   error strings say ContextMint Bridge; the README install link is real.
4. The cohort-MCP README sweep (separate follow-up) points at the Chrome Web Store
   listing and at ContextMint (iOS and Mac) for Safari.

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
5. **Safari spike** (macOS + iOS) → go/no-go, and the iOS scope confirmed.
6. **`extension-safari`** in the bridge repo → safari-resources zip on each release.
7. **ContextMint for Mac v0 + the appex** in `mcp-host-app`, with the App Group
   pairing hand-off → local builds on this Mac → TestFlight for macOS.
8. **The same appex in the iOS app** → TestFlight → ContextMint iOS release.

The spike (5) does **not** wait for the Mac app: it runs against a throwaway container
from `xcrun safari-web-extension-packager` and Safari's *Allow unsigned extensions*,
which is enough to answer every row of its table. The Mac app is what the real,
signed extension and the pairing hand-off need.

## Decisions (owner, 2026-09-25)

1. ~~Bundle IDs `app.nullnet.contextmint.bridge[.extension]`~~ — withdrawn the same
   day, never registered. Safari ships inside ContextMint on iOS and macOS;
   appex `app.nullnet.mcphost.bridge`, App Group `group.app.nullnet.mcphost`.
2. Extension packages **move** to `nullnet-app/contextmint-bridge`.
3. CWS publisher of record: **nullnet** group publisher.
