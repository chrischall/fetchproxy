# Transporter — Chrome Web Store launch (design)

**Date:** 2026-05-21
**Status:** Approved, ready for implementation plan
**Scope:** Chrome Web Store only. Firefox (AMO) and Safari (Mac App Store) are sequential follow-ups, each with their own spec.

---

## Goal

Ship the fetchproxy browser extension to the Chrome Web Store as an officially-listed, signed, one-click-install extension. Today the only way to install it is `git clone + npm run build + Load Unpacked` — that's fine for the author and a handful of early adopters, but blocks the cohort MCPs (HoneyBook, OFW, OpenTable, Resy, Zola, SignUpGenius, Canvas, Infinite Campus, Credit Karma) from recommending the extension to end users.

After this spec lands, the cohort MCPs can replace their "install the fetchproxy 0.4.0 browser extension" instructions with a single Chrome Web Store URL.

## Identity

**Store-facing name: `Transporter`** — the evocative metaphor (request dematerializes locally and rematerializes through the user's signed-in browser session) carries the user experience. Appears in:

- `manifest.json` `name` field (toolbar tooltip + install dialog + extension management page)
- Chrome Web Store listing title (search results + install page)
- Popup UI headings (replaces `fetchproxy` wordmark in the trust list + pair prompt + diff render)

**Dev-facing name stays `fetchproxy`** — npm packages (`@fetchproxy/protocol`, `@fetchproxy/server`, `@fetchproxy/bootstrap`, `@fetchproxy/extension-core`, `@fetchproxy/extension-chrome`), repo (`chrischall/fetchproxy`), CLAUDE.md, README technical sections, the cohort MCPs' docs, the trust-record `serverName` field (the MCP's own identity, not the extension's). One bridge sentence in the repo README:

> In the Chrome Web Store it's listed as **Transporter**; the protocol and npm packages are **fetchproxy**.

**Trek-flavored visual identity**, but no literal transporter-pad imagery (Paramount IP risk). Geometric portal/aperture motif with a passing arrow or particle.

## Manifest changes

`packages/extension-chrome/manifest.json` edits:

```json
{
  "name": "Transporter",
  "description": "Bridge local MCP servers to your signed-in browser tabs — let agentic tools hit authenticated APIs without copying credentials.",
  "version": "<set by next Tag & Bump — main is currently 0.4.3, so the launch tag will be v0.4.3>",
  ...
}
```

131-char description (fits the 132-char CWS limit). Version stays on the natural T&B cadence — no jump to 1.0.0. The protocol is still iterating; semver discipline says 1.0.0 implies API stability we don't yet have.

## Permission strategy

Keep the current permission set:

```json
"permissions": ["storage", "tabs", "scripting", "cookies", "webRequest", "alarms"],
"host_permissions": ["<all_urls>"]
```

Each permission has a CWS-required justification text. Drafts (live in `docs/store-assets/listing-description.md` for review):

| Permission | Justification |
|---|---|
| `storage` | Persist per-MCP trust records (`identityHash → {capabilities, domains, ...}`), the extension's own X25519 + Ed25519 identity keypair, and transient pending-pair state across service-worker restarts. No data leaves the user's machine. |
| `tabs` | Find the signed-in tab on a declared domain (HoneyBook vendor portals, Canvas school subdomains, etc.) and route requests through it. Tab matching is by host-or-subdomain against the MCP-declared `domains[]` list. |
| `scripting` | Inject the content script that issues `fetch()` from the page context with cookies. Extension-context fetches don't carry the tab's TLS fingerprint + cookie jar. |
| `cookies` | Optional capability: `read_cookies`. An MCP must declare specific cookie keys at pair time; the user approves the keys before any read. HttpOnly cookies are accessible only via this API. |
| `webRequest` | Optional capability: `capture_request_header`. One-shot `onBeforeSendHeaders` listener for an MCP-declared URL pattern, captures one header value, removes itself. Never modifies outgoing requests. |
| `alarms` | MV3 service-worker keepalive only — a single 24-second alarm fires `connect()` (idempotent) to prevent the bridge from silently dropping. No scheduling, no payload. |
| `host_permissions: <all_urls>` | Per-MCP domain set is declared dynamically at pair time, can't be enumerated statically. The runtime gate is the per-MCP `domains[]` allowlist (host-or-subdomain match) checked before every fetch / cookie read / storage read / header capture. |

**`<all_urls>` is the most-scrutinized permission**, but the per-MCP `domains[]` runtime check is the actual enforcement. If a reviewer rejects this justification, the fallback is `optional_host_permissions: ['<all_urls>']` + `chrome.permissions.request({origins: [...]}) ` on each pair — a ~30 line code change in `background.ts`, not in this spec's scope to implement preemptively.

**Single-purpose statement** for the CWS form:

> Relay HTTP fetches and read user-declared session data (cookies, localStorage, request headers) between a local MCP server and the user's signed-in browser tab on a domain the user has explicitly approved at pair time.

## Branding assets

All assets check into the repo so the listing is reproducible from git:

```
packages/extension-chrome/icons/
  16.png      (new, replaces placeholder)
  32.png      (new — manifest currently only ships 16/48/128)
  48.png      (new)
  128.png     (new)
docs/store-assets/
  promo-tile.png             (440 × 280, CWS-required)
  screenshots/
    01-pair-prompt.png       (1280 × 800)
    02-trusted-mcps.png      (1280 × 800)
    03-architecture.png      (1280 × 800)
  listing-description.md     (long description, prepared for paste)
  permission-justifications.md  (per-permission text, prepared for paste)
docs/
  PRIVACY.md                 (privacy policy, served via GitHub Pages)
```

**Icon design direction.** Stylized geometric portal/aperture — two concentric rings with a horizontal arrow passing through, OR a pad-with-rising-column motif. Single-color flat design (Chrome's toolbar makes detailed icons illegible at 16px). Single SVG source → exported PNGs at the four target sizes.

**Screenshots:**
1. **Pair-code popup** — the security-critical UX moment, showing the 6-digit code + scope diff. Sells "no surprise permissions."
2. **Trusted-MCPs list with revoke buttons** — what users see day-to-day.
3. **Architectural diagram** with wordmark — local MCP → extension → signed-in tab → service. Visual hook for non-developers.

**Listing description** (~600–800 words): explains what it does, who it's for, how the pair flow works, the security model summary, and a permission-by-permission breakdown. Full draft in Section 3 of the brainstorm (will commit to `docs/store-assets/listing-description.md`).

**Privacy policy:** new file at `docs/PRIVACY.md`, served via GitHub Pages on the fetchproxy repo (enable Pages on `main`, `/docs` folder). Listing-form URL: `https://chrischall.github.io/fetchproxy/PRIVACY.html`. Covers what data is processed (locally), what's stored (trust records + identity keys in `chrome.storage.local`), what's shared externally (nothing), revoke + uninstall paths, contact email.

**Popup wordmark change:** `packages/extension-core/src/popup/popup.html` `<title>` + `popup.ts` headings replace `fetchproxy` with `Transporter`. The trust-record `serverName` field (the MCP's own identity, e.g. `opentable-mcp`) is unchanged.

## CWS submission flow

**Developer account:** sign in to [chrome.google.com/webstore/devconsole](https://chrome.google.com/webstore/devconsole) with the long-lived Google account that owns the listing. Pay the $5 one-time developer fee, accept the Developer Program Policies.

**Listing form fields:**

| Field | Source |
|---|---|
| Extension package | The `fetchproxy-extension-${VERSION}.zip` already produced by the Release workflow |
| Item name | `Transporter` |
| Item summary | 132-char description from the manifest |
| Detailed description | `docs/store-assets/listing-description.md` |
| Category | Developer Tools |
| Store icon | `packages/extension-chrome/icons/128.png` |
| Small promo tile | `docs/store-assets/promo-tile.png` |
| Screenshots | The three 1280×800 PNGs from `docs/store-assets/screenshots/` |
| Privacy policy URL | `https://chrischall.github.io/fetchproxy/PRIVACY.html` |
| Single purpose | The statement from §"Permission strategy" |
| Permission justifications | Per-permission paragraphs from §"Permission strategy" |
| Data usage disclosure | "I do not collect or use any user data" — none of the listed categories apply |
| Distribution | Public, all regions |
| Pricing | Free |
| Support email | `chris.c.hall@gmail.com` |
| Support URL | `https://github.com/chrischall/fetchproxy` |

**Review timing.** First-submission review for a permission-heavy extension (`<all_urls>` + `cookies` + `webRequest`) historically takes 3–7 business days; can be longer with back-and-forth. Subsequent updates without new permissions go through expedited review (often <24h).

**Anticipated reviewer pushback:**

1. **`<all_urls>` scope** — addressed in the justification by naming the runtime per-MCP `domains[]` gate.
2. **`cookies` + `webRequest` combined** — addressed by the screenshot of the pair popup with explicit scope diff. Users opt in per-MCP, per-key.
3. **Single-purpose policy** — framed as one composite purpose (MCP↔browser bridge), not unrelated features.
4. **No external code** — already MV3-compliant; the bundle is fully self-contained.

## Transition for existing users

Today's users (the author + early adopters via sideload) have an unpacked extension with a temporary developer ID. CWS-published extensions get a permanent assigned ID; Chrome treats them as separate extensions, not an upgrade path.

**What carries over:**

| Item | Location | Carries over? |
|---|---|---|
| Extension's identity keypair | `chrome.storage.local` of the unpacked extension | **No** — CWS install starts fresh |
| Per-MCP trust records | `chrome.storage.local` of the unpacked extension | **No** — same |
| MCP-side identity keys | `~/.fetchproxy/identity/<server-name>.json` | **Yes** — outside the extension |
| MCP-side captured sessions (e.g. `~/.honeybook-mcp/sessions.json`) | MCP-owned files | **Yes** — outside the extension |

**Consequence:** existing users need to **re-pair each MCP once** with the new Transporter extension. First fetch through Transporter → no trust record → needs-pair popup with a fresh 6-digit code → user approves. No data loss; captured sessions, MCP identity keys, and downloaded data all stay put.

**Documentation:**

1. `packages/extension-chrome/README.md` — add "Migrating from the unpacked dev install" section.
2. The fetchproxy GitHub Release notes for the CWS-debut version — call out the one-time re-pair with screenshots.
3. Cohort MCP READMEs — replace "install fetchproxy 0.4.0 extension" / "sideload the .zip" with the Transporter CWS URL. One-off `docs/` PR per cohort repo. **Not in this spec's core scope** — sweep happens after Transporter is live.

## Build & release pipeline

**Initial CWS upload is manual.** First-submission review wants careful eyes on each form field. Upload `fetchproxy-extension-${VERSION}.zip` (the artifact attached to the GitHub release that lands after the next Tag & Bump — currently `v0.4.3`) by hand through `chrome.google.com/webstore/devconsole`, fill in fields from `docs/store-assets/`, submit for review.

**The Release workflow already produces the right artifact** — no packaging changes. Existing flow:

- `v*` tag push → `Release` workflow
- Builds workspaces in dep order
- npm publish protocol / server / bootstrap (already wired)
- Builds the Chrome extension bundle → zips → attaches to GitHub release

The CWS Publisher API automation step (`chrome-webstore-upload-cli` invoked from `release.yml`) is **deferred to a follow-up** after first review is clean. Adding it now would couple manifest-asset polish with infrastructure work that's only worth it after the listing is established.

**GitHub release artifact stays** even after CWS automation lands. The `.zip` is needed for:

- The eventual Firefox port (AMO accepts essentially the same artifact with manifest tweaks)
- Power users who sideload (self-hosted Chromium, dev profiles)
- Reproducibility audits (anyone can verify the CWS-listed code matches what the open-source repo built)

## Future-proofing for Firefox + Safari

Choices made in this spec that ease the next two sub-projects:

- **Branding assets are browser-neutral.** Icons, promo tile, screenshots, long description, privacy policy all in `docs/store-assets/` and `docs/PRIVACY.md`. AMO + Mac App Store take the same artwork (with format conversions handled per-store).
- **Store-only rebrand keeps the codebase brand-stable.** Source code in `extension-core` doesn't change when more browsers are added.
- **Privacy policy is hosted, not embedded.** Same URL works for AMO and App Store listings.
- **Permission justifications are reusable.** Firefox calls them the same name; Apple App Store maps them onto "App Privacy" labels with the underlying claims preserved.

**Anticipated structural refactor for the Firefox spec** (not now): rename `packages/extension-chrome` → `packages/extension-chromium` (covers Chrome + Edge + Brave) and add a sibling `packages/extension-firefox`. Both depend on `@fetchproxy/extension-core`. The Chrome → Chromium rename is cosmetic; it happens when Firefox actually needs a parallel package.

## Out of scope

Each gets its own design + plan when its time comes:

- **Firefox AMO submission.** Immediately after Chrome lands and the listing is stable. ~95% code reuse; manifest delta + `webextension-polyfill` for `chrome.*` → `browser.*`.
- **Safari Mac App Store submission.** After Firefox. Requires Xcode + Apple Developer Program ($99/yr) + a Swift wrapper app. Apple's `safari-web-extension-converter` generates the Xcode scaffold from the existing manifest.
- **Renaming repo / npm packages.** Never, per the store-only rebrand decision.
- **Renaming `@fetchproxy/bootstrap` / `@fetchproxy/server` API surface.** Not in this spec.
- **Automating CWS upload via the Publisher API.** Deferred to follow-up after first review passes.
- **`optional_host_permissions` audit.** Deferred unless CWS pushes back.
- **Resolving fetchproxy [#9](https://github.com/chrischall/fetchproxy/issues/9), [#10](https://github.com/chrischall/fetchproxy/issues/10), [#11](https://github.com/chrischall/fetchproxy/issues/11).** Independent tracking issues; don't block launch.

## Success criteria

1. `Transporter` is a discoverable, installable listing on `chrome.google.com/webstore`.
2. The CWS-installed Transporter passes a live end-to-end test: pair with `opentable-mcp` from a fresh install → run `opentable_list_reservations` → see real reservation data.
3. The fetchproxy repo's `README.md`, `packages/extension-chrome/README.md`, and `docs/PRIVACY.md` document the new install path + the one-time migration for existing sideload users.
4. The cohort MCP README sweep (separate follow-up) replaces sideload instructions with the Transporter CWS URL across all 9 repos.
5. No regressions in fetchproxy's existing 453-test vitest suite.
6. The next Tag & Bump → Release pipeline produces a CWS-uploadable `.zip` exactly as it does today (no infrastructure change).
