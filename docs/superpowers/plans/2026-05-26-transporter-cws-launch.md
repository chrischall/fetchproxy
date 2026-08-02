# Transporter — Chrome Web Store Launch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the fetchproxy browser extension to the Chrome Web Store as "Transporter" — rebrand the user-facing name, create all required store assets and docs, and prepare everything for manual first submission.

**Architecture:** Config + docs change, no new runtime code. The manifest `name` and popup `<title>` change to "Transporter"; all protocol-level identifiers (`fetchproxy-fetch`, `fetchproxy-keepalive`, `@fetchproxy/*` packages, etc.) stay as-is. New files: privacy policy, store listing copy, permission justification text, icon SVG source + exported PNGs. GitHub Pages enabled on `docs/` for hosting the privacy policy.

**Tech Stack:** SVG → PNG export via `rsvg-convert` (librsvg, Homebrew). Vitest for regression. Markdown for all store copy.

**Spec:** `docs/superpowers/specs/2026-05-21-transporter-cws-launch-design.md`

---

## File map

| Action | Path | Purpose |
|--------|------|---------|
| Modify | `packages/extension-chrome/manifest.json` | `name` → "Transporter", `description` → CWS-ready 131-char, add `icons.32` |
| Modify | `packages/extension-core/src/popup/popup.html` | `<title>` → "Transporter" |
| Modify | `packages/extension-core/src/popup/popup.ts` | JSDoc header comment |
| Create | `packages/extension-chrome/icons/icon.svg` | Single SVG source for all icon sizes |
| Replace | `packages/extension-chrome/icons/16.png` | Exported from SVG |
| Create | `packages/extension-chrome/icons/32.png` | Exported from SVG (new size for CWS) |
| Replace | `packages/extension-chrome/icons/48.png` | Exported from SVG |
| Replace | `packages/extension-chrome/icons/128.png` | Exported from SVG |
| Modify | `packages/extension-chrome/build.ts` | No change needed — already copies all files in `icons/` |
| Create | `docs/PRIVACY.md` | Privacy policy (GitHub Pages will serve it) |
| Create | `docs/index.html` | Redirect to GitHub repo (GitHub Pages landing) |
| Create | `docs/.nojekyll` | Tell GitHub Pages not to process through Jekyll |
| Create | `docs/store-assets/listing-description.md` | CWS detailed description, ready to paste |
| Create | `docs/store-assets/permission-justifications.md` | Per-permission text for CWS review form |
| Modify | `README.md` | Bridge sentence, CWS install path, update "not yet on CWS" line |
| Modify | `packages/extension-chrome/README.md` | Migration-from-sideload section, CWS link placeholder |

---

### Task 1: Manifest rebrand

**Files:**
- Modify: `packages/extension-chrome/manifest.json`

- [ ] **Step 1: Update manifest name and description**

```json
{
  "name": "Transporter",
  "description": "Bridge local MCP servers to your signed-in browser tabs — let agentic tools hit authenticated APIs without copying credentials.",
  ...
}
```

Change `"name": "fetchproxy"` → `"name": "Transporter"` and `"description": "Relay authenticated fetch()…"` → the 131-char version above.

- [ ] **Step 2: Add 32px icon entry**

Add `"32": "icons/32.png"` to both `icons` and `action.default_icon`:

```json
{
  "icons": {
    "16": "icons/16.png",
    "32": "icons/32.png",
    "48": "icons/48.png",
    "128": "icons/128.png"
  },
  "action": {
    "default_icon": {
      "16": "icons/16.png",
      "32": "icons/32.png",
      "48": "icons/48.png",
      "128": "icons/128.png"
    }
  }
}
```

- [ ] **Step 3: Run tests to verify nothing broke**

```bash
npm test
```

Expected: all 453+ tests pass. The manifest is config, not tested directly, but the build must still work.

- [ ] **Step 4: Build the extension to verify manifest is valid**

```bash
npm run build --workspace=@fetchproxy/extension-chrome
```

Expected: builds without error, `dist/manifest.json` contains `"name": "Transporter"`.

- [ ] **Step 5: Commit**

```bash
git add packages/extension-chrome/manifest.json
git commit -m "feat(extension): rebrand manifest name to Transporter for CWS

Store-facing name becomes Transporter; dev-facing names (@fetchproxy/*,
protocol identifiers) stay as-is per the CWS launch spec."
```

---

### Task 2: Popup rebrand

**Files:**
- Modify: `packages/extension-core/src/popup/popup.html:5`
- Modify: `packages/extension-core/src/popup/popup.ts:2`

- [ ] **Step 1: Update popup.html title**

In `packages/extension-core/src/popup/popup.html` line 5, change:

```html
<title>fetchproxy</title>
```

to:

```html
<title>Transporter</title>
```

- [ ] **Step 2: Update popup.ts JSDoc**

In `packages/extension-core/src/popup/popup.ts` line 2, change:

```typescript
 * Popup UI for the fetchproxy extension. Three modes:
```

to:

```typescript
 * Popup UI for the Transporter extension. Three modes:
```

- [ ] **Step 3: Run tests**

```bash
npm test --workspace=@fetchproxy/extension-core
```

Expected: all extension-core tests pass. The popup tests check rendered content (MCP names, domains, buttons), not the page title.

- [ ] **Step 4: Build extension and verify**

```bash
npm run build --workspace=@fetchproxy/extension-chrome
```

Expected: `dist/popup.html` contains `<title>Transporter</title>`.

- [ ] **Step 5: Commit**

```bash
git add packages/extension-core/src/popup/popup.html packages/extension-core/src/popup/popup.ts
git commit -m "feat(extension): rebrand popup title to Transporter"
```

---

### Task 3: Icon assets

**Files:**
- Create: `packages/extension-chrome/icons/icon.svg`
- Replace: `packages/extension-chrome/icons/16.png`
- Create: `packages/extension-chrome/icons/32.png`
- Replace: `packages/extension-chrome/icons/48.png`
- Replace: `packages/extension-chrome/icons/128.png`

The spec calls for a "stylized geometric portal/aperture — two concentric rings with a horizontal arrow passing through." Single-color flat design, legible at 16px. No literal Star Trek transporter-pad imagery (IP risk).

- [ ] **Step 1: Install librsvg for SVG → PNG export**

```bash
brew install librsvg
```

Provides `rsvg-convert` CLI.

- [ ] **Step 2: Create SVG source**

Create `packages/extension-chrome/icons/icon.svg` — a geometric portal icon:
two concentric circles (rings) with a rightward arrow passing through the center.
Single color (#2563eb, the blue already used in the popup approve button).
128×128 viewBox. Transparent background.

```svg
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" fill="none">
  <!-- Outer ring -->
  <circle cx="64" cy="64" r="56" stroke="#2563eb" stroke-width="8"/>
  <!-- Inner ring -->
  <circle cx="64" cy="64" r="34" stroke="#2563eb" stroke-width="6"/>
  <!-- Arrow shaft -->
  <line x1="20" y1="64" x2="96" y2="64" stroke="#2563eb" stroke-width="8" stroke-linecap="round"/>
  <!-- Arrow head -->
  <polyline points="80,48 96,64 80,80" stroke="#2563eb" stroke-width="8" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
</svg>
```

- [ ] **Step 3: Export PNGs at all four sizes**

```bash
cd packages/extension-chrome/icons
for size in 16 32 48 128; do
  rsvg-convert -w $size -h $size icon.svg -o ${size}.png
done
```

- [ ] **Step 4: Verify PNGs exist and are reasonable sizes**

```bash
file packages/extension-chrome/icons/*.png
```

Expected: each file is PNG image data, correct dimensions.

- [ ] **Step 5: Build extension and verify icons copied**

```bash
npm run build --workspace=@fetchproxy/extension-chrome
file packages/extension-chrome/dist/icons/*.png
```

Expected: dist/ contains all four PNGs plus the SVG source.

- [ ] **Step 6: Commit**

```bash
git add packages/extension-chrome/icons/
git commit -m "feat(extension): Transporter icon — geometric portal motif

Two concentric rings with an arrow passing through. Single-color flat
design (#2563eb) legible at 16px toolbar size. SVG source + exported
PNGs at 16/32/48/128."
```

---

### Task 4: Privacy policy

**Files:**
- Create: `docs/PRIVACY.md`
- Create: `docs/index.html`
- Create: `docs/.nojekyll`

The privacy policy is served via GitHub Pages at `https://chrischall.github.io/fetchproxy/PRIVACY`. GitHub Pages renders `.md` files as HTML automatically.

- [ ] **Step 1: Create docs/PRIVACY.md**

```markdown
# Transporter — Privacy Policy

**Last updated:** 2026-05-26

Transporter is a browser extension that bridges local MCP (Model Context
Protocol) servers to your signed-in browser tabs. It is open source at
[github.com/chrischall/fetchproxy](https://github.com/chrischall/fetchproxy).

## What data is processed

Transporter processes HTTP requests and browser session data **locally on
your machine**. When a paired MCP server asks Transporter to fetch a URL,
the extension issues the request from a matching browser tab and returns
the response to the MCP server over a localhost WebSocket connection.

All communication stays on `127.0.0.1`. No data is sent to any external
server, analytics service, or third party.

## What data is stored

Transporter stores the following in `chrome.storage.local` (never synced,
never leaves your device):

- **Extension identity keypair** — an X25519 + Ed25519 key pair generated
  on first install, used for end-to-end encrypted sessions with MCP
  servers.
- **Trust records** — for each MCP you have approved: its identity hash,
  server name, declared domains, and approved capability set.
- **Pending-pair state** — transient data while a pairing request is
  awaiting your approval. Cleared automatically.

MCP-side identity keys are stored by the MCP server itself (typically at
`~/.fetchproxy/identity/<server-name>.json`), outside the extension's
control.

## What data is shared externally

**None.** Transporter has no telemetry, no analytics, no crash reporting,
no remote configuration, and no network calls other than the localhost
WebSocket to paired MCP servers and the HTTP requests those servers
explicitly ask it to make on declared domains.

## Cookies and session data

If an MCP declares the `read_cookies` capability and you approve it at
pair time, Transporter can read specific cookies from tabs on the MCP's
declared domains. Cookie keys are listed in the pair prompt before you
approve. HttpOnly cookies are read via `chrome.cookies` API; all others
via `document.cookie`.

Similarly, `read_local_storage`, `read_session_storage`, and
`read_indexed_db` capabilities allow reading specific keys from a tab's
Web Storage or IndexedDB stores, only on declared domains, only after
your explicit approval.

No cookie or storage data is sent anywhere except back to the requesting
MCP server over the encrypted localhost connection.

## Permissions

See the [permission justifications](https://github.com/chrischall/fetchproxy/blob/main/docs/store-assets/permission-justifications.md)
for a detailed explanation of why each Chrome permission is requested.

## Revoking access

Open the Transporter popup and click the **revoke** button next to any
MCP. This deletes its trust record immediately. The MCP must re-pair
(with your approval) to regain access.

## Uninstalling

Removing Transporter from `chrome://extensions` deletes all stored data
(identity keys, trust records, pending state). MCP-side identity keys at
`~/.fetchproxy/identity/` are not affected.

## Contact

For questions or concerns about this privacy policy:

- **Email:** chris.c.hall@gmail.com
- **GitHub:** [github.com/chrischall/fetchproxy/issues](https://github.com/chrischall/fetchproxy/issues)
```

- [ ] **Step 2: Create docs/.nojekyll**

Empty file — tells GitHub Pages to serve files directly without Jekyll processing.

```bash
touch docs/.nojekyll
```

- [ ] **Step 3: Create docs/index.html**

Simple redirect to the GitHub repo (so `chrischall.github.io/fetchproxy/` isn't a blank page):

```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="0; url=https://github.com/chrischall/fetchproxy">
  <title>fetchproxy</title>
</head>
<body>
  <p>Redirecting to <a href="https://github.com/chrischall/fetchproxy">github.com/chrischall/fetchproxy</a>…</p>
</body>
</html>
```

- [ ] **Step 4: Commit**

```bash
git add docs/PRIVACY.md docs/.nojekyll docs/index.html
git commit -m "docs: privacy policy for Transporter CWS listing

Served via GitHub Pages at chrischall.github.io/fetchproxy/PRIVACY.
Covers local-only data processing, chrome.storage.local contents,
no external sharing, revoke/uninstall paths."
```

**Note:** GitHub Pages must be enabled manually in the repo settings (Settings → Pages → Source: Deploy from branch `main`, folder `/docs`). This is a one-time manual step outside the codebase.

---

### Task 5: Store listing copy

**Files:**
- Create: `docs/store-assets/listing-description.md`
- Create: `docs/store-assets/permission-justifications.md`

- [ ] **Step 1: Create listing-description.md**

```markdown
# Transporter — Chrome Web Store Listing Description

> Paste this into the "Detailed description" field in the CWS developer console.

---

## What Transporter does

Transporter bridges local MCP (Model Context Protocol) servers to your
signed-in browser tabs. AI coding assistants like Claude, Cursor, and
Windsurf use MCP servers to interact with web services — but many
services block automated requests with bot detection (Akamai, Cloudflare
Bot Management, DataDome). Transporter solves this by routing requests
through your real, signed-in browser session.

Instead of fighting bot walls or copying session cookies by hand,
Transporter lets an MCP server say: "fetch this URL through the user's
browser tab on opentable.com" — and the extension does exactly that,
returning the response over a local encrypted channel.

## How it works

1. Install Transporter and keep it running in Chrome.
2. When an MCP server starts, it connects to Transporter over a
   localhost WebSocket (127.0.0.1:37149).
3. The first time a new MCP connects, Transporter shows a popup with a
   6-digit pair code, the server's declared domains, and what it's
   asking to do. You verify the code matches what the MCP printed and
   click Approve.
4. From then on, the MCP can issue fetch requests through your
   signed-in tabs on its declared domains.

All traffic stays on your machine — Transporter never sends data to any
external server.

## Security model

- **Pair-before-trust.** Every new MCP identity triggers a pair prompt.
  You see the server name, domains, and capabilities before approving.
- **End-to-end encryption.** Each MCP↔extension session uses AES-256-GCM
  with a per-session key derived via X25519 ECDH. Even in the
  concentrator architecture (multiple MCPs sharing one port), the host
  cannot read peer traffic.
- **Per-MCP domain allowlist.** Each MCP declares its domains at pair
  time. Transporter rejects any request outside the declared set.
- **No automation primitives.** No eval, no DOM manipulation, no general
  storage exfiltration. Transporter is a fetch relay, not a browser
  automation tool.
- **Revoke any time.** Click the revoke button in the popup to remove an
  MCP's trust record instantly.

## Who it's for

Developers and power users running MCP-based AI tools that need
authenticated access to web services. Transporter is the install-once
companion extension for the fetchproxy ecosystem of MCP servers.

## Open source

Transporter is open source under the MIT license. The source code, wire
protocol specification, and security threat model are all at:
https://github.com/chrischall/fetchproxy

The npm packages are published as @fetchproxy/server, @fetchproxy/protocol,
and @fetchproxy/bootstrap.
```

- [ ] **Step 2: Create permission-justifications.md**

```markdown
# Transporter — Permission Justifications

> CWS review form: paste each justification into the corresponding
> permission field.

---

## `storage`

Persist per-MCP trust records (identity hash, server name, declared
domains, approved capabilities), the extension's own X25519 + Ed25519
identity keypair, and transient pending-pair state across service-worker
restarts. No data leaves the user's machine.

## `tabs`

Find the signed-in tab on a declared domain and route fetch requests
through it. Tab matching uses host-or-subdomain comparison against
the MCP-declared domains list. For example, an MCP declaring
"opentable.com" can issue requests through any tab on opentable.com or
www.opentable.com.

## `scripting`

Inject the content script that executes fetch() from the page context
with the tab's cookies and TLS session. Extension-context fetches
don't carry the tab's cookie jar or TLS fingerprint, which is the
entire point of the relay.

## `cookies`

Optional capability: read_cookies. An MCP must declare specific cookie
access at pair time; the user approves the capability before any read
occurs. HttpOnly cookies are accessible only via the chrome.cookies
API. Non-HttpOnly cookies are read via document.cookie in the content
script.

## `webRequest`

Optional capability: capture_request_header. Registers a one-shot
onBeforeSendHeaders listener for an MCP-declared URL pattern, captures
one header value, then removes itself. Never modifies outgoing
requests. Used by MCPs that need a CSRF or session token from the
request flow.

## `alarms`

MV3 service-worker keepalive only. A single alarm fires every 24
seconds to call the idempotent connect() function, preventing Chrome
from evicting the service worker and silently dropping the WebSocket
bridge between bursts of MCP traffic. No scheduling, no payload.

## `host_permissions: <all_urls>`

Per-MCP domain sets are declared dynamically at pair time and cannot
be enumerated statically in the manifest. The runtime enforcement is
the per-MCP domains[] allowlist — every fetch URL, cookie read,
storage read, and header capture is checked against the declared
domains (exact host or subdomain match) before execution. Requests
outside the declared set are rejected.

## Single-purpose statement

> Paste into the "Single purpose" field.

Relay HTTP fetches and read user-declared session data (cookies,
localStorage, request headers) between a local MCP server and the
user's signed-in browser tab on a domain the user has explicitly
approved at pair time.
```

- [ ] **Step 3: Commit**

```bash
git add docs/store-assets/listing-description.md docs/store-assets/permission-justifications.md
git commit -m "docs: CWS listing description and permission justifications

Ready-to-paste text for the Chrome Web Store developer console.
Listing covers what/how/security/audience. Permission justifications
address each manifest permission including the <all_urls> host scope."
```

---

### Task 6: README updates

**Files:**
- Modify: `README.md`
- Modify: `packages/extension-chrome/README.md`

- [ ] **Step 1: Update top-level README install section**

In `README.md`, replace the current extension install section (lines 56–67):

```markdown
### Extension

The Chrome MV3 extension is not (yet) on the Chrome Web Store. Build and load unpacked:

```sh
git clone https://github.com/chrischall/fetchproxy
cd fetchproxy
npm ci
npm --workspace=@fetchproxy/extension-chrome run build
```

Then in Chrome: `chrome://extensions` → toggle "Developer mode" → "Load unpacked" → pick `packages/extension-chrome/dist/`.
```

with:

```markdown
### Extension

Install **Transporter** from the [Chrome Web Store](https://chromewebstore.google.com/detail/transporter/EXTENSION_ID_PLACEHOLDER). One click, auto-updates.

> In the Chrome Web Store it's listed as **Transporter**; the protocol and npm packages are **fetchproxy**.

<details>
<summary>Manual / sideload install</summary>

```sh
git clone https://github.com/chrischall/fetchproxy
cd fetchproxy
npm ci
npm --workspace=@fetchproxy/extension-chrome run build
```

Then in Chrome: `chrome://extensions` → toggle "Developer mode" → "Load unpacked" → pick `packages/extension-chrome/dist/`.
</details>
```

**Note:** `EXTENSION_ID_PLACEHOLDER` will be replaced with the real CWS extension ID after first submission is approved.

- [ ] **Step 2: Update extension-chrome README**

Append a migration section to `packages/extension-chrome/README.md`:

```markdown

## Migrating from the unpacked dev install

The Chrome Web Store version of the extension (listed as **Transporter**)
gets a new extension ID assigned by Google. Chrome treats it as a
separate extension from the sideloaded "Load unpacked" version — not an
upgrade.

**What carries over:**

| Item | Carries over? |
|---|---|
| MCP-side identity keys (`~/.fetchproxy/identity/`) | Yes — outside the extension |
| MCP-captured sessions (e.g. `~/.honeybook-mcp/`) | Yes — outside the extension |
| Extension identity keypair | No — CWS install starts fresh |
| Per-MCP trust records | No — stored in the old extension's `chrome.storage.local` |

**What to do:**

1. Install Transporter from the Chrome Web Store.
2. Remove the sideloaded extension from `chrome://extensions`.
3. Each MCP will trigger a fresh pair prompt on its next connection.
   Verify the 6-digit code and click Approve.

No data is lost. The one-time re-pair takes a few seconds per MCP.
```

- [ ] **Step 3: Run tests**

```bash
npm test
```

Expected: all tests pass (README changes don't affect tests, but verify nothing was accidentally touched).

- [ ] **Step 4: Commit**

```bash
git add README.md packages/extension-chrome/README.md
git commit -m "docs: Transporter CWS install path + sideload migration guide

Top-level README gets the CWS link (placeholder ID until approved),
bridge sentence about naming, and sideload instructions in a details
fold. Extension-chrome README gets a migration section for existing
sideload users."
```

---

### Task 7: Final verification

- [ ] **Step 1: Full test suite**

```bash
npm test
```

Expected: all tests pass, no regressions.

- [ ] **Step 2: Full build**

```bash
npm run build --workspaces --if-present
```

Expected: all workspaces build successfully.

- [ ] **Step 3: Verify extension zip is valid**

```bash
cd packages/extension-chrome
npx tsx build.ts
cd dist
zip -r /tmp/transporter-test.zip .
ls -la /tmp/transporter-test.zip
unzip -l /tmp/transporter-test.zip | head -20
```

Expected: zip contains manifest.json with `"name": "Transporter"`, all four icon PNGs, background.js, content.js, capture-logger.js, popup.html, popup.js.

- [ ] **Step 4: Verify manifest contents**

```bash
cat packages/extension-chrome/dist/manifest.json | grep -E '"name"|"description"|32'
```

Expected output:
```
  "name": "Transporter",
  "description": "Bridge local MCP servers to your signed-in browser tabs — let agentic tools hit authenticated APIs without copying credentials.",
    "32": "icons/32.png",
    "32": "icons/32.png",
```

- [ ] **Step 5: Verify privacy policy renders**

Open `docs/PRIVACY.md` in a browser or use:
```bash
head -5 docs/PRIVACY.md
```

Expected: starts with `# Transporter — Privacy Policy`.

---

## Post-plan manual steps (not automatable)

These happen after the code changes are merged:

1. **Enable GitHub Pages** — repo Settings → Pages → Source: Deploy from branch `main`, folder `/docs`. Verify `https://chrischall.github.io/fetchproxy/PRIVACY` loads.
2. **Register CWS developer account** — [chrome.google.com/webstore/devconsole](https://chrome.google.com/webstore/devconsole), pay $5 one-time fee.
3. **Upload extension** — use the `.zip` from the latest GitHub release (`fetchproxy-extension-0.6.0.zip` or newer). Fill form fields from `docs/store-assets/`.
4. **Replace `EXTENSION_ID_PLACEHOLDER`** — after CWS assigns the extension ID, update `README.md` with the real CWS URL.
5. **Icon iteration** — the programmatic SVG → PNG icons are functional but may benefit from professional design polish. Replace the PNGs and the SVG source when ready; the build pipeline copies them automatically.
6. **Screenshots + promo tile** — capture real screenshots of the pair prompt and trusted-MCPs list once the CWS version is installed. Create the 440×280 promo tile. Add to `docs/store-assets/screenshots/` and `docs/store-assets/promo-tile.png`.
