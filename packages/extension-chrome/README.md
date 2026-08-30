# @fetchproxy/extension-chrome

Chrome MV3 build target for the [fetchproxy](https://github.com/chrischall/fetchproxy) browser extension.

Workspace-internal. The shared TypeScript lives in [`packages/extension-core`](../extension-core); this package owns the per-browser bits: the MV3 `manifest.json`, the icons, and the esbuild step that produces a loadable unpacked extension at `dist/`.

## Build

From the repo root:

```sh
npm ci
npm --workspace=@fetchproxy/extension-chrome run build
```

Or directly:

```sh
cd packages/extension-chrome
npx tsx build.ts
```

Output lands in `packages/extension-chrome/dist/`:

```
dist/
  manifest.json
  background.js       service worker (WS client + dispatcher)
  content.js          isolated-world content script
  capture-logger.js   page-main-world helper (CSRF token sync)
  popup.html
  popup.js
  icons/
```

## Install (developer / sideload)

1. Open `chrome://extensions` in Chrome.
2. Toggle "Developer mode" (top right).
3. "Load unpacked" → pick `packages/extension-chrome/dist/`.

Each release also publishes a packaged `fetchproxy-extension-${VERSION}.zip` on the [GitHub Releases](https://github.com/chrischall/fetchproxy/releases) page — the same `dist/` zipped up, suitable for sideloading without building from source.

## Manifest highlights

- `manifest_version: 3` (MV3 service worker).
- `host_permissions: ["<all_urls>"]` — required because per-MCP domains are dynamic and enforced inside the extension, not statically in the manifest.
- `content_scripts` registers both an isolated-world dispatcher (`content.js`) and a MAIN-world capture helper (`capture-logger.js`) at `<all_urls>`. Routing/allowlist enforcement happens inside the scripts themselves once the background dispatches a request.
- `permissions: ["alarms"]` — used solely for the MV3 service-worker keepalive (`chrome.alarms` ticks every ~24s to wake the SW from idle so the WS bridge stays reachable between bursts of MCP traffic). No alarm payload, no scheduling beyond the single keepalive.
- `permissions: ["downloads"]` — backs the `download` capability: `chrome.downloads.download` lets the BROWSER fetch a declared-domain URL with the user's real cookies + TLS/JA3 fingerprint, clearing a Cloudflare bot-challenge a page-level `fetch()` (cors) cannot. Only used when an MCP declares `download`; the extension returns the saved local file path (the bridge is loopback-only, so the MCP reads it from the same disk) and erases only the download *record*, leaving the file for the MCP to move.
- **`write_cookies` needs NO new permission**, but it is new `chrome.*` surface: `permissions: ["cookies"]` was already granted for `chrome.cookies.get` (the HttpOnly-visible read path), and the capability adds `chrome.cookies.set` on top of it. It is the only verb in the protocol that CHANGES browser state rather than reading it, and it is deliberately narrow: it overwrites the value of a cookie that already exists, on a declared domain, whose name is already in the MCP's declared `cookieKeys` — it cannot create cookies or reach one the MCP could not already read. See [`docs/SECURITY.md` §T-cookie-write](https://github.com/chrischall/fetchproxy/blob/main/docs/SECURITY.md#t-cookie-write--write_cookies-capability-misuse).
- **`graphql` needs NO new permission.** The capability rides on infrastructure the manifest already ships: `content_scripts` already registers `capture-logger.js` as a `world: MAIN`, `document_start` script on `<all_urls>`, and `permissions: ["scripting"]` is already present. `graphql` extends that same MAIN-world script into a request/response RPC bridge (isolated ⇄ MAIN via `window.postMessage`, gated by strict origin/type/source checks) that invokes the page's own `window.__APOLLO_CLIENT__` for a declared operation — no new manifest entry required.
- `permissions: ["tabGroups"]` — backs the relay tab group. `ensureDomainTab` opens its tab with `active: false` (a relay tab is machinery, not somewhere the person asked to go, so it must not steal focus) and files it into one titled **"fetchproxy"** group via `chrome.tabs.group`; `tabGroups` is needed only for `chrome.tabGroups.query`/`update`, i.e. to FIND the existing group and set its title and colour. It reads and titles the extension's own group and nothing else — it cannot read page content, and the grouping is best-effort: a browser without the API, or a build without this permission, still gets its relay tab ungrouped.

See the [top-level README](https://github.com/chrischall/fetchproxy#readme) for the architecture and the [protocol reference](https://github.com/chrischall/fetchproxy/blob/main/docs/PROTOCOL.md) for the wire format.

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
