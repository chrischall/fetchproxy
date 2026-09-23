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

That is the **release** build: no sourcemaps, because the release workflow zips
`dist/` with this same plain command, so whatever the default is, is what
ships. For a debuggable bundle add `--dev` (or run
`npm --workspace=@fetchproxy/extension-chrome run build:dev`), which inlines
the sourcemaps and takes `background.js` from ~147 KB to ~790 KB. Both halves
are pinned by `tests/release-bundle-sourcemaps.test.ts`.

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
4. After **every** later pull: rebuild (above), then press **Reload** on the
   extension's card — see the requirement below.

Each release also publishes a packaged `fetchproxy-extension-${VERSION}.zip` on the [GitHub Releases](https://github.com/chrischall/fetchproxy/releases) page — the same `dist/` zipped up, suitable for sideloading without building from source.

**This build pairs with the npm packages of the same major.** The extension and
`@fetchproxy/server` ship from one repo at one version, and the pairing is one
to one: extension **3.x** (3.0.0+) speaks fetchproxy **protocol 4** and pairs
with `@fetchproxy/server` **3.x**; extension 2.x speaks protocol 3 and pairs
with 2.x. Nothing negotiates down — a v4 extension that still accepted v3 would
*be* the downgrade path, since a relay that can rewrite frames can rewrite the
version it advertises. A mismatched pair is refused at the hello, naming both
numbers: this extension answers a v3 MCP on the wire with `protocol version
mismatch: this browser extension speaks fetchproxy protocol 4, this MCP speaks
3 — upgrade @fetchproxy/server to >= 3.0.0`, and says the same thing in its own
words in the popup — naming the server, both versions, and the fact that
nothing in the browser fixes it — because an MCP older than 2.6.0 cannot hear
the wire answer at all. A v4 MCP meeting a v3 extension closes the socket
`1002` with the same fact the other way round. [`docs/PROTOCOL.md`](https://github.com/chrischall/fetchproxy/blob/main/docs/PROTOCOL.md)
§Versioning has the table of what each protocol number changed and both refusal
texts verbatim.

**Reloading after a rebuild is a requirement, not hygiene.** Chrome keeps
running the bundle it loaded at "Load unpacked"; rebuilding `dist/` underneath
it changes nothing in the browser until you press Reload. Across a protocol
major that is the difference between a working bridge and a dead one — a stale
extension goes on speaking the old protocol to MCPs the same pull upgraded, the
handshake is refused rather than degraded, and every call fails at once with
`protocol version mismatch`. Within a major it is milder and still real: a fixed
background or content script that is simply not running is the first thing to
rule out when a change "did nothing".

## Manifest highlights

- `manifest_version: 3` (MV3 service worker).
- `minimum_chrome_version: "102"` — the first Chrome with `chrome.storage.session`, which carries the pairing queue and the popup's approve/cancel decisions. Unlike `storage.local`, it is closed to content scripts (which run on every site), so no page can forge an approval. It adds no permission and causes no re-prompt; a browser older than 102 cannot install or update to this version.
- `host_permissions: ["<all_urls>"]` — required because per-MCP domains are dynamic and enforced inside the extension, not statically in the manifest.
- `content_scripts` registers both an isolated-world dispatcher (`content.js`) and a MAIN-world capture helper (`capture-logger.js`) at `<all_urls>`. Routing/allowlist enforcement happens inside the scripts themselves once the background dispatches a request.
- `permissions: ["alarms"]` — used solely for the MV3 service-worker keepalive (`chrome.alarms` ticks every ~24s to wake the SW from idle so the WS bridge stays reachable between bursts of MCP traffic). No alarm payload, no scheduling beyond the single keepalive.
- `permissions: ["downloads"]` — backs the `download` capability: `chrome.downloads.download` lets the BROWSER fetch a declared-domain URL with the user's real cookies + TLS/JA3 fingerprint, clearing a Cloudflare bot-challenge a page-level `fetch()` (cors) cannot. Only used when an MCP declares `download`; the extension returns the saved local file path (the bridge is loopback-only, so the MCP reads it from the same disk) and erases only the download *record*, leaving the file for the MCP to move.
- **`write_cookies` needs NO new permission**, but it is new `chrome.*` surface: `permissions: ["cookies"]` was already granted for `chrome.cookies.get` (the HttpOnly-visible read path), and the capability adds `chrome.cookies.set` on top of it. It is the only verb in the protocol that CHANGES browser state rather than reading it, and it is deliberately narrow: it overwrites the value of a cookie that already exists, on a declared domain, whose name is already in the MCP's declared `cookieKeys` — it cannot create cookies or reach one the MCP could not already read. See [`docs/SECURITY.md` §T-cookie-write](https://github.com/chrischall/fetchproxy/blob/main/docs/SECURITY.md#t-cookie-write--write_cookies-capability-misuse).
- **`graphql` needs NO new permission.** The capability rides on infrastructure the manifest already ships: `content_scripts` already registers `capture-logger.js` as a `world: MAIN`, `document_start` script on `<all_urls>`, and `permissions: ["scripting"]` is already present. `graphql` extends that same MAIN-world script into a request/response RPC bridge (isolated ⇄ MAIN via `window.postMessage`, gated by strict origin/type/source checks) that invokes the page's own `window.__APOLLO_CLIENT__` for a declared operation — no new manifest entry required.
- `permissions: ["tabGroups"]` — backs the relay tab group. `ensureDomainTab` opens its tab with `active: false` (a relay tab is machinery, not somewhere the person asked to go, so it must not steal focus) and files it into one titled **"fetchproxy"** group via `chrome.tabs.group`; `tabGroups` is needed only for `chrome.tabGroups.query`/`update`, i.e. to FIND the existing group and set its title and colour. It reads and titles the extension's own group and nothing else — it cannot read page content, and the grouping is best-effort: a browser without the API, or a build without this permission, still gets its relay tab ungrouped.
- **`chrome.runtime.onInstalled` needs NO new permission**, but it is new `chrome.*` surface. Chrome tears the content scripts out of every already-open tab when the extension updates and injects no new ones — `content_scripts` only covers navigations from that point on — so every tab a person already had open is left with no listener, and every MCP reading from a long-lived tab breaks at once until they reload it by hand. Nothing tells them to. On `onInstalled` with reason `update` (and only that reason: `install` has no pre-existing tabs and `chrome_update` does not tear scripts down) the background re-injects each script the manifest declares, in its declared world, into the open tabs its `matches` cover, via `chrome.scripting.executeScript` — `permissions: ["scripting"]` was already granted. It is best-effort: restricted pages (`chrome://`, the Web Store, a tab mid-navigation) legitimately refuse injection, so failures are swallowed per tab. It reads no page content; it only puts back what the manifest already said belonged there.

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
   Verify the 8-digit code and click Approve.

No data is lost. The one-time re-pair takes a few seconds per MCP.
