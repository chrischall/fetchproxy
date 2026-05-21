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

See the [top-level README](https://github.com/chrischall/fetchproxy#readme) for the architecture and the [protocol reference](https://github.com/chrischall/fetchproxy/blob/main/docs/PROTOCOL.md) for the wire format.
