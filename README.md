# fetchproxy

> Authenticated `fetch()` from an MCP server, proxied through the user's signed-in browser tab.

[![CI](https://github.com/chrischall/fetchproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/chrischall/fetchproxy/actions/workflows/ci.yml)

A Node library and a browser extension. MCP servers (`opentable-mcp`, `resy-mcp`, anything similar) embed the library; the user installs the extension once. Together they route HTTP requests from the MCP server through a real, signed-in browser tab — so Akamai, Cloudflare Bot Management, and similar bot walls see a real browser, not a Node process.

Tiny on purpose. The protocol exposes two verbs (`fetch`, opt-in `read_cookies`) and a handful of lifecycle frames. No DOM automation, no `eval_js`, no general storage exfiltration — that's outside scope and outside the security budget.

## Why

Consumer reservation/booking platforms — OpenTable, Resy, and friends — front their APIs with Akamai Bot Manager. Node `fetch`, `cycletls`, impersonated `curl`, and even Playwright all hit 403 or a JS interstitial. The only thing the bot wall never blocks is the actual signed-in Chrome tab.

So instead of a bot-evasion arms race, an MCP server can use fetchproxy to ask the user's browser to make the request on its behalf. Real TLS, real cookies, real Akamai-cleared `_abck`. Clean 200s.

## Architecture

```
                       ┌──────────────────────────┐
                       │ Browser extension        │
                       │ (one process, all MCPs)  │
                       └───────────────┬──────────┘
                                       │ ws://127.0.0.1:37149
                                       │  (shared port; concentrator)
                                       │
                          ┌────────────▼────────────┐
                          │ MCP A — host            │
                          │  • bound the WS port    │
                          │  • routes peer frames   │
                          │  • runs own MCP traffic │
                          └─────┬──────────────┬────┘
                                │ local WS     │ local WS
                       ┌────────▼──┐     ┌─────▼──────┐
                       │ MCP B     │     │ MCP C      │
                       │ (peer)    │     │ (peer)     │
                       └───────────┘     └────────────┘
```

Every MCP races `bind(127.0.0.1:37149)` on startup. The first one wins (`role: 'host'`); the rest dial in as peers (`role: 'peer'`). One extension, one port, N MCPs. Frames between each MCP and the extension are AES-256-GCM encrypted end-to-end using a per-session key derived via X25519+HKDF from a long-term Ed25519/X25519 identity that lives on disk in `~/.fetchproxy/identity/<server-name>.json`. The host routes; it cannot read or modify peer traffic.

When the extension first sees a new identity it triggers a pair flow: the MCP prints a 6-digit SAS code to stderr and the extension popup shows the same code. The user clicks Approve. Subsequent connections from the same identity skip the prompt.

Three pieces, one repo:

| Package | What | Lives in |
|---|---|---|
| [`@fetchproxy/server`](packages/server) | Node library MCP authors depend on. Elects host/peer, runs the handshake, exposes `fetch()` + convenience verbs (`get`, `postJson`, `readCookies`, …). | `packages/server/` |
| [`@fetchproxy/protocol`](packages/protocol) | Wire types, validators, crypto wrappers. Shared between server and extension. | `packages/protocol/` |
| [`@fetchproxy/test-helpers`](packages/test-helpers) | Vitest mocks for downstream MCP test suites — drop-in `FetchproxyServer` replacement that captures constructor opts and exposes spy-able verbs. | `packages/test-helpers/` |
| `fetchproxy-extension` | Browser extension. Connects to the WS, runs `fetch(url, { credentials: 'include' })` in the page MAIN world of a matching tab, returns the response. | `packages/extension-core/` + `packages/extension-chrome/` |

`extension-core/` holds the shared TypeScript; `extension-chrome/` is the per-browser MV3 manifest + esbuild bundle. Safari/Firefox targets can slot in alongside without forking the core.

## Install

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

### Node library

In your MCP server:

```sh
npm install @fetchproxy/server
```

`@fetchproxy/protocol` is pulled in transitively. You only need to depend on it directly if you're building your own bridge.

## Quickstart

A minimal MCP shape using `FetchproxyServer`:

```ts
import { FetchproxyServer } from '@fetchproxy/server';

const fp = new FetchproxyServer({
  serverName: 'opentable-mcp',
  version: '0.10.0',
  domains: ['opentable.com'],
});

await fp.listen();
// First run prints the pair code to stderr:
//   fetchproxy pair code: 123-456
// Open the extension popup and click Approve.

// Single-domain MCP: `domains[0]` is the implicit base.
const dashboard = await fp.getHtml('/user/dining-dashboard', {
  subdomain: 'www',
});

// JSON shortcuts: postJson stringifies + sets Content-Type, getJson parses.
const result = await fp.postJson('/dapi/fe/gql', {
  operationName: 'Autocomplete',
  variables: { term: 'state of confusion' },
}, { subdomain: 'www' });

await fp.close();
```

The `listen()` call elects host or peer automatically — call it from every MCP that wants to share the bridge.

## Capabilities

Each MCP declares an opt-in capability set in its hello frame. The extension stores the approved set in its trust record and forces a re-pair if it ever changes.

| Capability | What it lets the MCP do |
|---|---|
| `fetch` (default) | Issue HTTP requests against the user's signed-in tab. Granted to every MCP that pairs. |
| `read_cookies` | Snapshot non-HttpOnly `document.cookie` from a tab on a declared domain. The popup shows a visible warning at pair time. |

`fetch` is implied if `capabilities` is omitted. Including anything else is opt-in:

```ts
const fp = new FetchproxyServer({
  serverName: 'creditkarma-mcp',
  version: '0.1.0',
  domains: ['creditkarma.com'],
  capabilities: ['fetch', 'read_cookies'],
});

await fp.listen();
const cookies = await fp.readCookies({ subdomain: 'www' });
// "sid=...; csrf=...; ..."
```

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for the wire-level definition and [`docs/SECURITY.md`](docs/SECURITY.md) for the threat model.

## Multi-domain MCPs

Most MCPs target a single domain and can rely on the implicit default. If an MCP legitimately needs more than one (e.g. HoneyBook spans `honeybook.com` and `hbsplit.com`), declare them all and pass `{ domain }` explicitly on every call:

```ts
const fp = new FetchproxyServer({
  serverName: 'honeybook-mcp',
  version: '0.1.0',
  domains: ['honeybook.com', 'hbsplit.com'],
});

await fp.listen();
await fp.getJson('/api/v2/me', { domain: 'honeybook.com', subdomain: 'www' });
await fp.postJson('/share', { … },  { domain: 'hbsplit.com',   subdomain: 'www' });
```

Single-domain MCPs may also pass `{ domain }`; it's required only when more than one is declared.

The extension validates each fetch URL against the set: exact-host match, or subdomain of one of the declared entries. Cross-domain fetches fail with `ok: false`.

## Concentrator + end-to-end encryption

One port, N MCPs. The first MCP to call `listen()` binds `127.0.0.1:37149` and becomes the host; later MCPs dial that host as peers. The host routes frames between peers and the extension but cannot read peer traffic — every data frame after the handshake is AES-256-GCM encrypted under a per-session key the host never sees. Identity keys are per-MCP and stable across restarts; the pair record on the extension side is keyed off the identity hash, not the port or the server name.

Override the bind address if you need to:

```ts
new FetchproxyServer({ port: 37150, host: '127.0.0.1', /* … */ });
```

## Security

`docs/SECURITY.md` is the full threat model. The headlines:

- **Localhost only.** The WS server binds `127.0.0.1`. Multi-user shared machines are out of scope.
- **Identity-keyed pair prompt.** First connection from a new identity does NOT auto-trust. The popup shows the server name, declared domains, and capability set; the user clicks Approve.
- **End-to-end encryption.** The concentrator host routes by `mcpId` but never decrypts peer traffic.
- **Per-MCP domain allowlist.** Each MCP declares its domains; the extension rejects any fetch outside them.
- **No automation primitives.** No `eval_js`, no `read_storage` (other than the opt-in `read_cookies`), no navigation. The minimum-permission shape is intentional.
- **Honest about the expansion.** fetchproxy DOES expand the local attack surface — Chrome cookies aren't freely readable by every local process, but a trusted fetchproxy MCP can act AS the browser on its declared domains without prompting Keychain. If you don't trust everything else running on your user account, fetchproxy isn't for you.

## Project structure

```
packages/
  protocol/          @fetchproxy/protocol         (npm, public)
  server/            @fetchproxy/server           (npm, public)
  test-helpers/      @fetchproxy/test-helpers     (npm, public)
  extension-core/    shared TS for the extension  (workspace internal)
  extension-chrome/  Chrome MV3 build target      (workspace internal)
docs/
  PROTOCOL.md        wire-format reference
  SECURITY.md        threat model
```

`npm test` runs the full vitest suite across all workspaces. `npm run typecheck` runs tsc-build on all TS workspaces (extension-chrome is bundled, not typechecked separately).

## License

MIT.
