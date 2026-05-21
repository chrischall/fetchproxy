# fetchproxy

**Authenticated `fetch()` from an MCP server, proxied through the user's signed-in browser tab.**

A browser extension + a Node library. MCP servers (`opentable-mcp`, `resy-mcp`, anything similar) embed the library; the user installs the extension once. Together they route HTTP requests from the MCP server through a real, signed-in browser tab — so Akamai, Cloudflare Bot Management, and similar bot walls see a real browser, not a Node process.

Tiny on purpose. The protocol exposes one verb (`fetch`) and a handful of lifecycle frames. No DOM automation, no `eval_js`, no cookie exfiltration — that's outside scope and outside the security budget.

## Why

Consumer reservation/booking platforms — OpenTable, Resy, and friends — front their APIs with Akamai Bot Manager. Node `fetch`, `cycletls`, impersonated `curl`, and even Playwright all hit 403 or a JS interstitial. The only thing the bot wall never blocks is the actual signed-in Chrome tab.

So instead of a bot-evasion arms race, an MCP server can use fetchproxy to ask the user's browser to make the request on its behalf. Real TLS, real cookies, real Akamai-cleared `_abck`. Clean 200s.

## Architecture

```
┌──────────────────┐  stdio  ┌──────────────────┐    WS    ┌────────────────┐  fetch()  ┌─────────────────────┐
│ MCP client       │◀───────▶│ Your MCP server  │◀────────▶│ fetchproxy ext │◀─────────▶│ target site (signed │
│ (Claude, etc.)   │         │ (e.g. OpenTable) │ :37149   │ (Chrome/Safari)│           │ in, Akamai-cleared) │
└──────────────────┘         └──────────────────┘          └────────────────┘           └─────────────────────┘
                              └ uses @fetchproxy/server (Node lib)
```

Three pieces, one repo:

| Package | What | Lives in |
|---|---|---|
| `@fetchproxy/server` | Node library MCP servers depend on. Starts a localhost WS, accepts `fetch()` calls, relays them to the extension, returns the response. | `packages/server/` |
| `fetchproxy-extension` | Browser extension. Connects to the WS, runs `fetch(url, { credentials: 'include' })` in the page MAIN world of a matching tab, returns the response. | `packages/extension-core/` + `packages/extension-chrome/` + `packages/extension-safari/` |
| `fetchproxy` protocol | WS frame schema between the two. | `docs/PROTOCOL.md` |

Cross-browser: one TypeScript codebase in `extension-core/`, built into per-browser packages. Chrome ships as a regular MV3 extension; Safari ships as a `.dmg`-wrapped Safari Web Extension. See [Cross-browser strategy](#cross-browser-strategy).

## Scope

### In scope (v1)

- `fetch(url, init)` from MCP server, executed in the page MAIN world of a tab matching a caller-supplied `tabUrl` prefix.
- Tab-pinned routing — the extension picks the right tab; the MCP server never sees an "active tab" assumption.
- Status indicators in the extension popup (WS connection, tab present, optional auth-cookie present).
- Multi-MCP support — one extension serves many MCPs on different ports (opentable-mcp on 37149, resy-mcp on 37148, etc.).
- Chrome (MV3) + Safari Web Extensions.

### Explicitly out of scope

- **DOM automation** (clicks, screenshots, form-fill) — use `claude-in-chrome` or `playwright-mcp` for that.
- **`eval_js` / arbitrary JS execution** — security footgun. Locally-malicious software on `127.0.0.1` could exec in your signed-in tabs.
- **Cookie or credential exfiltration** — the protocol can't request "give me the cookies for opentable.com." Fetches happen in the browser; bytes return.
- **Headless / cloud browsers** — fetchproxy targets the user's real, signed-in browser. If you need a fresh browser session, use Playwright or Browserbase.
- **Cross-origin proxy for arbitrary URLs** — the tab must be on the right domain. Targeting `tabUrl: "https://www.opentable.com/"` and fetching `https://api.example.com/` won't work; the fetch runs from the opentable.com origin.

## Cross-browser strategy

Shared TypeScript core, per-browser packaging.

| Browser | Distribution | Notes |
|---|---|---|
| Chrome / Chromium-based (Edge, Brave) | Unpacked dev-load + Chrome Web Store | MV3 service worker. 20s WS ping to keep it warm. |
| Safari | Signed `.dmg` (containing app) | Safari Web Extensions API is ~95% compatible with Chrome MV3 since Safari 16.4. Service worker is killed more aggressively; we use a 5s ping and `chrome.alarms` backup. Requires Apple Developer account ($99/yr) to ship signed builds via GitHub Releases. |
| Firefox | (Phase 3) | WebExtensions API differs slightly from MV3; cheap to add once the shared core stabilizes. |

The split between `extension-core/` (the shared TS) and `extension-chrome/` / `extension-safari/` (the per-browser manifests + build outputs) keeps platform divergence contained to manifest files + the build step.

## Phases

### Phase 1 — Chrome MVP + Node library

- Extract `opentable-mcp/extension/` into `packages/extension-core/` + `packages/extension-chrome/`. Make it domain-agnostic — no hardcoded `opentable.com` paths.
- Publish `@fetchproxy/server` to npm.
- Migrate `opentable-mcp` to depend on `@fetchproxy/server` instead of carrying its own extension. (One PR against opentable-mcp.)
- One end-to-end test covers Chrome → MCP server → opentable.com.

### Phase 2 — Safari port

- Set up Xcode containing-app wrapper in `packages/extension-safari/`.
- Same `extension-core/` source, different build target.
- CI release pipeline produces signed `.dmg` from a tagged GitHub Release.
- Verify against a Safari user.

### Phase 3 — Polish + Firefox

- Firefox WebExtension target.
- Better popup UX (per-MCP status, "open my opentable.com tab" shortcut).
- Possibly: add a "capture-logger" opt-in mode for developer-time endpoint discovery (the pattern we use today to grab persisted-query hashes from Apollo).

## Protocol

See [`docs/PROTOCOL.md`](docs/PROTOCOL.md) for full WS frame schemas. One verb today: `fetch`.

## Security model

Full threat model and defenses live in [`docs/SECURITY.md`](docs/SECURITY.md). Headline posture:

- **Local trust boundary.** fetchproxy is a single-user, same-machine product. WS binds `127.0.0.1` only. Multi-user shared machines are out of scope.
- **Explicit trust prompt.** First connection from a new `(port, server-name, domain)` tuple does NOT auto-trust. The extension popup shows the user a permission prompt with the domain in large type. "Always allow" persists; anything else re-prompts on next connection.
- **Per-MCP domain allowlist.** Each MCP declares its domains (`["opentable.com"]`, or `["honeybook.com", "hbsplit.com"]` for an MCP that legitimately spans two hosts) in the `hello` frame. The extension rejects any fetch outside that set — so a compromised `opentable-mcp` can leak OpenTable data, but cannot ALSO be used against your bank, email, or Slack.
- **No automation primitives.** No `eval_js`, no `get_cookies`, no DOM access, no navigation. The minimum-permission shape is intentional — a hostile MCP that gets past the trust prompt can read pages on its declared domain and that's it.
- **Webpage drive-by defenses.** WS upgrades from public-origin pages get rejected (Origin allowlist + Chrome Private Network Access support).
- **Honest about the expansion.** fetchproxy DOES expand the local attack surface — Chrome cookies aren't freely readable by every local process, but a trusted fetchproxy MCP can act AS the browser without prompting Keychain. If you don't trust everything else on your user account, fetchproxy isn't for you.

## License

MIT.
