# fetchproxy security model

The whole point of fetchproxy is to let a Node process speak as the user's signed-in browser. That's a powerful primitive. This doc enumerates what we defend against, what we *don't* defend against, and how the defenses are structured.

If you don't trust everything else running on your local user account, **fetchproxy is not for you.** Read the [§Local trust boundary](#local-trust-boundary) section first.

---

## TL;DR

| What | Defense |
|---|---|
| Random local process trying to use your sessions | Per-MCP trust prompt in the extension popup. Connections to new ports require explicit user approval. |
| Compromised MCP fetching off-domain | Per-MCP domain allowlist. `opentable-mcp` declares `domain: "opentable.com"`; the extension rejects any fetch outside that. |
| A webpage you visit connecting to the WS | WS binds 127.0.0.1; the upgrade handler rejects requests with a non-null `Origin` header. |
| Arbitrary JS execution in your tabs | The protocol has no `eval_js`, `inject_script`, or equivalent. Closed by design. |
| Cookie / token exfiltration | The protocol has no `get_cookies` or `read_storage`. Closed by design. |
| Multi-user machine sniffing | Out of scope. Localhost binding only. If you share a user account with someone you don't trust, fetchproxy is not the biggest problem. |

## Local trust boundary

fetchproxy is a **local trust** product. Anything running on `127.0.0.1` under your user account is, by default, in the same trust zone as fetchproxy itself.

This matters because the cookie jar is *not* freely readable by every local process — Chrome and Safari encrypt cookies under per-user Keychain keys on macOS, and accessing them either prompts the user (Keychain dialog) or requires the right entitlements. **fetchproxy expands the local attack surface** by giving any local process that gets past the trust prompt the ability to act as the user's signed-in browser on the declared domain without a Keychain prompt.

We don't pretend otherwise. The defenses below are about making sure malicious local processes can't *quietly* trust themselves.

## Threat model

### T1 — Malicious local process exfiltrates signed-in sessions

A piece of malware running under your user account opens `ws://127.0.0.1:37149`, sends a forged `hello` frame claiming to be `opentable-mcp`, and uses `fetch` to scrape your reservations / favorites / email-on-file.

**Defense — explicit trust prompt.** First time the extension sees a connection from a new (port, server-name, declared-domain) tuple, it does NOT respond with a `hello`. Instead it shows a popup prompt to the user:

> **A new MCP server is asking to relay HTTP requests through your browser.**
> Server: `opentable-mcp v0.9.1`
> Domain: `opentable.com`
> Port: `37149`
> [Allow once] [Always allow] [Block]

"Always allow" persists the tuple in `chrome.storage.local`. Subsequent connections from the same tuple skip the prompt. Any change to name, version's major number, or domain → re-prompt. (Patch-version changes don't re-prompt to avoid prompt fatigue on minor releases.)

**Residual risk:** A user who hits "Always allow" without reading does in fact get pwned by a maliciously-named MCP. We can't fix social engineering. The prompt is intentionally interruptive — it shows the domain in large type and requires an active click.

### T2 — Webpage you visit connects to the WS

Chrome / Safari currently allow WebSocket connections from HTTP pages to `ws://localhost`. A malicious webpage could theoretically connect, send a `hello`, and use `fetch` against your sessions.

**Defenses (layered):**

1. **Reject non-localhost remote addresses at the TCP layer.** `ws-server.ts` binds explicitly to `127.0.0.1` (not `0.0.0.0`). This is already the case today in opentable-mcp.
2. **Reject WS upgrades whose `Origin` header is set to a public origin.** Browsers set `Origin: https://evil.com` on WS upgrades initiated by webpages; the extension is invoked from `chrome-extension://...` and sends a `null` or matching origin. We allowlist `null`, `chrome-extension://*`, `safari-extension://*`, `moz-extension://*` and reject everything else.
3. **No-key handshake.** Connections that don't send a valid `hello` frame within 5 seconds get closed. A drive-by webpage script trying to enumerate localhost ports gets nothing useful.
4. **Browser-side Private Network Access (PNA).** Chrome's [PNA spec](https://wicg.github.io/private-network-access/) (Chrome 130+) requires public-origin pages to do a CORS preflight before connecting to private addresses. We refuse to honor any preflight, which kills the connection.

### T3 — Compromised MCP server (supply chain)

The MCP server we trust gets compromised — npm package backdoor, or a malicious fork the user installs.

**Defense — per-MCP domain scope.** Every `fetch` request goes through:

```typescript
function isAllowedUrl(reqUrl: string, mcpDomain: string): boolean {
  const u = new URL(reqUrl);
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
  return u.hostname === mcpDomain || u.hostname.endsWith('.' + mcpDomain);
}
```

`opentable-mcp` declared `domain: "opentable.com"` in `hello` → the extension rejects fetches to anything not under `*.opentable.com`. A backdoored opentable-mcp can still leak your OpenTable data (we can't fix that without making the MCP useless), but it cannot ALSO be used to read your bank, email, or Slack.

If an MCP legitimately needs more than one domain (rare), it declares them explicitly in `hello`: `domains: ["opentable.com", "ot-cdn.com"]`. We don't support wildcard domains.

**Residual risk:** Same-domain exfil is unavoidable for the data the MCP is *supposed* to access. If an MCP gets compromised, you lose the data it had access to. This is the same tradeoff as any third-party tool you grant access to a service.

### T4 — User installs unknown MCP via Claude Code

A user runs `npx some-mcp-server` from a random GitHub. It registers with fetchproxy declaring `domain: "yourbank.com"`.

**Defense — same as T1.** The trust prompt is the gate. The popup shows the domain in large type. If you see `yourbank.com` in the prompt and didn't intend to install a banking MCP, you click Block.

We also surface a domain *category warning* for high-risk domains:

```
⚠️  This domain looks high-risk:
    yourbank.com — financial institution
    
    Are you sure you trust "some-mcp-server v0.0.1" with access?
    [Block] [I understand the risk, allow once]
```

Hard-coded list of high-risk TLDs/categories: financial (`*.bank`, known FI domains), webmail (`gmail.com`, `outlook.com`, etc.), social (`twitter.com`, `facebook.com`), government (`*.gov`, `*.gov.uk`). Curated, not exhaustive; meant to slow down obvious-scam scenarios, not to be a perfect filter.

### T5 — Lateral movement via tab navigation

A compromised MCP could fetch a URL that navigates the tab to an attacker-controlled page (e.g., a redirect chain). If the tab navigates, subsequent fetches go through a different document.

**Defense:** The extension's content-script fetches are `fetch(url, { credentials: 'include' })` from the page MAIN world, but they do NOT navigate the tab. Redirects are followed by the `fetch` API itself — the document the script runs in stays put. So this isn't a real attack vector unless the MCP server explicitly asks the user to navigate (which isn't a protocol verb).

### T6 — Service worker compromise via crafted WS frame

The extension's service worker parses every WS frame. A bug (prototype pollution, JSON parser issue, unhandled exception) could let a malicious local process pwn the worker.

**Defenses:**
1. **Schema validation on every frame.** Use a small inline validator (no dependency) that checks frame `type`, required fields, types. Reject everything else.
2. **Reject `__proto__`, `constructor`, etc. as JSON keys.** Standard prototype-pollution defense.
3. **Bound request body size.** Refuse fetch requests with `init.body.length > 1 MB`. Refuse responses larger than 5 MB (extension truncates and returns `ok: false, error: "response too large"`).
4. **Treat any parse error as a connection-killer.** If a frame fails validation, close the WS with code 1002 (protocol error). Reconnect logic kicks in.

### T7 — CSRF token exposure

Some target sites (OpenTable, Resy) use CSRF tokens that live on `window.__CSRF_TOKEN__` in the page MAIN world. Today's opentable-mcp extension syncs this to `document.documentElement.dataset.otMcpCsrf` so the isolated-world content script can read it.

**Concern:** That dataset attribute is readable by any script running on the page, including any third-party script the target site loads.

**Defense — same-origin assumption.** opentable.com → opentable.com. The third-party scripts in question are loaded by opentable.com itself; the CSRF is THEIR CSRF, used to call THEIR endpoints. Exposing it to same-origin scripts isn't a new exposure — they'd find it on `window.__CSRF_TOKEN__` anyway.

We document this clearly so future contributors don't expand the CSRF-sync pattern to expose tokens cross-origin.

### T8 — MCP impersonation

A malicious local process connects, sends `hello: { server: "opentable-mcp", version: "0.9.1", domain: "opentable.com" }` lying about its identity to get past the trust prompt.

**Defense — trust unit is (port, name, domain), not (name, domain).** The user trusts that port 37149 is opentable-mcp at install time. If a different process binds 37149 after opentable-mcp's WS server dies and tries to impersonate, the extension's WS connection survives across the takeover gap with a server-disconnect-detection. Each fresh WS connection's `hello` is recompared against the persisted tuple; if anything in (server name, domain, version major) changed, re-prompt. (Patch versions don't re-prompt.)

We CANNOT detect "different process took over the same port and is now sending the same hello" — that's a TOCTOU problem with no clean fix in the WS layer. The mitigation is OS-level: if a malicious process can `bind(127.0.0.1:37149)` after legitimate `opentable-mcp` exits, it can also do worse things to your user account. Goes back to [§Local trust boundary](#local-trust-boundary).

### T9 — Replay / cross-MCP id collision

Two MCPs both send `{ id: 1, ... }`. Could responses route to the wrong server?

**No.** Each MCP runs its own WS server; the extension maintains separate connection state per MCP. IDs are scoped per-connection.

### T10 — Update / supply chain on the extension itself

The extension is a Chrome / Safari extension distributed through the respective stores. Either store could push a compromised update.

**Defense:** Standard store-level review. We sign Safari builds with our Apple Developer cert; the Chrome Web Store signs Chrome builds. Mirror the published builds on GitHub Releases for users who want to verify before installing.

For users in the highest-paranoia tier: build from source (`packages/extension-chrome/build.ts` produces a loadable unpacked extension; `packages/extension-safari/` has an `xcodebuild` target).

## What we don't defend against

Stated plainly so there are no surprises:

- **A user account that's already compromised.** If malware has root/sudo or your full user privileges, it can hijack your real browser, install a malicious extension, or read your Keychain. fetchproxy isn't designed to defend against a fully-pwned account.
- **A user who clicks "Always allow" on every prompt.** We make the prompt loud, but we can't override active consent.
- **An MCP that lies about what it does.** If `opentable-mcp` actually exfiltrates your reservations to its author, the protocol can't tell. Trust the MCPs you install.
- **Multi-user shared machines.** Localhost is the trust boundary. Don't share user accounts.
- **State-actor-grade attackers.** Out of scope.

## Open questions (decide before v1)

1. **Optional shared-secret token in WS upgrade?** The MCP server library could write a per-MCP token to `~/.fetchproxy/<port>.token`, the extension reads it on first prompt, and subsequent connections require the token in a header. Defends against T8 in scenarios where the WS bind survives an MCP restart, but adds a config file the user has to live with. Lean toward NO for v1 — the trust prompt is enough.

2. **High-risk-domain blocklist hard-coded or fetched?** Hard-coded is auditable; fetched can be updated faster. Lean toward hard-coded for v1, in `extension-core/src/high-risk-domains.ts`.

3. **Trust scope: per-port or per-(port,name,domain)?** Spec says (port, name, domain). Stricter is safer. Lean toward keeping it strict.

4. **Should we offer a "paranoid mode" that re-prompts on every fetch?** Maybe for sensitive domains. Lean toward NO for v1 — too prompt-noisy. Could add per-domain "confirm every request" as a v2 setting.

## Reporting

Security issues: TODO email or GPG key once we have a release. Until then, GitHub Security Advisories on `chrischall/fetchproxy`.
