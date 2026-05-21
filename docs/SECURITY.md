# fetchproxy security model

The whole point of fetchproxy is to let a Node process speak as the user's signed-in browser. That's a powerful primitive. This doc enumerates what we defend against, what we *don't* defend against, and how the defenses are structured.

If you don't trust everything else running on your local user account, **fetchproxy is not for you.** Read [§Local trust boundary](#local-trust-boundary) first.

This document tracks 0.2.0. Two structural changes vs. 0.0.x / 0.1.x bear on the threat model:

- **Concentrator + end-to-end encryption.** One WS port serves N MCPs. One MCP wins the port and routes encrypted frames between the others and the extension. The host MCP cannot read peer traffic — every data frame is AES-256-GCM encrypted under a per-session key derived from each MCP's own identity key. This adds T-host-MITM as an explicit threat and closes it.
- **Capabilities.** The MCP-facing API is gated by an explicit, user-approved capability set declared in the hello frame. `fetch` is the default; `read_cookies` is strictly opt-in and surfaces a visible warning at pair time. The capability set is part of the trust record; widening or narrowing it forces a re-pair.

---

## TL;DR

| What | Defense |
|---|---|
| Random local process trying to use your sessions | Per-identity SAS pair prompt in the extension popup. New identities never auto-trust. |
| Compromised MCP fetching off-domain | Per-MCP domain allowlist. Each MCP declares `domains: [...]`; the extension rejects any fetch outside the set. |
| Host MCP reading peer MCP traffic on the shared bridge | End-to-end AES-256-GCM between each MCP and the extension. Host routes by `mcpId` but never holds the session key. |
| A webpage you visit connecting to the WS | WS binds `127.0.0.1`; the upgrade handler rejects non-extension origins; Chrome Private Network Access blocks public-origin preflights. |
| MCP silently expanding its powers post-pair | The trust record stores the approved `domains` AND `capabilities` set. Any change → re-pair prompt. |
| Arbitrary JS execution in your tabs | The protocol has no `eval_js`, `inject_script`, or equivalent. Closed by design. |
| Storage exfiltration | `read_storage`, `read_indexeddb`, etc. don't exist. `read_cookies` is a deliberate, narrow opt-in. |
| Multi-user machine sniffing | Out of scope. Localhost binding only. |

## Local trust boundary

fetchproxy is a **local trust** product. Anything running on `127.0.0.1` under your user account is, by default, in the same trust zone as fetchproxy itself.

This matters because the cookie jar is *not* freely readable by every local process — Chrome and Safari encrypt cookies under per-user Keychain keys on macOS, and accessing them either prompts the user (Keychain dialog) or requires the right entitlements. **fetchproxy expands the local attack surface** by giving any local process that gets past the trust prompt the ability to act as the user's signed-in browser on the declared domain without a Keychain prompt.

We don't pretend otherwise. The defenses below are about making sure malicious local processes can't *quietly* trust themselves.

## Threat model

### T1 — Malicious local process exfiltrates signed-in sessions

A piece of malware running under your user account opens `ws://127.0.0.1:37149`, sends a forged `hello` frame claiming to be `opentable-mcp`, and tries to use `fetch` to scrape your reservations / favorites / email-on-file.

**Defense — identity-keyed SAS pair prompt.** Every MCP holds a long-term Ed25519 + X25519 keypair at `~/.fetchproxy/identity/<server-name>.json` (mode `0600`). The hello frame carries the public keys, a fresh `sessionNonce`, and an Ed25519 signature over `mcpId || sessionNonce`. The extension verifies the signature, then looks up the identity hash in `chrome.storage.local["trustedMcps"]`.

If unknown, the extension does NOT respond with a `ready` frame. Instead it shows a popup:

> **A new MCP server is asking to relay HTTP requests through your browser.**
> Server: `opentable-mcp v0.10.0`
> Domains: `opentable.com`
> Capabilities: HTTP fetches
> Pair code: `123-456`
> [Approve] [Cancel]

The 6-digit pair code (SAS — Short Authentication String) is `SHA256(identityX25519Pub)[0..3] mod 1_000_000` formatted as `XXX-XXX`. The MCP prints it to stderr; the extension shows the same value. The user compares them and clicks Approve. Same identity → same code, every time. Approving stores the identity-key hash plus the declared `domains` and `capabilities` set in `chrome.storage.local`; subsequent connections with the same hash skip the prompt.

A malicious process *can* connect, but it can't produce a valid signature without the legitimate MCP's private key, and it can't fake a pair code that matches a code the user is willing to approve.

**Residual risk:** A user who hits Approve without comparing the code is still vulnerable to social engineering. We can't fix that. The popup is intentionally interruptive and shows the domain in large type.

### T2 — Webpage you visit connects to the WS

Chrome / Safari currently allow WebSocket connections from HTTP pages to `ws://localhost`. A malicious webpage could theoretically connect, send a `hello`, and try to use `fetch` against your sessions.

**Defenses (layered):**

1. **Reject non-localhost remote addresses at the TCP layer.** The WS server binds explicitly to `127.0.0.1` (not `0.0.0.0`).
2. **Reject WS upgrades whose `Origin` header is set to a public origin.** The extension is invoked from `chrome-extension://...` and sends a `null` or matching origin. Anything else is rejected.
3. **No-key handshake.** Connections that don't send a valid `hello` frame within 15 seconds get closed. A drive-by webpage script enumerating localhost ports gets nothing useful.
4. **Browser-side Private Network Access (PNA).** Chrome's PNA spec (Chrome 130+) requires public-origin pages to do a CORS preflight before connecting to private addresses. We refuse to honor any preflight, which kills the connection.
5. **Identity signature.** Even if a webpage got past the above, it cannot mint a valid `sessionSig` over `mcpId || sessionNonce` without the legitimate MCP's private key — and an unknown identity falls into T1 (pair prompt).

### T3 — Compromised MCP server (supply chain)

The MCP server we trust gets compromised — npm package backdoor, or a malicious fork the user installs.

**Defense 1 — per-MCP domain allowlist.** Every MCP declares `domains: [...]` in its hello. The extension allows a fetch iff its URL host equals one of those entries exactly OR is a subdomain of one of them:

```ts
function isAllowedUrl(reqUrl: string, declared: string[]): boolean {
  const u = new URL(reqUrl);
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
  const host = u.hostname.toLowerCase();
  return declared.some((d) => host === d || host.endsWith('.' + d));
}
```

`opentable-mcp` declares `["opentable.com"]` → the extension rejects fetches to anything not under `*.opentable.com`. A backdoored opentable-mcp can still leak your OpenTable data (we can't fix that without making the MCP useless), but it cannot ALSO be used to read your bank, email, or Slack.

If an MCP legitimately needs more than one domain (rare), it enumerates them: `domains: ["honeybook.com", "hbsplit.com"]`. There is no wildcard syntax.

**Defense 2 — capability allowlist.** Each MCP also declares a `capabilities: [...]` set. `fetch` is the default; `read_cookies` is opt-in. A backdoored MCP can't escalate to verbs the user didn't approve at pair time — the trust record stores the approved set, and the extension rejects any inner request whose `op` isn't in it.

**Defense 3 — pair record locks both sets.** If the MCP later declares a different `domains` or `capabilities` set (set-equality check, order-insensitive), the extension treats the trust record as missing and falls back to a re-pair prompt. So a compromised MCP that secretly widens its domain list to add a new target site or asks for `read_cookies` post-pair forces a fresh popup with the new ask in plain view.

**Residual risk:** Same-domain, same-capability exfil is unavoidable for the data the MCP is *supposed* to access. If an MCP gets compromised, you lose what it had legitimate access to. This is the same tradeoff as any third-party tool you grant access to a service.

### T-cookie-exfil — `read_cookies` misuse

`read_cookies` is the most-elevated capability in the protocol. The extension reads `document.cookie` from a tab on a declared domain and returns the string. Only non-HttpOnly cookies are visible to page JS — the HTTP-only session token that actually authenticates the user is NOT included — but the value still contains things like CSRF tokens and "is logged in?" markers and is enough to break a site's auth bootstrap in some designs.

**Defenses:**

1. **Opt-in at the wire level.** `read_cookies` only works if the MCP declared it in `capabilities`. Omitting it disables the verb entirely; even the `FetchproxyServer.readCookies()` helper throws synchronously at the call site so an MCP author who forgot to declare it gets a clear error.
2. **Approved at pair time.** The popup labels `read_cookies` with a visible warning marker (a `cap-warn`-styled list entry that decorates the label with a warning glyph) so the user notices the elevated trust. The trust record stores the approved capability set; a post-pair upgrade to `read_cookies` forces a re-pair with the new ask spelled out.
3. **Domain-bound.** Like `fetch`, `read_cookies` must target a tab on a declared domain — there's no way to read cookies from outside the MCP's allowlist.
4. **HTTP-only cookies are not exposed.** The browser refuses to surface them to page JS. fetchproxy doesn't have a side channel to read them either — it relies on `document.cookie`, same as any in-page script.

**Residual risk:** A user who approves a pair with `read_cookies` is giving the MCP a powerful read primitive for the declared domains. The popup tries to make that visible; the trust record forces re-approval on change. There is no further defense — if you don't trust the MCP, don't approve the pair.

### T-host-MITM — Host MCP reading peer traffic

In the 0.2.0 concentrator model, one MCP wins the WS port and acts as the host. Other MCPs on the same machine dial it as peers and tunnel their traffic through. A backdoored host MCP could read or tamper with peer traffic, exfiltrating their fetches or rewriting responses.

**Defense — end-to-end AES-256-GCM.** Each MCP runs its own crypto handshake with the extension, independent of the host:

```
shared     = X25519(extEphemeralPriv, mcpIdentityX25519Pub)
sessionKey = HKDF-SHA256(shared, salt=sessionNonce, info="fetchproxy/0.1.0/session", L=32)
```

The session key is derived between the *peer MCP* and the *extension*. The host never holds the IKM (the X25519 ECDH output) and cannot derive `sessionKey`. Every data frame is:

```
{ type: 'frame', mcpId, seq, iv, ciphertext }
```

where `ciphertext` is `AES-256-GCM(sessionKey, iv, JSON(innerFrame))` with a 16-byte GCM tag. The host sees `mcpId` (route hint), `seq` (replay protection), `iv` (per-frame nonce), and opaque ciphertext. It cannot decrypt and any tampering with the bytes fails GCM verification on the other end.

Replay protection: receivers track the highest seen `seq` per direction per session and reject anything `<= lastInbound`. WS guarantees ordering, so we don't have to tolerate gaps.

**Residual risk:** The host can drop or delay peer traffic (denial of service against peers). It cannot read or modify it. If the host crashes, peers race the port and one wins; the takeover is invisible to peers because trust + session derivation are stateless given the identity keys.

### T4 — User installs unknown MCP via Claude Code or similar

A user runs `npx some-mcp-server` from a random GitHub. It registers with fetchproxy declaring `domains: ["yourbank.com"]` and possibly `capabilities: ["fetch", "read_cookies"]`.

**Defense 1 — same as T1.** The pair prompt is the gate. The popup shows the domain set and capability set; if you see `yourbank.com` in the prompt and didn't intend to install a banking MCP, you click Cancel.

**Defense 2 — high-risk-keyword warning.** The popup runs a substring match against each declared domain. If any of `bank`, `gov`, `mil` appears anywhere in the hostname, the popup decorates the entry with a `WARNING: <domain> looks high-risk.` line above the Approve button.

```ts
const HIGH_RISK_KEYWORDS = ['bank', 'gov', 'mil'];
HIGH_RISK_KEYWORDS.some((k) => domain.includes(k));
```

**Limitations of the high-risk heuristic — by design, not aspirations:**

- It's a *speed bump*, not a filter. Substring matching catches obvious cases (`chase.com` won't fire, but `chasebankonline.com` would) and misses non-obvious ones. `creditkarma.com`, `wellsfargoadvisors.com`, `irs.gov` (matches), `paypal.com` (does NOT match), `coinbase.com` (does NOT match), `gmail.com` (does NOT match) — the list is illustrative, not principled.
- We deliberately don't ship a curated allowlist of "financial institutions" or "webmail providers" — that's a category we can't keep accurate, and a stale list gives false confidence.
- The defense the user must rely on is reading the domain list, not the warning marker. The warning exists to make the user pause; the actual gate is the explicit Approve click.

### T5 — Lateral movement via tab navigation

A compromised MCP could fetch a URL that navigates the tab to an attacker-controlled page (e.g., a redirect chain). If the tab navigates, subsequent fetches would go through a different document.

**Defense.** The extension's content-script fetches are `fetch(url, { credentials: 'include' })` from the page MAIN world, but they do NOT navigate the tab. Redirects are followed by the `fetch` API itself — the document the script runs in stays put. So this isn't a real attack vector unless the MCP server explicitly asks the user to navigate, which isn't a protocol verb.

### T6 — Service worker compromise via crafted WS frame

The extension's service worker parses every WS frame. A bug (prototype pollution, JSON parser issue, unhandled exception) could let a malicious local process pwn the worker.

**Defenses:**

1. **Schema validation on every frame.** A dependency-free validator in `@fetchproxy/protocol` checks `type`, required fields, types, base64 well-formedness, hostname syntax, capability-string membership. Unknown frames close the WS with code `1002`.
2. **Reject `__proto__`, `constructor`, `prototype` as JSON keys.** Standard prototype-pollution defense. Also reject objects with a non-`Object.prototype` prototype.
3. **Bound request/response body size.** Refuse fetch requests with `init.body.length > 1 MB`. Refuse response bodies larger than 5 MB.
4. **Treat any parse / validation error as a connection-killer.** If a frame fails validation, close the WS with code `1002`. Reconnect logic kicks in.
5. **GCM authenticity check.** Tampered encrypted frames fail decryption and close the session.

### T7 — CSRF token exposure

Some target sites (OpenTable, Resy) use CSRF tokens that live on `window.__CSRF_TOKEN__` in the page MAIN world. The extension syncs this to a `dataset` attribute so the isolated-world content script can read it before issuing a fetch.

**Concern.** That dataset attribute is readable by any script running on the page, including any third-party script the target site loads.

**Defense — same-origin assumption.** opentable.com → opentable.com. The third-party scripts in question are loaded by opentable.com itself; the CSRF is THEIR CSRF, used to call THEIR endpoints. Exposing it to same-origin scripts isn't a new exposure — they'd find it on `window.__CSRF_TOKEN__` anyway.

We document this so future contributors don't expand the CSRF-sync pattern to expose tokens cross-origin.

### T8 — MCP impersonation

A malicious local process connects and sends a hello claiming to be `opentable-mcp v0.10.0` with `domains: ["opentable.com"]` to ride on a previously-approved trust record.

**Defense — identity-key signature.** The hello carries `identityX25519Pub`, `identityEd25519Pub`, a fresh `sessionNonce`, and `sessionSig = Ed25519Sign(identityEd25519Priv, mcpId || sessionNonce)`. The extension verifies the signature on every connection.

A bare hello with a stolen `identityX25519Pub` (it's public!) won't work — the validator demands a valid signature, which requires the private key. The trust record is keyed by `hex(sha256(identityX25519Pub))`, so even a name/version-perfect impostor with a different key hits the pair prompt.

The legacy 0.0.x port-based trust unit (`(port, server-name, domain)`) is gone. Trust is now per-identity-key, full stop. Port changes, restarts, and MCP package renames don't invalidate trust; key compromise does.

**Residual risk:** If the legitimate MCP's private key on disk is stolen (`~/.fetchproxy/identity/<server-name>.json` mode `0600` — but a fully-pwned account can read it), an attacker can impersonate it. Goes back to [§Local trust boundary](#local-trust-boundary).

### T9 — Replay / cross-MCP id collision

Two MCPs both send `{ id: 1, ... }`. Could responses route to the wrong server? Could a recorded frame be replayed?

**Defense — per-session keying.** Each MCP has its own `sessionKey` (different per-connection because of the fresh `sessionNonce`). Frames addressed to MCP A cannot be decrypted by MCP B even if the host misroutes them. The host routes by `mcpId`; within an `mcpId`, request `id`s are scoped per-connection.

**Replay defense — monotonic seq.** Receivers reject any frame whose `seq` is `<= lastInbound`. WS guarantees ordering, so legitimate frames always increase. A replayed frame from earlier in the session is dropped.

### T10 — Update / supply chain on the extension itself

The extension is distributed via the Chrome Web Store (eventually) and built-from-source today. Either path could ship a compromised update.

**Defense:** Standard store-level review where applicable; for users in the highest-paranoia tier, build from source (`packages/extension-chrome/build.ts` produces a loadable unpacked extension; the GitHub Release also ships a `fetchproxy-extension-${VERSION}.zip` built by the release workflow).

Extension major-version bumps invalidate the trust store (force re-pair on every MCP); patch and minor bumps carry trust forward. The trust record schema is versioned on read; pre-capability records (no `capabilities` field) are normalised to `["fetch"]` for back-compat.

## What we don't defend against

Stated plainly so there are no surprises:

- **A user account that's already compromised.** Root/sudo or full user privileges → malware can read `~/.fetchproxy/identity/<server-name>.json`, install a malicious extension, or read your Keychain. fetchproxy isn't designed to defend against a fully-pwned account.
- **A user who clicks Approve on every prompt.** We make the prompt loud, but we can't override active consent.
- **An MCP that lies about what it does within its declared scope.** If `opentable-mcp` actually exfiltrates your reservations to its author over a legitimate-looking opentable.com URL, the protocol can't tell. Trust the MCPs you install.
- **Multi-user shared machines.** Localhost is the trust boundary. Don't share user accounts.
- **State-actor-grade attackers.** Out of scope.

## Resolved questions (closed in 0.2.0)

These were open in the 0.0.3 / 0.1.x security doc and have since been answered by the implementation.

1. **Shared-secret token in WS upgrade?** *Resolved: no, identity keys instead.* Each MCP holds a long-term Ed25519/X25519 keypair and signs `mcpId || sessionNonce` per connection. Stronger than a static token (no replay) and doesn't require a per-port config file. See T8.
2. **Trust scope — per-port or per-`(port, name, domain)`?** *Resolved: per-identity-key.* Stricter than either of the original options. The trust record is keyed off `hex(sha256(identityX25519Pub))`; the `domains` and `capabilities` sets are stored alongside and any change forces a re-pair. See T1 + T3.

## Still-open questions

1. **High-risk-domain heuristic: substring vs. curated list.** *Status: substring with `bank | gov | mil`.* Curated lists go stale and give false confidence; substring is honest but imprecise. We may add a more careful classifier when there's a real-world miss that hurts. See T4.
2. **Paranoid mode that re-prompts on every fetch?** *Status: not implemented.* Too prompt-noisy for the default. Could become a per-domain "confirm every request" toggle in a future release.
3. **Extension-side identity key.** *Status: ephemeral per-connection.* The extension generates a fresh X25519 keypair every time it connects. That's fine for confidentiality, but means a peer-MCP can't pin "this is the same extension as last time" if the WS reconnects. Probably never needed; flag for revisit if a use case appears.

## Reporting

Security issues: open a private GitHub Security Advisory on `chrischall/fetchproxy`.
