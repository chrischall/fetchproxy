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
| Host MCP reading peer MCP traffic on the shared bridge | End-to-end AES-256-GCM between each MCP and the extension. Host routes by `mcpId` but never holds the session key — and since 2.0.0 the ready signature covers the ephemeral key, so it cannot substitute one it does. |
| A webpage you visit connecting to the WS | WS binds `127.0.0.1`; the upgrade handler rejects non-extension origins; Chrome Private Network Access blocks public-origin preflights. |
| MCP silently expanding its powers post-pair | The trust record stores the approved `domains` AND `capabilities` set. Any change → re-pair prompt. |
| Arbitrary JS execution in your tabs | The protocol has no `eval_js`, `inject_script`, or equivalent. `graphql` is NOT this — it can only invoke a page-declared GraphQL operation through the page's own Apollo client, never arbitrary page code. See [§T-graphql-misuse](#t-graphql-misuse--graphql-capability-misuse). |
| Storage exfiltration | `read_storage`, `read_indexeddb`, etc. don't exist. `read_cookies` is a deliberate, narrow opt-in. |
| An MCP tampering with your session | The one write verb, `write_cookies`, can only overwrite cookies the MCP already declares readable, only on declared domains, only when the cookie already exists, and only under its own approved capability. See [§T-cookie-write](#t-cookie-write--write_cookies-capability-misuse). |
| Something else answering as your browser | The MCP pins the extension's identity on first pair and refuses a different one — the mirror of `trustedMcps`. See [§T-fake-extension](#t-fake-extension--something-else-answering-as-the-browser). 1.12.0+. |
| A remote bridge the user configured turning into a way in | The target is `wss://` (or loopback), the credential is a separate field, no configuration removes or repoints the loopback link, and every MCP the relay carries still pairs, pins and encrypts exactly as it does on a laptop. See [§T-remote-bridge](#t-remote-bridge--a-configured-remote-bridge-target). 2.1.0+. |
| Multi-user machine sniffing | Out of scope. Localhost binding only. |

## Local trust boundary

fetchproxy is a **local trust** product. Anything running on `127.0.0.1` under your user account is, by default, in the same trust zone as fetchproxy itself.

This matters because the cookie jar is *not* freely readable by every local process — Chrome and Safari encrypt cookies under per-user Keychain keys on macOS, and accessing them either prompts the user (Keychain dialog) or requires the right entitlements. **fetchproxy expands the local attack surface** by giving any local process that gets past the trust prompt the ability to act as the user's signed-in browser on the declared domain without a Keychain prompt.

We don't pretend otherwise. The defenses below are about making sure malicious local processes can't *quietly* trust themselves.

### Where the concentrator binds — `FETCHPROXY_WS_HOST`

**2.2.0+.** The concentrator binds `127.0.0.1`, and that address is doing work in this document: [§T2](#t2--webpage-you-visit-connects-to-the-ws) defence 1 and the [§T-fake-extension](#t-fake-extension--something-else-answering-as-the-browser) argument both rest on "the only thing that can reach the socket is a process on this host". `FetchproxyServerOpts.host` has always allowed a different address, and `FETCHPROXY_WS_HOST` now supplies it from the environment the way `FETCHPROXY_WS_PORT` supplies the port — for the consumer that never sees the option, `@fetchproxy/bootstrap`. It exists for exactly one topology and is worth being exact about it.

**The topology.** A hosted deployment that sandboxes each MCP child (chrischall/mcp-host, gVisor) gives every child its own network namespace. Inside one, `127.0.0.1` is a loopback nobody outside the sandbox can reach — the runner's relay agent, which is what dials a hosted child in place of the browser, gets connection refused. So the child binds the sandbox end of a veth pair instead, `10.200.<slot>.2`, and the runner dials that. The address is private to a /30 whose other end is the runner: the population that can reach the socket is still "a process on this host", the trust scope 127.0.0.1 states is unchanged, and nothing in `extension-trust.ts` needs to reason differently. The fence moved; what is inside it did not.

**It is not a knob for a laptop.** Binding an address the network can route — `0.0.0.0`, the machine's LAN address — puts the bridge, and through it the user's signed-in cookies, on the network, and every defence above that says "local" stops being true. Nothing in fetchproxy prevents that bind, for the same reason nothing prevents `opts.host`; the variable is an operator's statement about where the sandbox is, and the operator is accountable for it being one.

**What it refuses.** Only a literal IP address (v4 or v6) is honoured. A hostname — `localhost` included — an empty value or whitespace is ignored and the default applies, never resolved: a resolved name binds whatever the resolver said, which can differ between the child and the thing dialling it, and a mistyped variable must fall through to the bind that has always worked rather than becoming a dead bridge or a bind on something the operator did not write down. An explicit `opts.host` is a decision made in code and beats the environment. `bridgeHealth().host` reports the address actually bound so a hosted healthcheck can tell "bound where the relay dials" from "bound on a loopback nothing outside the sandbox can reach".

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

### T-cookie-write — `write_cookies` capability misuse

`write_cookies` is the **only verb in the protocol that changes browser state**. Everything else reads.

It exists for one failure class. Sites that **rotate** a credential cookie hand back a new value on every refresh; when an MCP refreshes and keeps the result to itself, the copy in the browser's cookie jar is dead, and the user is silently signed out of a tab they never touched — usually reported to them as "inactivity", which points nowhere near the cause. Reading cannot repair that. Measured on creditkarma.com: **two** MCP-side refreshes were enough to log out an untouched, freshly signed-in tab, and reloading the page does not recover it — only a full sign-in does (chrischall/creditkarma-mcp#119).

**What it is NOT:** a general cookie-authoring primitive. Four independent constraints, each enforced on the extension side:

1. **Capability.** `write_cookies` is declared in the hello, approved at pair time as its own line, and stored in the trust record — so adding it later forces a re-pair with the diff UI, like any other capability change. The popup labels it "Overwrite cookies it can already read (can change your signed-in session)" rather than as a sibling of the read verbs, because it is not one.
2. **Read scope.** Every name must already be in the MCP's declared `cookieKeys`. A write can never reach a cookie the user did not already approve for reading, so granting it cannot widen *which* cookies are in play — only what may be done to the ones already listed.
3. **Domain.** The origin is gated against the declared `domains`, decided on the bare origin before any path is appended, exactly as the read path does.
4. **Existence.** The cookie must already exist. This verb refreshes a value in place; it cannot create cookies. That is what keeps it from becoming a cookie-*injection* primitive — an MCP cannot mint a session cookie for a domain, only replace a value the user's browser already holds.

Attributes are copied off the cookie being replaced (`domain`/`path`/`secure`/`httpOnly`/`sameSite`/`expirationDate`), so a write overwrites rather than shadows. `domain` is omitted for host-only cookies and `expirationDate` for session cookies, because passing either would silently widen the cookie's scope or lifetime.

**Residual risk:** an MCP granted `write_cookies` can set a declared cookie to a value of its choosing on a declared domain — including a value the user did not authorise, e.g. swapping a session for one the MCP controls. The containment is that this is limited to cookies the MCP could already *read* (and therefore already exfiltrate), so it grants no new access to the user's data; what it adds is the ability to alter the browser's state for those specific cookies. As with `read_cookies`: if you don't trust the MCP, don't approve the pair.

### T-graphql-misuse — `graphql` capability misuse

`graphql` invokes a **page-declared GraphQL operation through the page's OWN Apollo client** (`window.__APOLLO_CLIENT__`), in the page's MAIN world. This exists because some endpoints (OpenTable's `RestaurantsAvailability`) reject the isolated-world `fetch` path at the edge — the bot-detection sensor telemetry lives inside the page's own Apollo link chain, not on `window.fetch` — so the only way to clear it is to run the request through the exact code path the page itself uses.

**What it is NOT:** general MAIN-world JS execution. There is no `page_eval`, no arbitrary function call, no way to reach any object other than the page's Apollo client, and no way to run any operation the page hasn't already defined.

**Defenses:**

1. **It can only run operations the page already exposes.** The extension carries NO hardcoded query text and NO persisted-query hash. It hooks `client.link.request` to capture the live `DocumentNode` the page's own Apollo client observed for a given `operationName`, then reuses that exact object via `client.query(...)`. If the page's client has never observed the operation (e.g. the user hasn't loaded the relevant page yet), the bridge returns a typed "operation not yet observed on this tab" error rather than inventing a query. When several tabs match, the query is offered to each in turn until one owns the operation — this widens *which tab* may serve a request, never *which operations* may run: every tab is already on the declared-domain allowlist, and each still resolves the DocumentNode from its own page.
2. **Declared-operation allowlist, approved at pair time.** The MCP declares a `graphqlOps: [{ name, operationName }]` list in its hello. Only operations in this list can ever be invoked; the popup surfaces the exact `operationName` values verbatim so the user sees precisely what will run. Widening or changing the declared set forces a re-pair with a diff, same as every other capability.
3. **Capability-gated.** `'graphql'` must be declared in `capabilities` and approved at pair time — same opt-in mechanics as `read_cookies` / `read_dom`. The popup labels it with a warning marker.
4. **Domain allowlist + host-or-subdomain tab match.** Same as every other verb: the tab the query runs against must be on one of the MCP's declared `domains` (or a subdomain of one).
5. **Returns only the GraphQL response `data`.** The response is `{ ok: true, data }` where `data` is the parsed GraphQL response body — no page state, no DOM, no other globals, no ability to read anything the operation itself didn't return.
6. **Per-call `variables` are supplied by the MCP, not the page.** The extension never inspects or mutates them — it passes the MCP's object straight to `client.query({ query, variables })`.

**Residual risk:** If the operation the MCP declared genuinely returns sensitive data (e.g. a booking-availability query that also echoes account details), that's the same tradeoff as any declared `fetch` endpoint — the user is trusting the MCP with what it's declared, not with arbitrary access. The mechanism cannot be used to invoke an operation the user hasn't implicitly exposed by using the page normally.

**Known limitation (tracked, not yet fixed):** the MAIN-world bridge script (`capture-logger.ts`) wraps `client.link.request` on **every** page that exposes an Apollo client, regardless of whether any MCP has declared the `graphql` capability — the captured `DocumentNode`s stay in an in-process `Map` and are never exfiltrated, so this is a wider MAIN-world footprint (not a data leak) than the read-only CSRF sync this file previously did. It also polls for `window.__APOLLO_CLIENT__` every 500ms for the lifetime of any tab that never gets one, with no give-up cap. Neither is a security hole, but both are worth tightening — see the PR #178 auto-review follow-up issue.

### T-in-page-fetch — `fetch_in_page` capability misuse

`fetch_in_page` permits a fetch carrying `init.inPage: true` to be issued by the page's MAIN world instead of the content script's isolated world. Everything else is unchanged: same URL, method, body, injected CSRF header, same cookies, same domain allowlist.

It exists because some edge bot-managers distinguish the two worlds. Verified live on opentable.com: a GraphQL **mutation** POST returns 403 from the isolated world and 200 from the page, byte-for-byte identical, while GraphQL *queries* and *REST* writes pass from either — that 403 blocks every booking write. The precise signal was never confirmed (most likely the extension `Origin`/`Sec-Fetch-Site` Chrome attaches to content-script requests), so this is characterised by the observed world difference, not by a header we read.

**What it is NOT:** MAIN-world JS execution. Nothing is evaluated in the page. The bridge takes a URL, method, headers and body, calls `fetch`, and posts back `{status, url, body}`. It cannot read page globals, the DOM, or anything else.

**Defenses:**

1. **Per-request, not per-MCP.** The flag is set on individual calls, so an MCP needing it for two GraphQL mutations keeps the isolated world for every other fetch. There is no mode that routes all traffic through the page.
2. **Capability-gated, refused early.** `fetch_in_page` must be declared and approved at pair time; `handleFetchRequest` rejects `inPage: true` from an MCP without it **before the request reaches any tab**.
3. **Strictly boolean on the wire.** The validator rejects a non-boolean `inPage` rather than coercing it, so a truthy string can never become a privilege decision.
4. **Domain allowlist unchanged.** The URL must still be on the MCP's declared `domains`, with the usual tab matching.
5. **Every field of the reply is validated.** MAIN and isolated worlds share one message bus, so page script can post a forged `fetch-res`. The isolated side matches a monotonic `reqId`, requires numeric `status` and string `url`/`body`, and enforces the same `MAX_RESPONSE_BODY_BYTES` cap as the ordinary path — a malformed shape reaching the server's validators would otherwise tear down the WebSocket for every MCP on the concentrator.
6. **No privilege is created in the page.** The bridge runs with the page's own credentials on its own origin, so anything it can fetch, page script could already fetch itself.

**Residual risk — and it is a real one.** The isolated world is what makes an ordinary fetchproxy request tamper-resistant: page script cannot see or alter it. A request routed through the MAIN world gives that up. A compromised or hostile page on a declared domain can patch `window.fetch` and observe or modify a flagged request's headers and body — including the injected CSRF token — and can hand the MCP a fabricated response. That is strictly worse than the isolated-world path, and it is exactly why this is a separate capability the user approves rather than a silent fallback: an MCP declaring it is asking for that trade on the calls it marks. Do not declare it for requests that work without it.

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

**1.12.0 correction — this claim was not true on the peer path until 1.12.0.** The paragraphs above describe the intent, and the intent held for the host's own session from 0.4.0. It did not hold for peers, and the reason is worth stating plainly rather than quietly fixing: a peer derived its session key from `ready.extensionSessionPub` and verified *nothing* — no signature, no identity. So the concentrator could put its own ephemeral public key in that frame, derive the same shared secret with the peer, and read and rewrite everything the peer believed was end-to-end encrypted, forwarding to the real extension to keep the illusion. "The host never holds the IKM" is only true when the peer authenticates whose ephemeral key it is deriving against.

1.12.0 narrows it with the material 0.4.0 already defined: the host relays the extension's hello to every peer, and a peer verifies `Ed25519Sign(extPriv, ownHelloNonce || extHelloNonce)` against it before deriving anything — the same check `host.ts` does for its own session. A concentrator cannot produce that signature without the extension's private key, so it can no longer invent an extension out of nothing, and (with the pin below) it cannot substitute a *different* extension identity either.

**2.0.0 closes the rest of it.** 1.12.0 left a residual worth naming, because it was the whole of the remaining attack: the signature covered the two nonces and NOT `ready.extensionSessionPub`, so a concentrator relaying the genuine hellos and the genuine signature — every nonce and identity intact — could still swap the ephemeral public key for one it held the private half of, derive the same shared secret, and read and rewrite the traffic. Everything the receiver checked still passed, because none of it committed to the key the ECDH actually used. That was true of the host's own session too, and had been since 0.4.0.

`sessionSig` now signs `(mcpHelloNonce || extHelloNonce || extensionSessionPub)` — one definition, `readySignaturePayload()` in `@fetchproxy/protocol`, used by the extension that produces it and both server paths that verify it. A relay would have to sign its own ephemeral key with the extension's Ed25519 private key, which is the thing it does not have.

This is a wire break (`PROTOCOL_VERSION` 2 → 3) and is handled as one: a v2 peer is refused at the hello rather than negotiated down. A negotiated variant was considered and rejected — a relay that can rewrite frames can rewrite the version it sees advertised, so the downgrade would be the attacker's to choose unless the negotiation itself were signed. All packages release together, and the extension must be reloaded with them.

One compatibility seam remains, deliberately: concentrators before 1.12.0 relay no hello, so a 1.12.0 peer behind an older host has nothing to verify against. It warns loudly and proceeds, because the port election picks the concentrator arbitrarily and refusing would break a mixed-version fleet at random. `requireExtensionIdentity: true` turns that warning into a refusal, and should be set anywhere the concentrator is not simply another MCP on the same laptop. **The peer path's guarantee is only in force once every MCP on the machine is ≥1.12.0.**

### T-fake-extension — Something else answering as the browser

Until 1.12.0 an MCP's answer to "which browser is this?" was "whichever one said hello". `host.ts` verified the ready signature against the identity presented *in the same connection* — proof that the connecting party holds the key it just showed us, and no evidence at all that it is the party we paired with — and `peer.ts` verified nothing (above). The extension has pinned the MCP since 0.2.0 (`trustedMcps`, keyed by the SHA-256 of its X25519 pub); nothing pinned in the other direction.

On loopback that asymmetry is the [local trust boundary](#local-trust-boundary) doing its job: the only thing that can reach `127.0.0.1:37149` is a local process, and a local process under your account is already inside the model. It stops being harmless the moment the far end of that socket can be something other than a process on this machine — a relayed or hosted bridge, for example. There, "whichever extension said hello" means a stolen relay credential buys a working session with every bridged MCP: the attacker's browser sees every request those MCPs make (URLs, headers, bodies) and answers them with content of its choosing, and there is no prompt anywhere, because the MCP has nothing to compare against and the user's browser is not involved.

**Defense — the MCP pins the extension too.** First contact is trusted and remembered (`~/.fetchproxy/identity/<server-name>.extension-trust.json`, mode 0600, written only after the ready signature proves the key). A different identity afterwards is refused before any session exists, on both the host and peer paths. This is the mirror of `trustedMcps`, and it uses the same TOFU shape the extension uses.

**Getting out of it deliberately.** A legitimate extension re-install mints a new identity and would otherwise lock every MCP out at once, so the refusal names the exact file, `fpx trust list` / `fpx trust clear <server-name>` shows and drops pins, and `FETCHPROXY_TRUST_NEW_EXTENSION=1` re-pairs an MCP whose source you do not own. Each of those is a deliberate act; none of them happen by accident.

**Residual risk:** the pin is a file beside the MCP's own private key, so a local process that can write there can delete it and force a fresh first contact — the same boundary the identity key itself has, and not something a file store can close. What the pin closes is the case where the attacker is *not* on this machine and cannot touch that file. Trust-on-first-use also assumes the first contact is yours; on loopback that is near-certain, on a network endpoint it is an assumption worth naming.

**A malformed-but-legitimate response degrades gracefully, not fatally.** A peer's incoming `frame` can fail to open in two very different ways, and the code distinguishes them (`openEncryptedFrameDetailed` in `packages/protocol/src/seal.ts`):

- **Decrypt failure** (AES-GCM authentication fails) — the wrong session key or genuinely tampered ciphertext. Nothing about the plaintext can be trusted; `peer.ts` drops it silently, same as before (typically a straggler frame from a session that already rotated).
- **Validation failure** *after a successful decrypt* — the ciphertext authenticated fine under the *current* session key (so this really is the live host forwarding the live extension's bytes), but the plaintext is malformed JSON or fails the wire schema. This is a genuine protocol bug, not a stale-key symptom, so `peer.ts` logs it loudly (`console.error`) and, when the malformed response's `id` is recoverable, routes a synthetic `ok:false` through the normal id-keyed dispatch — failing just that one pending call immediately instead of leaving it to hang until its own timeout with zero diagnostic signal, and without tearing down the connection over one bad response.

`host.ts` — the concentrator's single physical connection to the extension, multiplexing every MCP's traffic — still closes the whole WS on ANY validation failure (its message handler wraps everything in one try/catch; see `host.ts:344-351`). That remains a broader-blast-radius reaction than the peer path now has, but the concrete triggers found for it in this PR (the graphql errorPolicy bug, the download `bytes:-1` sentinel, the graphql_query op-echo gap) were each fixed at the SOURCE — the extension no longer produces a response that fails validation for those cases — rather than by changing what `host.ts` does when one does. A future op-specific bug could still trip the same host.ts-side "close everything" behavior; this is a known, accepted broader risk, not one this PR closes generically.

### T-remote-bridge — A configured remote bridge target

**2.1.0+.** The extension can dial a configured `wss://` relay in addition to `ws://127.0.0.1:37149`. This exists so an MCP that has to run somewhere other than the user's laptop — a hosted one — can still issue its requests from inside the user's signed-in tab (chrischall/mcp-host#162). It is the one feature in fetchproxy that widens the [local trust boundary](#local-trust-boundary), so it is worth being exact about which parts move and which do not.

**What does not change, and is the reason this is tractable at all.** A relay is a concentrator, and a concentrator has never been able to read what it routes: every MCP derives its own AES-256-GCM session key with the extension from its own X25519 identity, and the relay sees `{mcpId, seq, iv, ciphertext}`. That is [§T-host-MITM](#t-host-mitm--host-mcp-reading-peer-traffic), already closed, and 2.0.0's ready signature over the ephemeral pub is what closes it against a relay that forwards genuine frames. Every MCP arriving over a remote link still pairs with a code the user confirms, still declares domains and capabilities the extension enforces, and still holds a session key the relay never has. **Hosting an MCP does not give the host the user's cookies, requests or responses.**

**What does change:**

- **which relay to trust is now a decision.** A remote target is a URL plus a credential the user pastes in. Point it at something hostile and the traffic still cannot be read — but the MCPs behind it are MCPs that hostile thing chose, and each of them can ask the browser to pair. Approving a bridge is therefore approving *what may ask*, which is why the popup says so next to the form;
- **the population that can reach this browser grows** from "processes on this machine under my account" to "whatever that relay carries";
- **pairing happens across a WAN**, where the pair code is doing more work than it did on loopback: on a laptop "this is my machine" carried most of the argument, and here it carries none of it.

**Defenses in this change:**

- **loopback is not configurable.** Remote targets are strictly additional; nothing in storage or in the popup can remove or repoint the local link. A misconfiguration cannot take the bridge that has always worked;
- **`wss://` is required** unless the host is loopback, so the hello, the `mcpId` and the pair-pending frame are not readable in transit. The inner frames were already sealed; the handshake around them was not;
- **the credential is its own field.** Credentials in the URL are refused, because a URL is the part that gets pasted into a chat window;
- **one `mcpId`, one bridge.** An `mcpId` is minted by the MCP, so it is not a name the extension can assume is unique across relays. It binds to the link its hello arrived on, a second link claiming a bound id is refused, and a frame arriving on the wrong link is dropped before it is decrypted. Otherwise a relay could claim an id it observed and have this browser answer for it;
- **per-link handshake.** Each link sends its own hello with its own nonce and signs its readies over that nonce, so a ready cannot be replayed onto another bridge;
- **teardown is per link.** A relay dropping takes its own sessions with it and leaves the loopback ones alone.

**One verb does not cross.** `download` saves a file on the machine running the browser and answers with that machine's path, on the assumption the MCP asking reads the same disk. Over a remote bridge neither half holds — the path names a file the MCP cannot open, and the request would have a remote MCP writing bytes into the user's Downloads folder, which is the only thing in this protocol that leaves something behind on the machine. It is refused on a remote link, before the URL is examined, with a reason the calling MCP can print.

**Residual risks, stated rather than implied:**

- **a relay can drop, delay or reorder** — denial of service, never disclosure. The same residual the concentrator has always had, for the same reason;
- **the MCP-side pin ([§T-fake-extension](#t-fake-extension--something-else-answering-as-the-browser)) is what makes a stolen relay credential survivable.** Without it, an attacker holding the credential pairs their own browser with the hosted MCPs and reads every request they make. It shipped in 1.12.0 and is a hard precondition for using this feature with anything hosted — not an improvement to it;
- **the extension's trust store is keyed by MCP identity, not by bridge.** An MCP identity the user already approved locally is auto-trusted if it appears over a relay. It cannot be impersonated (the session derives via ECDH against that identity's public key, so only the holder of the private key can read the traffic), but the trust decision is deliberately about *who the MCP is* and not *which pipe it arrived through*.

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
