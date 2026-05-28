# @fetchproxy/server

> Node library MCP servers depend on to relay HTTP through the user's signed-in browser via the [fetchproxy extension](https://github.com/chrischall/fetchproxy).

```
                 ┌────────────────────┐
   MCP request   │ FetchproxyServer   │  ws://127.0.0.1:37149   ┌─────────────┐
   ────────────▶ │  • host or peer    │ ──────────────────────▶ │ fetchproxy  │
                 │  • crypto + routing│                          │ extension   │
                 └────────────────────┘                          └──────┬──────┘
                                                                        │ fetch()
                                                                        ▼
                                                              signed-in tab
                                                              on declared domain
```

`FetchproxyServer` is the only export most callers need. Construct it with a server name, version, and a non-empty `domains` array; call `listen()` once at startup; then issue requests with the verb shortcuts (`get`, `post`, `getJson`, `postJson`, `getHtml`) or raw `fetch()`. Call `close()` on shutdown.

The library handles host/peer election automatically — the first MCP to call `listen()` binds the port and routes frames for everyone else. Identity keys live on disk at `~/.fetchproxy/identity/<serverName>.json` so trust survives restarts.

See the [top-level README](https://github.com/chrischall/fetchproxy#readme) for the full picture: extension install, architecture, threat model.

## Install

```sh
npm install @fetchproxy/server
```

The user also needs the fetchproxy browser extension installed. See the [top-level README](https://github.com/chrischall/fetchproxy#install) for instructions.

## Quickstart

```ts
import { FetchproxyServer } from '@fetchproxy/server';

const fp = new FetchproxyServer({
  serverName: 'opentable-mcp',
  version: '0.10.0',
  domains: ['opentable.com'],
});

await fp.listen();
// First run prints a pair code to stderr; the user approves it in the
// extension popup. Same identity → same code, every restart.

const html = await fp.getHtml('/user/dining-dashboard', { subdomain: 'www' });
// fetched from https://www.opentable.com/user/dining-dashboard
// through the signed-in opentable.com tab.

const data = await fp.postJson('/dapi/fe/gql', {
  operationName: 'Autocomplete',
  variables: { term: 'state of confusion' },
}, { subdomain: 'www' });

await fp.close();
```

## Server options

Every public field on `FetchproxyServerOpts` at a glance — defaults
plus a one-liner on what each option does. The same information is
mirrored as JSDoc on the type itself, so editors and hover help reach
parity with this table. For longer "when to override" guidance, see
[Choosing the right options](#choosing-the-right-options) below.

| Option | Type | Default | What it does |
|---|---|---|---|
| `serverName` | `string` | — (required) | Stable MCP identifier. Used in the pair popup, identity-key filename, and `mcpId`. |
| `version` | `string` | — (required) | Your MCP's package version. Surfaced in the pair popup. |
| `domains` | `string[]` | — (required) | Trust boundary. The extension refuses any fetch outside this set or its subdomains. |
| `capabilities` | `Capability[]` | `['fetch']` | Opt-in verb set. Add `'read_cookies'` / `'read_local_storage'` / `'capture_request_header'` / etc. Changing this forces a re-pair. |
| `port` | `number` | `37149` | Localhost concentrator port. Only override for local development or test isolation — production MCPs all need to share one port. |
| `host` | `string` | `'127.0.0.1'` | Loopback bind interface. Keep on loopback — the threat model assumes single-user trust. |
| `identityDir` | `string` | `~/.fetchproxy/identity/` | Where to store the long-term identity keypair. Override for tests or sandboxed deployments. |
| `onPairCode` | `(code: string) => void` | (off by default) | Invoked once with the joint pair code on extension hello, so an MCP can surface it via stderr / MCP logging. |
| `fetchTimeoutMs` | `number` | `30_000` | Per-request timeout for `fetch()`. `0` opts back into legacy hang-forever. ([#58](https://github.com/chrischall/fetchproxy/issues/58)) |
| `bridgeReviveDelayMs` | `number` | `2_000` | Delay before the one-shot retry after `content_script_unreachable`. Gives Chrome a moment to wake the evicted MV3 SW. `0` disables. ([#58](https://github.com/chrischall/fetchproxy/issues/58)) |
| `keepAliveIntervalMs` | `number` | `25_000` | Server-initiated ping cadence that keeps the MV3 SW resident across activity bursts. Comfortably under Chrome's ~30s eviction threshold. Pass `0` to disable. Default flipped from `undefined` in 0.10.0 ([#71](https://github.com/chrischall/fetchproxy/issues/71)). ([#67](https://github.com/chrischall/fetchproxy/issues/67)) |
| `keepAliveMaxIdleMs` | `number` | `300_000` (5 min) | How long after the most-recent activity the keep-alive pings keep firing. No-op when `keepAliveIntervalMs` is `0`. ([#67](https://github.com/chrischall/fetchproxy/issues/67)) |
| `cookieKeys` | `string[]` | `[]` | Declared cookie names for `readCookies({ keys })`. Gates the call site (gate #1) before the extension re-checks (gate #2). |
| `localStorageKeys` | `string[]` | `[]` | Declared localStorage keys for `readLocalStorage`. |
| `sessionStorageKeys` | `string[]` | `[]` | Declared sessionStorage keys for `readSessionStorage`. |
| `captureHeaders` | `CaptureHeaderDecl[]` | `[]` | Declared `(urlPattern, headerName)` pairs for `captureRequestHeader`. |
| `indexedDbScopes` | `IndexedDbScopeDecl[]` | `[]` | Declared IndexedDB `(origin, database, store, keys)` scopes for `readIndexedDb`. |
| `localStoragePointers` | `StoragePointerDecl[]` | `[]` | Declared `(key, jsonPointer)` extractions over localStorage. |
| `sessionStoragePointers` | `StoragePointerDecl[]` | `[]` | Same shape as `localStoragePointers`, against sessionStorage. |

### Choosing the right options

- **`fetchTimeoutMs`.** The default `30_000` matches what every realty
  / dining MCP was already wrapping. Tighten for latency-sensitive
  interactive tool calls; loosen for known-slow endpoints (large
  downloads, long-running search). Pass `0` to opt back into the
  legacy hang-forever behavior. On timeout, `fetch()` returns
  `{ ok: false, kind: 'timeout' }` and the convenience methods throw
  `FetchproxyTimeoutError`.
- **`bridgeReviveDelayMs`.** Chrome MV3 evicts extension service
  workers after ~30s idle. The default `2_000` ms is the same delay
  the zillow/onehome cohort had been hand-rolling in their transport
  adapters before the option existed. Lengthen on slow machines where
  2s isn't enough for the SW to wake; shorten if the caller is
  willing to surface the bridge-down error sooner. Pass `0` to
  disable the retry entirely.
- **`keepAliveIntervalMs`.** Default `25_000` since 0.10.0 (the
  round-3 #71 cohort showed every consumer was opting into the same
  value, so it was promoted to the default). Comfortably under
  Chrome's ~30s eviction threshold — keeps the MV3 SW resident
  across activity bursts (a user opens a search, thinks for 30s,
  runs another tool). Pass `0` to disable. Pairs with
  `keepAliveMaxIdleMs` (default 5 min) so the pings self-quiesce on
  idle processes.
- **`domains`.** Trust boundary, required. Use the apex hostname
  (`'opentable.com'`) and let the extension match subdomains
  automatically. Multi-domain MCPs (HoneyBook, Resy two-host setups)
  pass every declared domain on every per-call request via
  `{ domain: 'x.com' }`.
- **`port` / `host`.** The defaults are load-bearing — the browser
  extension's connect target is hard-coded to `127.0.0.1:37149`, so
  every MCP that wants to share the concentrator needs to keep the
  defaults. Override only for local development or test isolation.

## API

### `new FetchproxyServer(opts)`

See [Server options](#server-options) for the full table. Three
fields are required: `serverName`, `version`, `domains`. Everything
else has a default.

`fp.bridgeHealth()` exposes a snapshot of the bridge's process-wide
freshness counters — downstream MCPs surface this through their
healthcheck tool. As of 0.10.0 ([#73](https://github.com/chrischall/fetchproxy/issues/73))
the return shape includes `keepAlive` and `swEviction` sub-objects
so consumers can verify the keep-alive is actually preventing
Chrome MV3 service-worker eviction. As of 0.11.0 ([#82](https://github.com/chrischall/fetchproxy/issues/82))
the resolved `fetchTimeoutMs` and `bridgeReviveDelayMs` are also
top-level fields so cohort healthcheck tools can drop their local
`DEFAULT_FETCH_TIMEOUT_MS` / `DEFAULT_BRIDGE_REVIVE_DELAY_MS`
constants and read the resolved value directly:

```ts
const h = fp.bridgeHealth();
// h.fetchTimeoutMs: number;       // resolved (30_000 default, or override; 0 = disabled)
// h.bridgeReviveDelayMs: number;  // resolved (2_000 default, or override; 0 = disabled)
// h.keepAlive: {
//   enabled: boolean;          // true when intervalMs > 0
//   intervalMs: number;        // resolved (25_000 default)
//   maxIdleMs: number;         // resolved (300_000 default)
//   lastPingAt: number | null; // epoch ms; null until first tick
//   totalPings: number;        // monotonic across the process lifetime
//   idleSinceMs: number | null;// elapsed ms since lastActiveAt
// };
// h.swEviction: {
//   lazyReviveAttempts: number;
//   lazyReviveSuccesses: number;
//   lastEvictionDetectedAt: number | null; // latest content_script_unreachable (overwritten on each detection)
// };
```

### `await fp.listen(): Promise<void>`

Loads or creates the identity keypair, races the port, and stands up either a host (binds the port) or peer (dials the host) connection. Idempotent only in the sense that it leaves `role` populated on success; calling `listen()` twice without `close()` is a programming error.

### `fp.role: 'host' | 'peer' | null`

Set after `listen()` succeeds. Callers should NOT branch on this — behaviour is identical across roles — but it's exposed for testability and metrics.

### Verb shortcuts

All verb shortcuts accept the same per-call options:

```ts
interface BodylessRequestOpts {
  headers?: Record<string, string>;
  expectStatus?: number | number[]; // throws FetchproxyHttpError on mismatch
  subdomain?: string;               // prepended to the chosen base domain
  domain?: string;                  // required when multiple `domains` declared
}
```

| Method | Returns | Default `expectStatus` | Notes |
|---|---|---|---|
| `get(path, opts?)` | `HttpResponse` | none | Raw GET. Does not parse the body. |
| `post(path, body?, opts?)` | `HttpResponse` | none | Raw POST. `body` is a string; no `Content-Type` is set. |
| `put(path, body?, opts?)` | `HttpResponse` | none | |
| `patch(path, body?, opts?)` | `HttpResponse` | none | |
| `delete(path, opts?)` | `HttpResponse` | none | No body — the bridge doesn't support DELETE-with-body. |
| `getHtml(path, opts?)` | `string` | `[200, 201, 202, 204]` | GET + return body as string. |
| `getJson<T>(path, opts?)` | `T` | `[200, 201, 202, 204]` | GET + `JSON.parse(body)`. |
| `postJson<T>(path, body?, opts?)` | `T` | `[200, 201, 202, 204]` | `JSON.stringify`'s `body`, sets `Content-Type: application/json` unless the caller already set one, parses the response body as JSON. |

`HttpResponse`:

```ts
interface HttpResponse {
  status: number;
  body: string;
  url: string;   // final URL after redirects, as seen by the browser
}
```

#### Path resolution

- Absolute URL (`https://...`) — used as-is. Still guarded against leaving the declared domain set.
- Relative path — joined with `https://${subdomain}.${baseDomain}${path}` (or `https://${baseDomain}${path}` when no `subdomain`).
- Base domain — `domains[0]` when only one is declared; `opts.domain` is required and must exactly equal one of the declared entries when more than one is.

#### Error model

| Condition | Behaviour |
|---|---|
| Bridge failed (no tab, extension offline, transport error) | Throws `FetchproxyProtocolError`. |
| HTTP status outside `expectStatus` (when set) | Throws `FetchproxyHttpError` with the full `HttpResponse` attached. |
| Any successful HTTP exchange when no `expectStatus` is set | Resolves; the caller inspects `response.status` themselves. |
| Programmer error (bad subdomain, undeclared domain, missing capability) | Throws a plain `Error` synchronously at the call site. |

### `await fp.fetch(init): Promise<FetchResult | FetchResultError>`

The raw, single-shot escape hatch behind the verb shortcuts. Use it when you already have a `FetchInit` ready or need to fully control `tabUrl` independently of the request URL.

```ts
interface FetchInit {
  url: string;        // absolute; must be on a declared domain
  method: string;
  headers?: Record<string, string>;
  body?: string;
  tabUrl: string;     // prefix-matched against open tabs
}
```

`fetch()` returns a discriminated union — `{ ok: true, status, url, body }` on any successful upstream HTTP exchange (any 2xx/3xx/4xx/5xx — status alone does NOT turn this into `ok: false`), or `{ ok: false, error }` only when the bridge itself failed. It does NOT throw on non-2xx.

### `await fp.readCookies(opts?): Promise<string>`

```ts
const fp = new FetchproxyServer({
  serverName: 'creditkarma-mcp',
  version: '0.1.0',
  domains: ['creditkarma.com'],
  capabilities: ['fetch', 'read_cookies'], // must include 'read_cookies'
});

await fp.listen();
const cookies = await fp.readCookies({ subdomain: 'www' });
// "sid=...; csrf=...; ..."
```

`opts` accepts `{ domain?, subdomain? }` (same semantics as the verb shortcuts).

Returns the raw `document.cookie` string from a tab on the chosen host. Only non-HttpOnly cookies are visible to page JS — that's the intentional security model.

Throws synchronously if the MCP did not declare `'read_cookies'` in `capabilities` (this is a programming mistake, not a runtime condition). Throws `FetchproxyProtocolError` if the bridge could not deliver the request.

### `await fp.close(): Promise<void>`

Closes the WS / extension connection. Safe to call before `listen()` (no-op) and twice in a row.

### Errors

| Class | Origin |
|---|---|
| `FetchproxyProtocolError` | Bridge-side failure (no signed-in tab, extension offline, transport error, capability not granted at the extension layer). |
| `FetchproxyHttpError` | Upstream HTTP status was outside `expectStatus`. Carries the full `HttpResponse`. |

## Resilience helpers

Pure, I/O-free utilities for rate-limit / bot-wall resilience, hoisted
from the portal-MCP cohort so every consumer imports one shared
implementation. All are independent and tree-shakeable.

| Export | What it does |
|---|---|
| `classifyBotWall(body, status, headers?)` | Detects a bot-wall / CAPTCHA interstitial → `{ blocked: true, vendor } \| { blocked: false }`. Vendors: `perimeterx`, `aws_waf`, `cloudflare`, `datadome`, `unknown`. Body-keyed first (a PerimeterX wall can be HTTP 200), with status/headers as additional signal. Pairs with the `bot_challenge` `FetchErrorKind` — distinct from not-found / bridge-down / timeout. |
| `TokenBucket` | Per-host requests-per-minute governor. `new TokenBucket({ ratePerMinute, burst?, now? })`; `await bucket.acquire()` resolves when a token is free. Governs *total request volume*, complementing the concurrency cap. Inject `now` for deterministic tests. |
| `backoffDelayMs(attempt, { baseMs, capMs, rng?, retryAfterMs? })` | Exponential backoff (`baseMs * 2^attempt`, capped at `capMs`) with full jitter, floored at an optional `retryAfterMs` hint. Inject `rng` for deterministic schedules. |
| `withDeadline(promise, ms)` | Races a promise against a timer → `{ timedOut: false, value } \| { timedOut: true }`. Clears and `unref`s the timer; inner rejections propagate (not folded into a timeout). For bulk partial-results below the MCP request deadline. |

```ts
import {
  classifyBotWall,
  TokenBucket,
  backoffDelayMs,
  withDeadline,
} from '@fetchproxy/server';

const wall = classifyBotWall(res.body, res.status, res.headers);
if (wall.blocked) {
  // back off + retry rather than treating it as "not found"
  await new Promise((r) => setTimeout(r, backoffDelayMs(attempt, { baseMs: 500, capMs: 30_000 })));
}
```

## License

MIT.
