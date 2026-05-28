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

## API

### `new FetchproxyServer(opts)`

| Option | Type | Required | Notes |
|---|---|:-:|---|
| `serverName` | `string` | yes | Stable identifier. Used in `mcpId`, identity-key filename, and the pair popup. |
| `version` | `string` | yes | Your MCP's package version. Surfaced in the pair popup. |
| `domains` | `string[]` | yes | Non-empty array of hostnames. The extension refuses any fetch outside this set or its subdomains. |
| `capabilities` | `('fetch' \| 'read_cookies')[]` | no | Defaults to `['fetch']`. Add `'read_cookies'` to enable `readCookies()`. Changing the set later forces the user to re-pair. |
| `port` | `number` | no | Defaults to `37149`. |
| `host` | `string` | no | Defaults to `'127.0.0.1'`. Never bind a public address — see the [security model](https://github.com/chrischall/fetchproxy/blob/main/docs/SECURITY.md). |
| `identityDir` | `string` | no | Override the identity-key storage directory. Defaults to `~/.fetchproxy/identity/`. |

#### Server options (timeout / keep-alive)

| Option | Type | Default | Notes |
|---|---|---|---|
| `fetchTimeoutMs` | `number` | `30_000` | Per-request timeout. Pass `0` to opt back into hang-forever. |
| `bridgeReviveDelayMs` | `number` | `2_000` | One-shot retry delay after `content_script_unreachable` (MV3 SW eviction). Pass `0` to disable the retry. |
| `keepAliveIntervalMs` | `number` | `25_000` | Server-side proactive keep-alive ping interval. **Flipped from `undefined` to `25_000` in 0.10.0** ([#72](https://github.com/chrischall/fetchproxy/issues/72)) — the round-3 #71 cohort wave showed every Pattern A consumer was opting into this value. Pass `0` to disable. |
| `keepAliveMaxIdleMs` | `number` | `5 * 60 * 1000` (300_000) | After this long without a successful fetch / capture / `markActive()` the keep-alive ping interval self-quiesces. |

`fp.bridgeHealth()` exposes a snapshot of the bridge's process-wide
freshness counters — downstream MCPs surface this through their
healthcheck tool. As of 0.10.0 ([#73](https://github.com/chrischall/fetchproxy/issues/73))
the return shape includes `keepAlive` and `swEviction` sub-objects
so consumers can verify the keep-alive is actually preventing
Chrome MV3 service-worker eviction:

```ts
const h = fp.bridgeHealth();
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
//   lastEvictionDetectedAt: number | null; // first content_script_unreachable
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

## License

MIT.
