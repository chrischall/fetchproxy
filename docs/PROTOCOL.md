# fetchproxy protocol

The wire format between the MCP server (WebSocket server) and the browser extension (WebSocket client). One data verb (`fetch`), four lifecycle frames (`hello`, `ready`, `ping`, `pong`).

JSON-over-WS, no binary frames, no fragmentation. Both directions speak the same frame schema.

## Connection lifecycle

```
Extension                                       MCP Server
   │                                                │
   │  WS connect ws://127.0.0.1:37149               │
   │ ──────────────────────────────────────────────▶│
   │                                                │
   │  { type: "hello", role: "extension",           │
   │    version: "1.0.0", platform: "chrome" }      │
   │ ──────────────────────────────────────────────▶│
   │                                                │
   │  { type: "hello", role: "server",              │
   │    server: "opentable-mcp", version: "0.9.1",  │
   │    domain: "opentable.com" }                   │
   │ ◀──────────────────────────────────────────────│
   │                                                │
   │  (extension verifies a tab matching `domain`   │
   │   exists; if not, doesn't send `ready`)        │
   │                                                │
   │  { type: "ready" }                             │
   │ ──────────────────────────────────────────────▶│
   │                                                │
   │  { type: "ping" }                              │
   │ ◀──────────────────────────────────────────────│
   │  { type: "pong" }                              │
   │ ──────────────────────────────────────────────▶│
   │           (...every 20s, both directions)      │
   │                                                │
   │  { type: "request", id: 1, op: "fetch",        │
   │    init: { url, method, headers, body,         │
   │            tabUrl } }                          │
   │ ◀──────────────────────────────────────────────│
   │                                                │
   │  (extension picks a tab matching tabUrl,       │
   │   runs window.fetch(url, init) in MAIN world)  │
   │                                                │
   │  { type: "response", id: 1, ok: true,          │
   │    status: 200, url: "https://...",            │
   │    body: "<html>..." }                         │
   │ ──────────────────────────────────────────────▶│
   │                                                │
```

**Only one extension is active at a time.** If a second extension instance connects, the server closes it with reason `"Another extension already connected"`. (Multi-extension simultaneously gets complicated fast and isn't a use case we need.)

## Frame types

All frames are JSON objects with a `type` field. Unknown frames are silently dropped.

### `hello`

Sent by both sides immediately after connection. Identifies the speaker so the other side can render meaningful status / errors.

**Extension → Server:**
```jsonc
{
  "type": "hello",
  "role": "extension",
  "version": "1.0.0",
  "platform": "chrome" | "safari" | "firefox",
  "extension_id": "fetchproxy"            // stable identifier; same across browsers
}
```

**Server → Extension:**
```jsonc
{
  "type": "hello",
  "role": "server",
  "server": "opentable-mcp",              // package name of the MCP server
  "version": "0.9.1",                     // MCP server version
  "domain": "opentable.com"               // primary domain the server targets; extension uses
                                          // this for popup status display + tab matching defaults
}
```

### `ready`

Extension → Server. Sent when the extension has at least one tab matching the server's `domain` (from `hello`). If no matching tab is open, `ready` is NOT sent — the server's `fetch()` calls hang up to a `connectTimeoutMs` deadline (default 15s) before throwing.

```jsonc
{ "type": "ready" }
```

### `ping` / `pong`

Either direction, every 20s. MV3 service workers die after ~30s idle on Chrome and faster on Safari; the ping keeps the connection (and thus the SW) warm. Extensions also schedule a `chrome.alarms` tick as a 25s backup for cold-wake recovery.

```jsonc
{ "type": "ping" }
{ "type": "pong" }
```

### `request`

Server → Extension. Each request has a server-generated integer `id` for response correlation.

```jsonc
{
  "type": "request",
  "id": 1,
  "op": "fetch",
  "init": {
    "url": "https://www.opentable.com/user/dining-dashboard",
    "method": "GET",                       // GET, POST, PUT, DELETE, PATCH
    "headers": {                           // optional; merged with browser defaults
      "Content-Type": "application/json",
      "X-CSRF-Token": "..."
    },
    "body": "{\"x\":1}",                   // optional; string only (server pre-serialises JSON)
    "tabUrl": "https://www.opentable.com/" // prefix-match against tab URLs; first match wins
  }
}
```

**`init` field semantics:**

- `url`: absolute URL. The extension does not rewrite or canonicalise.
- `method`: any HTTP verb the browser's `fetch` supports.
- `headers`: optional object. Merged with browser defaults; `Cookie`, `User-Agent`, `Origin`, `Referer` are controlled by the browser and ignored if set here. `credentials: 'include'` is always implied.
- `body`: optional string. Servers serialise JSON before sending; extension does not introspect.
- `tabUrl`: required. Prefix-matched against `chrome.tabs.query({})`. First matching tab is used. If no match, response is `{ ok: false, error: "no tab matching <tabUrl>" }`.

`op` is reserved for future expansion. v1 only accepts `"fetch"`. Unknown ops respond with `{ ok: false, error: "unknown op: <op>" }`.

### `response`

Extension → Server.

**Success:**
```jsonc
{
  "type": "response",
  "id": 1,
  "ok": true,
  "status": 200,                           // HTTP status code from the in-page fetch
  "url": "https://www.opentable.com/user/dining-dashboard",  // final URL after redirects
  "body": "<html>..."                      // response body as a string
}
```

**Failure:**
```jsonc
{
  "type": "response",
  "id": 1,
  "ok": false,
  "error": "no tab matching https://www.opentable.com/"
}
```

`ok: false` is reserved for *protocol-level* failures (no tab, content-script not injected, fetch threw a TypeError). HTTP-level errors (404, 500, 403) come back as `ok: true` with the relevant `status`. Servers are expected to map non-2xx to typed errors themselves.

## Timeouts + retries

- **Server-side**: `connectTimeoutMs` (default 15s) — wait for `ready` after a fresh extension connection. `requestTimeoutMs` (default 30s) — wait for a `response` to a given request id.
- **Extension-side**: no internal timeout on the in-page `fetch`. The page's own timeout governs.
- **Retries**: not in the protocol. If a `fetch` throws, the server gets an `ok: false` response and decides whether to retry. (For the OpenTable use case, slot tokens expire fast so retries usually aren't useful; better to re-call `find_slots` upstream.)

## Multi-MCP coordination

Multiple MCP servers on the same machine each run their own WS server on their own port. The extension's popup lets the user add server entries (port + label) which are persisted to `chrome.storage`. The extension connects to each in parallel; each connection is independent.

Example: a user has `opentable-mcp` on `:37149`, `resy-mcp` on `:37148`, `tock-mcp` on `:37147`. The extension popup shows three status rows, one per server.

There is no central registry, no mDNS, no port-scan. Configuration is explicit — the user adds servers, the extension trusts only those entries.

## Versioning

This document describes protocol version `1`. The `hello` frame doesn't carry a protocol version yet; we'll add one when the first breaking change ships, with a graceful-downgrade rule (older clients/servers ignore unknown fields and fall back to v1 behavior).

The MCP servers + extension are released together as part of the `fetchproxy` repo. Mixed-version scenarios (old extension, new server library) should keep working as long as the protocol fields the older side knows about are unchanged.
