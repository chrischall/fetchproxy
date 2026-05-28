# @fetchproxy/test-helpers

Vitest mock utilities for `@fetchproxy/server`. Drop-in
`FetchproxyServer` replacement that captures constructor options and
exposes spy-able lifecycle + data methods — so you can assert what
your `FetchproxyTransport` adapter is passing to the underlying server
without spinning up a real WebSocket.

## Why

Every downstream `*-mcp` repo that wraps `@fetchproxy/server` ends up
re-implementing the same module-scoped `ctorCalls` array and ad-hoc
`MockFetchproxyServer` class to verify it's threading options
(`keepAliveIntervalMs`, `bridgeReviveDelayMs`, `fetchTimeoutMs`, …)
through to the constructor. The keep-alive cohort of 0.8.1 PRs
(zillow#87, redfin#77, compass#72, homes#49, onehome#46,
opentable#57, resy#38) all carried near-identical copies of the same
~25 lines. This package hoists it once.

## Install

```sh
npm install --save-dev @fetchproxy/test-helpers
```

`vitest` (>=1.0) and `@fetchproxy/server` are peer dependencies.

## Usage

```ts
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createMockFetchproxyServer } from '@fetchproxy/test-helpers';

// Module-scoped so vi.mock's hoisted factory can close over it.
const helpers = createMockFetchproxyServer();

vi.mock('@fetchproxy/server', async () => {
  return { FetchproxyServer: helpers.MockServer };
});

beforeEach(() => helpers.reset());

it('passes keepAliveIntervalMs through to FetchproxyServer', async () => {
  const { FetchproxyTransport } = await import('../src/transport-fetchproxy.js');
  new FetchproxyTransport({ version: '0.0.0-test' });

  expect(helpers.getLastCtorOpts()?.keepAliveIntervalMs).toBe(25_000);
});

it('captures the Authorization header on the right URL', async () => {
  const { FetchproxyTransport } = await import('../src/transport-fetchproxy.js');
  const t = new FetchproxyTransport({ version: '0.0.0-test' });

  // Override the default empty-string stub on a specific test.
  const opts = helpers.getLastCtorOpts();
  // ...assert captureHeaders, then exercise:
  // (the MockServer instance's captureRequestHeader spy is on the
  // instance the transport just created; reach it via your transport's
  // public seams or override the spy before the call.)
});
```

## API

### `createMockFetchproxyServer()`

Returns `{ MockServer, ctorCalls, getLastCtorOpts, reset }`:

| Field               | Type                                      | What it does                                                                                                                 |
| ------------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `MockServer`        | class                                     | Drop into the `vi.mock('@fetchproxy/server', ...)` factory as `FetchproxyServer`. Constructed with `new MockServer(opts)`.   |
| `ctorCalls`         | `FetchproxyServerOpts[]`                  | Live, append-only list of every `new MockServer(...)` call's opts. Referentially stable across `reset()` (mutated in place). |
| `getLastCtorOpts()` | `() => FetchproxyServerOpts \| undefined` | The most recent ctor opts; `undefined` when none.                                                                            |
| `reset()`           | `() => void`                              | Clears `ctorCalls` in place and `.mockClear()`s every previously-created instance's spy methods. Call from `beforeEach`.     |

### `MockFetchproxyServerInstance`

Each `new MockServer(opts)` instance has these `vi.fn()`-backed spies
(default stubs return `undefined` / empty string; tests override per
case via `mockResolvedValue` / `mockImplementation`):

- `listen()` / `close()` — lifecycle no-ops.
- `request()` / `fetch()` — data verbs.
- `captureRequestHeader()` — header-capture verb.
- `bridgeHealth()` — health snapshot.

## License

MIT.
