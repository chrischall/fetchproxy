// @fetchproxy/test-helpers
//
// Test utilities for vitest suites that mock `@fetchproxy/server`'s
// `FetchproxyServer`. The seven keep-alive cohort PRs
// (zillow#87 / redfin#77 / compass#72 / homes#49 / onehome#46 /
// opentable#57 / resy#38) each re-implemented the same module-scoped
// `ctorCalls` array + ad-hoc `MockFetchproxyServer` class to verify
// that `FetchproxyTransport` was forwarding constructor options
// (notably `keepAliveIntervalMs`) to the underlying server. This
// package hoists that pattern once.
//
// USAGE
// -----
//   import { createMockFetchproxyServer } from '@fetchproxy/test-helpers';
//
//   const helpers = createMockFetchproxyServer();
//   vi.mock('@fetchproxy/server', async () => {
//     return { FetchproxyServer: helpers.MockServer };
//   });
//   beforeEach(() => helpers.reset());
//
//   it('passes keepAliveIntervalMs through', () => {
//     new FetchproxyTransport({ version: '0' });
//     expect(helpers.getLastCtorOpts()?.keepAliveIntervalMs).toBe(25_000);
//   });

import { vi, type Mock } from 'vitest';
import type { FetchproxyServerOpts } from '@fetchproxy/server';

/**
 * A pared-down vitest spy surface that mirrors the methods
 * downstream MCPs typically call on `FetchproxyServer`. Defaults are
 * no-op stubs (`listen()` / `close()` resolve to `undefined`); tests
 * override per case via `inst.request.mockResolvedValue(...)` etc.
 *
 * Each entry is `Mock` so consumers get the full vitest-mock
 * `.mockResolvedValue` / `.mockImplementation` / `.mock.calls`
 * surface without TS complaints.
 */
export interface MockFetchproxyServerInstance {
  listen: Mock<() => Promise<void>>;
  close: Mock<() => Promise<void>>;
  request: Mock<(...args: unknown[]) => Promise<unknown>>;
  fetch: Mock<(...args: unknown[]) => Promise<unknown>>;
  captureRequestHeader: Mock<(...args: unknown[]) => Promise<string>>;
  bridgeHealth: Mock<() => unknown>;
}

/**
 * The drop-in `FetchproxyServer` replacement. Constructed exactly like
 * the real server (`new MockServer(opts)`) — the opts are pushed onto
 * the helper's `ctorCalls` array. Each instance carries its own
 * `vi.fn()`-backed spy methods.
 *
 * Typed as a class constructor so `vi.mock('@fetchproxy/server', ...)`
 * returns can advertise the same `FetchproxyServer` shape.
 */
export interface MockFetchproxyServerCtor {
  new (opts: FetchproxyServerOpts): MockFetchproxyServerInstance;
}

export interface MockFetchproxyServerHelpers {
  /**
   * The drop-in class. Use inside `vi.mock('@fetchproxy/server', ...)`:
   *   `return { FetchproxyServer: helpers.MockServer };`
   */
  MockServer: MockFetchproxyServerCtor;
  /**
   * Live, append-only array of every `new MockServer(...)` call's
   * options. Referentially stable across `reset()` (the array is
   * mutated, not replaced) so suites that destructure once at module
   * scope keep working.
   */
  ctorCalls: FetchproxyServerOpts[];
  /**
   * Convenience for the single-instance test case — returns the most
   * recent `FetchproxyServerOpts`, or `undefined` if `MockServer` has
   * not been constructed since the last `reset()`.
   */
  getLastCtorOpts: () => FetchproxyServerOpts | undefined;
  /**
   * Clears `ctorCalls` in place AND resets every previously-created
   * instance's spy call history. Call from `beforeEach` for per-test
   * isolation.
   */
  reset: () => void;
}

/**
 * Build a fresh mock surface. Each call returns an independent
 * `MockServer` class + `ctorCalls` array — handy if a single test
 * file mocks two different consumers separately, though the typical
 * pattern is one call per test file.
 */
export function createMockFetchproxyServer(): MockFetchproxyServerHelpers {
  const ctorCalls: FetchproxyServerOpts[] = [];
  const instances: MockFetchproxyServerInstance[] = [];

  class MockServer implements MockFetchproxyServerInstance {
    listen: Mock<() => Promise<void>>;
    close: Mock<() => Promise<void>>;
    request: Mock<(...args: unknown[]) => Promise<unknown>>;
    fetch: Mock<(...args: unknown[]) => Promise<unknown>>;
    captureRequestHeader: Mock<(...args: unknown[]) => Promise<string>>;
    bridgeHealth: Mock<() => unknown>;

    constructor(opts: FetchproxyServerOpts) {
      ctorCalls.push(opts);
      // No-op stubs for the lifecycle pair so default `await
      // transport.start()` / `await transport.close()` paths don't
      // hang or throw. The data verbs default to undefined-returning
      // stubs — tests typically override them per case via
      // `mockResolvedValue` / `mockImplementation`.
      this.listen = vi.fn(async () => undefined);
      this.close = vi.fn(async () => undefined);
      this.request = vi.fn(async () => undefined);
      this.fetch = vi.fn(async () => undefined);
      this.captureRequestHeader = vi.fn(async () => '');
      this.bridgeHealth = vi.fn(() => undefined);
      instances.push(this);
    }
  }

  function reset(): void {
    // Mutate-in-place so any reference closed over at module scope
    // stays valid. (Reassigning `ctorCalls = []` would orphan such
    // references.)
    ctorCalls.length = 0;
    for (const inst of instances) {
      inst.listen.mockClear();
      inst.close.mockClear();
      inst.request.mockClear();
      inst.fetch.mockClear();
      inst.captureRequestHeader.mockClear();
      inst.bridgeHealth.mockClear();
    }
  }

  function getLastCtorOpts(): FetchproxyServerOpts | undefined {
    return ctorCalls[ctorCalls.length - 1];
  }

  return {
    MockServer: MockServer as unknown as MockFetchproxyServerCtor,
    ctorCalls,
    getLastCtorOpts,
    reset,
  };
}
