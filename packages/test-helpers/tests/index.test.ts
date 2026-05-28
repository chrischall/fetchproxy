// Dogfood tests for @fetchproxy/test-helpers. These cover the shape
// every downstream cohort MCP (zillow / redfin / compass / homes /
// onehome / opentable / resy) re-implemented by hand before this
// package existed.
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createMockFetchproxyServer } from '../src/index.js';

describe('createMockFetchproxyServer', () => {
  describe('constructor capture', () => {
    it('captures the FIRST constructor call into ctorCalls + getLastCtorOpts', () => {
      const helpers = createMockFetchproxyServer();
      const { MockServer, ctorCalls, getLastCtorOpts } = helpers;

      new MockServer({
        serverName: 'example-mcp',
        version: '0.0.0-test',
        domains: ['example.com'],
      });

      expect(ctorCalls).toHaveLength(1);
      expect(ctorCalls[0]?.serverName).toBe('example-mcp');
      expect(getLastCtorOpts()?.serverName).toBe('example-mcp');
      expect(getLastCtorOpts()?.domains).toEqual(['example.com']);
    });

    it('captures MULTIPLE constructor calls in order (getLastCtorOpts returns the most recent)', () => {
      const { MockServer, ctorCalls, getLastCtorOpts } = createMockFetchproxyServer();

      new MockServer({
        serverName: 'first',
        version: '0.0.0',
        domains: ['a.com'],
      });
      new MockServer({
        serverName: 'second',
        version: '0.0.0',
        domains: ['b.com'],
        keepAliveIntervalMs: 25_000,
      });

      expect(ctorCalls).toHaveLength(2);
      expect(ctorCalls[0]?.serverName).toBe('first');
      expect(ctorCalls[1]?.serverName).toBe('second');
      expect(getLastCtorOpts()?.keepAliveIntervalMs).toBe(25_000);
    });

    it('getLastCtorOpts returns undefined before any construction', () => {
      const { getLastCtorOpts } = createMockFetchproxyServer();
      expect(getLastCtorOpts()).toBeUndefined();
    });

    it('captures the keep-alive cohort opts (keepAliveIntervalMs, bridgeReviveDelayMs, fetchTimeoutMs)', () => {
      // This is the exact shape the seven cohort PRs were validating.
      const { MockServer, getLastCtorOpts } = createMockFetchproxyServer();

      new MockServer({
        serverName: 'cohort-mcp',
        version: '0.0.0',
        domains: ['cohort.com'],
        keepAliveIntervalMs: 25_000,
        bridgeReviveDelayMs: 2_000,
        fetchTimeoutMs: 30_000,
      });

      const opts = getLastCtorOpts();
      expect(opts?.keepAliveIntervalMs).toBe(25_000);
      expect(opts?.bridgeReviveDelayMs).toBe(2_000);
      expect(opts?.fetchTimeoutMs).toBe(30_000);
    });
  });

  describe('reset()', () => {
    it('clears ctorCalls and reverts the instance spies', () => {
      const { MockServer, ctorCalls, reset } = createMockFetchproxyServer();

      const inst = new MockServer({
        serverName: 's',
        version: '0',
        domains: ['x.com'],
      });
      // Drive each spy once.
      void inst.listen();
      void inst.close();
      void inst.request({ url: 'https://x.com/', method: 'GET' });
      void inst.fetch({ url: 'https://x.com/', method: 'GET' });
      void inst.captureRequestHeader();
      void inst.bridgeHealth();

      expect(ctorCalls).toHaveLength(1);
      expect(inst.listen).toHaveBeenCalledTimes(1);
      expect(inst.close).toHaveBeenCalledTimes(1);
      expect(inst.request).toHaveBeenCalledTimes(1);
      expect(inst.fetch).toHaveBeenCalledTimes(1);
      expect(inst.captureRequestHeader).toHaveBeenCalledTimes(1);
      expect(inst.bridgeHealth).toHaveBeenCalledTimes(1);

      reset();

      expect(ctorCalls).toHaveLength(0);
      // Existing instance spy call counts are reset too.
      expect(inst.listen).toHaveBeenCalledTimes(0);
      expect(inst.request).toHaveBeenCalledTimes(0);
    });

    it('keeps `ctorCalls` referentially stable across reset() (test files often hold a closed-over reference)', () => {
      const { MockServer, ctorCalls, reset } = createMockFetchproxyServer();
      const sameArrayRef = ctorCalls;

      new MockServer({ serverName: 'a', version: '0', domains: ['x.com'] });
      reset();
      new MockServer({ serverName: 'b', version: '0', domains: ['x.com'] });

      expect(ctorCalls).toBe(sameArrayRef);
      expect(sameArrayRef).toHaveLength(1);
      expect(sameArrayRef[0]?.serverName).toBe('b');
    });
  });

  describe('instance spies', () => {
    it('exposes listen / close / request / fetch / captureRequestHeader / bridgeHealth as vi.fn() spies', () => {
      const { MockServer } = createMockFetchproxyServer();
      const inst = new MockServer({
        serverName: 's',
        version: '0',
        domains: ['x.com'],
      });

      // The vi.fn marker — calling .mockResolvedValue is only legal on vi.fn instances.
      expect(vi.isMockFunction(inst.listen)).toBe(true);
      expect(vi.isMockFunction(inst.close)).toBe(true);
      expect(vi.isMockFunction(inst.request)).toBe(true);
      expect(vi.isMockFunction(inst.fetch)).toBe(true);
      expect(vi.isMockFunction(inst.captureRequestHeader)).toBe(true);
      expect(vi.isMockFunction(inst.bridgeHealth)).toBe(true);
    });

    it('default listen() / close() resolve to undefined (no-op stubs)', async () => {
      const { MockServer } = createMockFetchproxyServer();
      const inst = new MockServer({
        serverName: 's',
        version: '0',
        domains: ['x.com'],
      });
      await expect(inst.listen()).resolves.toBeUndefined();
      await expect(inst.close()).resolves.toBeUndefined();
    });

    it('allows overriding spy behavior per-test (mockResolvedValue / mockImplementation)', async () => {
      const { MockServer } = createMockFetchproxyServer();
      const inst = new MockServer({
        serverName: 's',
        version: '0',
        domains: ['x.com'],
      });

      inst.captureRequestHeader.mockResolvedValue('Bearer test-token');
      inst.request.mockResolvedValue({
        ok: true,
        status: 200,
        body: 'hi',
        url: 'https://x.com/',
      });

      await expect(inst.captureRequestHeader()).resolves.toBe('Bearer test-token');
      await expect(inst.request({ url: 'https://x.com/', method: 'GET' })).resolves.toEqual({
        ok: true,
        status: 200,
        body: 'hi',
        url: 'https://x.com/',
      });
    });
  });

  describe('isolation across helper instances', () => {
    it('two separate createMockFetchproxyServer() calls get independent ctorCalls arrays', () => {
      const a = createMockFetchproxyServer();
      const b = createMockFetchproxyServer();

      new a.MockServer({ serverName: 'A', version: '0', domains: ['x.com'] });
      new b.MockServer({ serverName: 'B1', version: '0', domains: ['x.com'] });
      new b.MockServer({ serverName: 'B2', version: '0', domains: ['x.com'] });

      expect(a.ctorCalls).toHaveLength(1);
      expect(b.ctorCalls).toHaveLength(2);
      expect(a.ctorCalls[0]?.serverName).toBe('A');
      expect(b.getLastCtorOpts()?.serverName).toBe('B2');
    });
  });
});

describe('createMockFetchproxyServer — beforeEach(reset) pattern', () => {
  // The exact pattern downstream MCPs use: a module-scoped helper +
  // reset() in beforeEach so per-test ctor capture is clean.
  const helper = createMockFetchproxyServer();
  beforeEach(() => helper.reset());

  it('first test sees only its own constructor call', () => {
    new helper.MockServer({
      serverName: 'isolated-1',
      version: '0',
      domains: ['x.com'],
    });
    expect(helper.ctorCalls).toHaveLength(1);
    expect(helper.getLastCtorOpts()?.serverName).toBe('isolated-1');
  });

  it('second test also sees only its own constructor call (reset cleared the first)', () => {
    new helper.MockServer({
      serverName: 'isolated-2',
      version: '0',
      domains: ['x.com'],
    });
    expect(helper.ctorCalls).toHaveLength(1);
    expect(helper.getLastCtorOpts()?.serverName).toBe('isolated-2');
  });
});
