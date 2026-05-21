import { describe, it, expect } from 'vitest';
import { bootstrap, type Session, type BootstrapServerFactory } from '../src/index.js';

/**
 * Minimal stub of `FetchproxyServer` that satisfies the surface `bootstrap`
 * actually calls — `listen`, `close`, `readCookies`, `readLocalStorage`,
 * `readSessionStorage`, `captureRequestHeader`. The factory pattern keeps
 * the bootstrap tests pure (no real WS, no real identity files) while still
 * exercising the orchestration logic.
 */
interface StubCalls {
  listen: number;
  close: number;
  readCookies: { keys: string[] }[];
  readLocalStorage: { keys: string[] }[];
  readSessionStorage: { keys: string[] }[];
  captureRequestHeader: { urlPattern: string; headerName: string }[];
  constructorOpts: unknown[];
}

function makeStubFactory(opts?: {
  cookies?: Record<string, string>;
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
  capturedHeaders?: Record<string, string>;
  throwOn?: 'listen' | 'readCookies' | 'readLocalStorage' | 'readSessionStorage' | 'captureRequestHeader';
}): { factory: BootstrapServerFactory; calls: StubCalls } {
  const calls: StubCalls = {
    listen: 0,
    close: 0,
    readCookies: [],
    readLocalStorage: [],
    readSessionStorage: [],
    captureRequestHeader: [],
    constructorOpts: [],
  };
  const factory: BootstrapServerFactory = (ctorOpts) => {
    calls.constructorOpts.push(ctorOpts);
    return {
      listen: async () => {
        calls.listen++;
        if (opts?.throwOn === 'listen') throw new Error('listen failed');
      },
      close: async () => {
        calls.close++;
      },
      readCookies: async (callOpts: { keys: string[] }) => {
        calls.readCookies.push({ keys: [...callOpts.keys] });
        if (opts?.throwOn === 'readCookies') throw new Error('readCookies failed');
        // Stub returns the joined cookies form; bootstrap parses it.
        const c = opts?.cookies ?? {};
        return Object.entries(c)
          .map(([k, v]) => `${k}=${v}`)
          .join('; ');
      },
      readLocalStorage: async (callOpts: { keys: string[] }) => {
        calls.readLocalStorage.push({ keys: [...callOpts.keys] });
        if (opts?.throwOn === 'readLocalStorage') throw new Error('readLocalStorage failed');
        return { ...(opts?.localStorage ?? {}) };
      },
      readSessionStorage: async (callOpts: { keys: string[] }) => {
        calls.readSessionStorage.push({ keys: [...callOpts.keys] });
        if (opts?.throwOn === 'readSessionStorage') throw new Error('readSessionStorage failed');
        return { ...(opts?.sessionStorage ?? {}) };
      },
      captureRequestHeader: async (callOpts: { urlPattern: string; headerName: string }) => {
        calls.captureRequestHeader.push({
          urlPattern: callOpts.urlPattern,
          headerName: callOpts.headerName,
        });
        if (opts?.throwOn === 'captureRequestHeader') throw new Error('captureRequestHeader failed');
        return opts?.capturedHeaders?.[callOpts.headerName] ?? '';
      },
    };
  };
  return { factory, calls };
}

describe('bootstrap()', () => {
  it('returns empty buckets when no declarations are provided', async () => {
    const { factory, calls } = makeStubFactory();
    const session: Session = await bootstrap({
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      declare: { cookies: [], localStorage: [], sessionStorage: [], captureHeaders: [] },
      _serverFactory: factory,
    });
    expect(session).toEqual({
      cookies: {},
      localStorage: {},
      sessionStorage: {},
      capturedHeaders: {},
    });
    // Should still listen + close, and should not have called any read.
    expect(calls.listen).toBe(1);
    expect(calls.close).toBe(1);
    expect(calls.readCookies).toEqual([]);
    expect(calls.readLocalStorage).toEqual([]);
    expect(calls.readSessionStorage).toEqual([]);
    expect(calls.captureRequestHeader).toEqual([]);
  });

  it('reads cookies when declared, parses joined string into a map', async () => {
    const { factory } = makeStubFactory({
      cookies: { hb_user_token: 'ey...', hb_session: 'abc' },
    });
    const session = await bootstrap({
      serverName: 'honeybook-mcp',
      version: '0.1.0',
      domains: ['honeybook.com'],
      declare: {
        cookies: ['hb_user_token', 'hb_session'],
        localStorage: [],
        sessionStorage: [],
        captureHeaders: [],
      },
      _serverFactory: factory,
    });
    expect(session.cookies).toEqual({ hb_user_token: 'ey...', hb_session: 'abc' });
  });

  it('reads localStorage when declared', async () => {
    const { factory, calls } = makeStubFactory({
      localStorage: { auth: 'ey...', tokenExpiry: '1730000000000' },
    });
    const session = await bootstrap({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      declare: {
        cookies: [],
        localStorage: ['auth', 'tokenExpiry'],
        sessionStorage: [],
        captureHeaders: [],
      },
      _serverFactory: factory,
    });
    expect(session.localStorage).toEqual({ auth: 'ey...', tokenExpiry: '1730000000000' });
    expect(calls.readLocalStorage).toEqual([{ keys: ['auth', 'tokenExpiry'] }]);
  });

  it('reads sessionStorage when declared', async () => {
    const { factory } = makeStubFactory({ sessionStorage: { 'anon-id': 'abc' } });
    const session = await bootstrap({
      serverName: 'some-mcp',
      version: '0.0.1',
      domains: ['x.com'],
      declare: {
        cookies: [],
        localStorage: [],
        sessionStorage: ['anon-id'],
        captureHeaders: [],
      },
      _serverFactory: factory,
    });
    expect(session.sessionStorage).toEqual({ 'anon-id': 'abc' });
  });

  it('captures each declared header in turn, keyed by headerName', async () => {
    const { factory, calls } = makeStubFactory({
      capturedHeaders: {
        'hb-api-fingerprint': 'fp-abc123',
        'x-csrf': 'csrf-xyz',
      },
    });
    const session = await bootstrap({
      serverName: 'honeybook-mcp',
      version: '0.1.0',
      domains: ['honeybook.com'],
      declare: {
        cookies: [],
        localStorage: [],
        sessionStorage: [],
        captureHeaders: [
          { urlPattern: 'https://api.honeybook.com/api/v2/*', headerName: 'hb-api-fingerprint' },
          { urlPattern: 'https://api.honeybook.com/api/v3/*', headerName: 'x-csrf' },
        ],
      },
      _serverFactory: factory,
    });
    expect(session.capturedHeaders).toEqual({
      'hb-api-fingerprint': 'fp-abc123',
      'x-csrf': 'csrf-xyz',
    });
    expect(calls.captureRequestHeader.length).toBe(2);
  });

  it('derives the right capability set from non-empty buckets', async () => {
    const { factory, calls } = makeStubFactory();
    await bootstrap({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      declare: {
        cookies: [],
        localStorage: ['auth'],
        sessionStorage: [],
        captureHeaders: [],
      },
      _serverFactory: factory,
    });
    const ctorOpts = calls.constructorOpts[0] as {
      capabilities: string[];
      localStorageKeys: string[];
    };
    // Only the localStorage capability should be derived (plus fetch as base).
    expect(ctorOpts.capabilities.sort()).toEqual(['fetch', 'read_local_storage']);
    expect(ctorOpts.localStorageKeys).toEqual(['auth']);
  });

  it('always closes the underlying server even when one of the reads throws', async () => {
    const { factory, calls } = makeStubFactory({
      localStorage: { auth: 'ey...' },
      throwOn: 'readLocalStorage',
    });
    await expect(
      bootstrap({
        serverName: 'ofw-mcp',
        version: '0.5.0',
        domains: ['ourfamilywizard.com'],
        declare: {
          cookies: [],
          localStorage: ['auth'],
          sessionStorage: [],
          captureHeaders: [],
        },
        _serverFactory: factory,
      }),
    ).rejects.toThrow(/readLocalStorage failed/);
    expect(calls.close).toBe(1);
  });

  it('always closes the underlying server even when listen() throws', async () => {
    const { factory, calls } = makeStubFactory({ throwOn: 'listen' });
    await expect(
      bootstrap({
        serverName: 'x',
        version: '0.0.1',
        domains: ['x.com'],
        declare: { cookies: [], localStorage: [], sessionStorage: [], captureHeaders: [] },
        _serverFactory: factory,
      }),
    ).rejects.toThrow(/listen failed/);
    // close() still called once for cleanup.
    expect(calls.close).toBe(1);
  });

  it('threads all declarations through to FetchproxyServer constructor opts', async () => {
    const { factory, calls } = makeStubFactory();
    await bootstrap({
      serverName: 'honeybook-mcp',
      version: '0.1.0',
      domains: ['honeybook.com'],
      declare: {
        cookies: ['hb_user_token'],
        localStorage: ['jStorage'],
        sessionStorage: [],
        captureHeaders: [
          { urlPattern: 'https://api.honeybook.com/api/v2/*', headerName: 'hb-api-fingerprint' },
        ],
      },
      _serverFactory: factory,
    });
    const ctorOpts = calls.constructorOpts[0] as Record<string, unknown>;
    expect(ctorOpts.cookieKeys).toEqual(['hb_user_token']);
    expect(ctorOpts.localStorageKeys).toEqual(['jStorage']);
    expect(ctorOpts.sessionStorageKeys).toEqual([]);
    expect(ctorOpts.captureHeaders).toEqual([
      { urlPattern: 'https://api.honeybook.com/api/v2/*', headerName: 'hb-api-fingerprint' },
    ]);
    expect(ctorOpts.capabilities).toEqual(
      expect.arrayContaining(['fetch', 'read_cookies', 'read_local_storage', 'capture_request_header']),
    );
  });
});
