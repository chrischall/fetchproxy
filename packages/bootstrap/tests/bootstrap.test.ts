import { describe, it, expect, afterEach } from 'vitest';
import {
  bootstrap,
  BootstrapDisabledError,
  type Session,
  type BootstrapServerFactory,
} from '../src/index.js';

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
  readCookies: { keys: string[]; domain?: string; subdomain?: string }[];
  readLocalStorage: { keys: string[]; domain?: string; subdomain?: string }[];
  readSessionStorage: { keys: string[]; domain?: string; subdomain?: string }[];
  captureRequestHeader: { host: string; path?: string; headerName: string }[];
  readIndexedDb: {
    database: string;
    store: string;
    keys: string[];
    domain?: string;
    subdomain?: string;
  }[];
  constructorOpts: unknown[];
}

function makeStubFactory(opts?: {
  cookies?: Record<string, string>;
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
  capturedHeaders?: Record<string, string>;
  indexedDb?: Record<string, Record<string, unknown>>;
  throwOn?:
    | 'listen'
    | 'readCookies'
    | 'readLocalStorage'
    | 'readSessionStorage'
    | 'captureRequestHeader'
    | 'readIndexedDb';
}): { factory: BootstrapServerFactory; calls: StubCalls } {
  const calls: StubCalls = {
    listen: 0,
    close: 0,
    readCookies: [],
    readLocalStorage: [],
    readSessionStorage: [],
    captureRequestHeader: [],
    readIndexedDb: [],
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
      readCookies: async (callOpts: { keys: string[]; domain?: string; subdomain?: string }) => {
        calls.readCookies.push({
          keys: [...callOpts.keys],
          ...(callOpts.domain !== undefined ? { domain: callOpts.domain } : {}),
          ...(callOpts.subdomain !== undefined ? { subdomain: callOpts.subdomain } : {}),
        });
        if (opts?.throwOn === 'readCookies') throw new Error('readCookies failed');
        // Stub returns the joined cookies form; bootstrap parses it.
        const c = opts?.cookies ?? {};
        return Object.entries(c)
          .map(([k, v]) => `${k}=${v}`)
          .join('; ');
      },
      readLocalStorage: async (callOpts: {
        keys: string[];
        domain?: string;
        subdomain?: string;
      }) => {
        calls.readLocalStorage.push({
          keys: [...callOpts.keys],
          ...(callOpts.domain !== undefined ? { domain: callOpts.domain } : {}),
          ...(callOpts.subdomain !== undefined ? { subdomain: callOpts.subdomain } : {}),
        });
        if (opts?.throwOn === 'readLocalStorage') throw new Error('readLocalStorage failed');
        return { ...(opts?.localStorage ?? {}) };
      },
      readSessionStorage: async (callOpts: {
        keys: string[];
        domain?: string;
        subdomain?: string;
      }) => {
        calls.readSessionStorage.push({
          keys: [...callOpts.keys],
          ...(callOpts.domain !== undefined ? { domain: callOpts.domain } : {}),
          ...(callOpts.subdomain !== undefined ? { subdomain: callOpts.subdomain } : {}),
        });
        if (opts?.throwOn === 'readSessionStorage') throw new Error('readSessionStorage failed');
        return { ...(opts?.sessionStorage ?? {}) };
      },
      captureRequestHeader: async (callOpts: { host: string; path?: string; headerName: string }) => {
        calls.captureRequestHeader.push({
          host: callOpts.host,
          ...(callOpts.path !== undefined ? { path: callOpts.path } : {}),
          headerName: callOpts.headerName,
        });
        if (opts?.throwOn === 'captureRequestHeader') throw new Error('captureRequestHeader failed');
        return opts?.capturedHeaders?.[callOpts.headerName] ?? '';
      },
      readIndexedDb: async (callOpts: {
        database: string;
        store: string;
        keys: string[];
        domain?: string;
        subdomain?: string;
      }) => {
        calls.readIndexedDb.push({
          database: callOpts.database,
          store: callOpts.store,
          keys: [...callOpts.keys],
          ...(callOpts.domain !== undefined ? { domain: callOpts.domain } : {}),
          ...(callOpts.subdomain !== undefined ? { subdomain: callOpts.subdomain } : {}),
        });
        if (opts?.throwOn === 'readIndexedDb') throw new Error('readIndexedDb failed');
        const key = `${callOpts.database}/${callOpts.store}`;
        return { ...(opts?.indexedDb?.[key] ?? {}) };
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
      indexedDb: {},
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
          { host: 'api.honeybook.com', path: '/api/v2/*', headerName: 'hb-api-fingerprint' },
          { host: 'api.honeybook.com', path: '/api/v3/*', headerName: 'x-csrf' },
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
          { host: 'api.honeybook.com', path: '/api/v2/*', headerName: 'hb-api-fingerprint' },
        ],
      },
      _serverFactory: factory,
    });
    const ctorOpts = calls.constructorOpts[0] as Record<string, unknown>;
    expect(ctorOpts.cookieKeys).toEqual(['hb_user_token']);
    expect(ctorOpts.localStorageKeys).toEqual(['jStorage']);
    expect(ctorOpts.sessionStorageKeys).toEqual([]);
    expect(ctorOpts.captureHeaders).toEqual([
      { host: 'api.honeybook.com', path: '/api/v2/*', headerName: 'hb-api-fingerprint' },
    ]);
    expect(ctorOpts.capabilities).toEqual(
      expect.arrayContaining(['fetch', 'read_cookies', 'read_local_storage', 'capture_request_header']),
    );
  });

  describe('0.4.0 ergonomics', () => {
    afterEach(() => {
      // Tests below mutate process.env — clean up so siblings see a clean slate.
      delete process.env['OPENTABLE_MCP_DISABLE_FETCHPROXY'];
      delete process.env['SCOPE_HONEYBOOK_MCP_DISABLE_FETCHPROXY'];
    });

    it('throws BootstrapDisabledError when the env-var is set', async () => {
      process.env['OPENTABLE_MCP_DISABLE_FETCHPROXY'] = '1';
      const { factory } = makeStubFactory();
      await expect(
        bootstrap({
          serverName: 'opentable-mcp',
          version: '0.9.1',
          domains: ['opentable.com'],
          declare: { cookies: [], localStorage: [], sessionStorage: [], captureHeaders: [] },
          _serverFactory: factory,
        }),
      ).rejects.toBeInstanceOf(BootstrapDisabledError);
    });

    it('resolves env-var name from a scoped serverName', async () => {
      process.env['SCOPE_HONEYBOOK_MCP_DISABLE_FETCHPROXY'] = '1';
      const { factory } = makeStubFactory();
      await expect(
        bootstrap({
          serverName: '@scope/honeybook-mcp',
          version: '0.1.0',
          domains: ['honeybook.com'],
          declare: { cookies: [], localStorage: [], sessionStorage: [], captureHeaders: [] },
          _serverFactory: factory,
        }),
      ).rejects.toBeInstanceOf(BootstrapDisabledError);
    });

    it('does not throw when env-var is unset or empty', async () => {
      const { factory } = makeStubFactory();
      // unset
      await expect(
        bootstrap({
          serverName: 'opentable-mcp',
          version: '0.9.1',
          domains: ['opentable.com'],
          declare: { cookies: [], localStorage: [], sessionStorage: [], captureHeaders: [] },
          _serverFactory: factory,
        }),
      ).resolves.toBeDefined();
      // explicitly '0' or 'false' is treated as unset
      process.env['OPENTABLE_MCP_DISABLE_FETCHPROXY'] = '0';
      await expect(
        bootstrap({
          serverName: 'opentable-mcp',
          version: '0.9.1',
          domains: ['opentable.com'],
          declare: { cookies: [], localStorage: [], sessionStorage: [], captureHeaders: [] },
          _serverFactory: factory,
        }),
      ).resolves.toBeDefined();
    });

    it('threads onPairCode through to the FetchproxyServer constructor', async () => {
      const { factory, calls } = makeStubFactory();
      const onPairCode = (): void => undefined;
      await bootstrap({
        serverName: 'opentable-mcp',
        version: '0.9.1',
        domains: ['opentable.com'],
        declare: { cookies: [], localStorage: [], sessionStorage: [], captureHeaders: [] },
        onPairCode,
        _serverFactory: factory,
      });
      const ctorOpts = calls.constructorOpts[0] as Record<string, unknown>;
      expect(ctorOpts.onPairCode).toBe(onPairCode);
    });

    it('fires onWaiting once per declared captureHeader', async () => {
      const hints: string[] = [];
      const { factory } = makeStubFactory({
        capturedHeaders: { 'hb-api-fingerprint': 'fp', 'x-csrf': 'csrf' },
      });
      await bootstrap({
        serverName: 'honeybook-mcp',
        version: '0.1.0',
        domains: ['honeybook.com'],
        declare: {
          cookies: [],
          localStorage: [],
          sessionStorage: [],
          captureHeaders: [
            { host: 'api.honeybook.com', path: '/api/v2/*', headerName: 'hb-api-fingerprint' },
            { host: 'api.honeybook.com', path: '/api/v3/*', headerName: 'x-csrf' },
          ],
        },
        onWaiting: (h) => hints.push(h),
        _serverFactory: factory,
      });
      expect(hints).toHaveLength(2);
      expect(hints[0]).toContain('api.honeybook.com');
      expect(hints[0]).toContain('hb-api-fingerprint');
      expect(hints[1]).toContain('x-csrf');
    });

    it('snapshots declared IndexedDB scopes into session.indexedDb', async () => {
      const { factory, calls } = makeStubFactory({
        indexedDb: {
          'resy/auth': { userToken: 'ey...', userId: 'u-1' },
        },
      });
      const session = await bootstrap({
        serverName: 'resy-mcp',
        version: '0.0.1',
        domains: ['resy.com'],
        declare: {
          cookies: [],
          localStorage: [],
          sessionStorage: [],
          captureHeaders: [],
          indexedDb: [
            {
              origin: 'https://resy.com',
              database: 'resy',
              store: 'auth',
              keys: ['userToken', 'userId'],
            },
          ],
        },
        _serverFactory: factory,
      });
      expect(session.indexedDb['resy/auth']).toEqual({ userToken: 'ey...', userId: 'u-1' });
      expect(calls.readIndexedDb).toEqual([
        { database: 'resy', store: 'auth', keys: ['userToken', 'userId'] },
      ]);
      // Capability + scope decl threaded through to the server ctor.
      const ctorOpts = calls.constructorOpts[0] as Record<string, unknown>;
      expect((ctorOpts.capabilities as string[]).sort()).toContain('read_indexed_db');
      expect(ctorOpts.indexedDbScopes).toEqual([
        { origin: 'https://resy.com', database: 'resy', store: 'auth', keys: ['userToken', 'userId'] },
      ]);
    });

    it('returns empty indexedDb when no IDB scopes are declared', async () => {
      const { factory } = makeStubFactory();
      const session = await bootstrap({
        serverName: 'opentable-mcp',
        version: '0.9.1',
        domains: ['opentable.com'],
        declare: { cookies: [], localStorage: [], sessionStorage: [], captureHeaders: [] },
        _serverFactory: factory,
      });
      expect(session.indexedDb).toEqual({});
    });
  });

  // 0.4.1: multi-domain MCPs must tell bootstrap which declared domain
  // the cookie / storage / IDB reads target. Without this, the server
  // throws "this MCP declared multiple domains [...] — pass { domain }".
  describe('storageDomain selector', () => {
    it('threads storageDomain to readCookies / readLocalStorage / readSessionStorage / readIndexedDb', async () => {
      const { factory, calls } = makeStubFactory({
        cookies: { sid: 'abc' },
        localStorage: { token: 'tok' },
        sessionStorage: { x: 'y' },
        capturedHeaders: { 'hb-api-fingerprint': 'fp' },
        indexedDb: { 'db/store': { k: 'v' } },
      });
      await bootstrap({
        serverName: 'honeybook-mcp',
        version: '0.1.13',
        domains: ['honeybook.com', 'hbportal.co'],
        storageDomain: 'hbportal.co',
        declare: {
          cookies: ['sid'],
          localStorage: ['token'],
          sessionStorage: ['x'],
          captureHeaders: [
            { host: 'api.honeybook.com', path: '/api/v2/*', headerName: 'hb-api-fingerprint' },
          ],
          indexedDb: [{ origin: 'https://hbportal.co', database: 'db', store: 'store', keys: ['k'] }],
        },
        _serverFactory: factory,
      });
      expect(calls.readCookies).toEqual([{ keys: ['sid'], domain: 'hbportal.co' }]);
      expect(calls.readLocalStorage).toEqual([{ keys: ['token'], domain: 'hbportal.co' }]);
      expect(calls.readSessionStorage).toEqual([{ keys: ['x'], domain: 'hbportal.co' }]);
      expect(calls.readIndexedDb).toEqual([
        { database: 'db', store: 'store', keys: ['k'], domain: 'hbportal.co' },
      ]);
      // captureRequestHeader carries its own host/path — no domain field.
      expect(calls.captureRequestHeader).toEqual([
        { host: 'api.honeybook.com', path: '/api/v2/*', headerName: 'hb-api-fingerprint' },
      ]);
    });

    it('threads storageSubdomain alongside storageDomain', async () => {
      const { factory, calls } = makeStubFactory({ localStorage: {} });
      await bootstrap({
        serverName: 'example-mcp',
        version: '0.0.1',
        domains: ['example.com'],
        storageDomain: 'example.com',
        storageSubdomain: 'app',
        declare: {
          cookies: [],
          localStorage: ['k'],
          sessionStorage: [],
          captureHeaders: [],
        },
        _serverFactory: factory,
      });
      expect(calls.readLocalStorage).toEqual([
        { keys: ['k'], domain: 'example.com', subdomain: 'app' },
      ]);
    });

    it('omits domain/subdomain when storageDomain is unset (single-domain MCPs)', async () => {
      const { factory, calls } = makeStubFactory({ localStorage: { k: 'v' } });
      await bootstrap({
        serverName: 'opentable-mcp',
        version: '0.9.1',
        domains: ['opentable.com'],
        declare: {
          cookies: [],
          localStorage: ['k'],
          sessionStorage: [],
          captureHeaders: [],
        },
        _serverFactory: factory,
      });
      // No domain key on the call — server uses the only declared domain.
      expect(calls.readLocalStorage).toEqual([{ keys: ['k'] }]);
    });
  });
});
