import { describe, it, expect, afterEach } from 'vitest';
import {
  bootstrap,
  createSessionLifter,
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
  readCookies: { keys: string[]; domain?: string; subdomain?: string; path?: string }[];
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
      readCookies: async (callOpts: {
        keys: string[];
        domain?: string;
        subdomain?: string;
        path?: string;
      }) => {
        calls.readCookies.push({
          keys: [...callOpts.keys],
          ...(callOpts.domain !== undefined ? { domain: callOpts.domain } : {}),
          ...(callOpts.subdomain !== undefined ? { subdomain: callOpts.subdomain } : {}),
          ...(callOpts.path !== undefined ? { path: callOpts.path } : {}),
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
      missing: { cookies: [], localStorage: [], sessionStorage: [] },
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

// ────────────────────────────────────────────────────────────────────────────
// Partial lifts must not look like clean successes
// ────────────────────────────────────────────────────────────────────────────
//
// Real incident (signupgenius-mcp): the MCP declared
// ['accessToken','cfid','cftoken'] and read at the APEX host, where only
// `accessToken` exists — `cfid`/`cftoken` live on `www`. bootstrap() returned
// a cookies map holding just `accessToken` and signalled nothing, so the MCP
// built a plausible-looking session that failed much later with an unrelated
// message ("You are no longer logged in"). Missing declared keys were simply
// absent from the map, and nothing pointed at the real cause. `missing` lets
// a caller fail loudly — "declared 3, got 1" — at the point of the lift.
describe('bootstrap — missing declared keys', () => {
  it('reports declared cookies the browser did not return', async () => {
    const { factory } = makeStubFactory({ cookies: { accessToken: 'jwt' } });
    const session = await bootstrap({
      serverName: 'signupgenius-mcp',
      version: '1.2.2',
      domains: ['signupgenius.com'],
      declare: {
        cookies: ['accessToken', 'cfid', 'cftoken'],
        localStorage: [],
        sessionStorage: [],
        captureHeaders: [],
      },
      _serverFactory: factory,
    });
    expect(session.cookies).toEqual({ accessToken: 'jwt' });
    expect(session.missing.cookies).toEqual(['cfid', 'cftoken']);
  });

  it('reports an empty list when every declared cookie came back', async () => {
    const { factory } = makeStubFactory({ cookies: { a: '1', b: '2' } });
    const session = await bootstrap({
      serverName: 'x',
      version: '1',
      domains: ['x.com'],
      declare: { cookies: ['a', 'b'], localStorage: [], sessionStorage: [], captureHeaders: [] },
      _serverFactory: factory,
    });
    expect(session.missing.cookies).toEqual([]);
  });

  it('reports every declared cookie when the jar is empty', async () => {
    const { factory } = makeStubFactory({ cookies: {} });
    const session = await bootstrap({
      serverName: 'x',
      version: '1',
      domains: ['x.com'],
      declare: { cookies: ['a', 'b'], localStorage: [], sessionStorage: [], captureHeaders: [] },
      _serverFactory: factory,
    });
    expect(session.missing.cookies).toEqual(['a', 'b']);
  });

  it('applies the same reporting to localStorage and sessionStorage', async () => {
    const { factory } = makeStubFactory({
      localStorage: { auth: 'tok' },
      sessionStorage: {},
    });
    const session = await bootstrap({
      serverName: 'x',
      version: '1',
      domains: ['x.com'],
      declare: {
        cookies: [],
        localStorage: ['auth', 'profile'],
        sessionStorage: ['sid'],
        captureHeaders: [],
      },
      _serverFactory: factory,
    });
    expect(session.missing.localStorage).toEqual(['profile']);
    expect(session.missing.sessionStorage).toEqual(['sid']);
  });

  it('reports nothing missing when nothing was declared', async () => {
    const { factory } = makeStubFactory();
    const session = await bootstrap({
      serverName: 'x',
      version: '1',
      domains: ['x.com'],
      declare: { cookies: [], localStorage: [], sessionStorage: [], captureHeaders: [] },
      _serverFactory: factory,
    });
    expect(session.missing).toEqual({ cookies: [], localStorage: [], sessionStorage: [] });
  });
});

// ────────────────────────────────────────────────────────────────────────────
// createSessionLifter — renewable lifts (#183)
// ────────────────────────────────────────────────────────────────────────────
//
// `bootstrap()` returns a VALUE, so consumers naturally capture a session once
// and never renew it. That is the API's grain, not a consumer mistake, and it
// produces a bug that only surfaces on sites with short-lived credentials:
// the MCP works for one credential lifetime, then dies with no way back
// (a browser-backed account has no password to re-login with).
//
// A fleet audit found four repos with the one-shot capture and four that had
// hand-rolled the renewable shape. This makes renewable the default.
describe('createSessionLifter', () => {
  it('does not touch the bridge until the lifter is called', async () => {
    const { factory, calls } = makeStubFactory({ cookies: { a: '1' } });
    const lift = createSessionLifter({
      serverName: 'x',
      version: '1',
      domains: ['x.com'],
      declare: { cookies: ['a'], localStorage: [], sessionStorage: [], captureHeaders: [] },
      _serverFactory: factory,
    });
    // Construction is pure — no server, no listen, no pair prompt.
    expect(calls.constructorOpts).toHaveLength(0);
    expect(calls.listen).toBe(0);

    const session = await lift();
    expect(session.cookies).toEqual({ a: '1' });
    expect(calls.listen).toBe(1);
  });

  it('can be called repeatedly, opening and closing a bridge each time', async () => {
    const { factory, calls } = makeStubFactory({ cookies: { a: '1' } });
    const lift = createSessionLifter({
      serverName: 'x',
      version: '1',
      domains: ['x.com'],
      declare: { cookies: ['a'], localStorage: [], sessionStorage: [], captureHeaders: [] },
      _serverFactory: factory,
    });
    await lift();
    await lift();
    await lift();
    expect(calls.listen).toBe(3);
    expect(calls.close).toBe(3);
  });

  it('reflects fresh browser state on each call', async () => {
    // The whole point: a renewal must re-read the browser, not replay a
    // captured value.
    let n = 0;
    const factory: BootstrapServerFactory = () => ({
      listen: async () => {},
      close: async () => {},
      readCookies: async () => `tok=v${++n}`,
      readLocalStorage: async () => ({}),
      readSessionStorage: async () => ({}),
      captureRequestHeader: async () => '',
      readIndexedDb: async () => ({}),
    }) as never;
    const lift = createSessionLifter({
      serverName: 'x',
      version: '1',
      domains: ['x.com'],
      declare: { cookies: ['tok'], localStorage: [], sessionStorage: [], captureHeaders: [] },
      _serverFactory: factory,
    });
    expect((await lift()).cookies.tok).toBe('v1');
    expect((await lift()).cookies.tok).toBe('v2');
  });

  it('surfaces a failed lift and stays usable for the next attempt', async () => {
    // A lift that fails because the user is signed out must not poison the
    // lifter — signing in and retrying has to work. This is the other half of
    // the one-shot bug: a startup failure used to be cached for the life of
    // the process.
    let attempt = 0;
    const factory: BootstrapServerFactory = () => ({
      listen: async () => {},
      close: async () => {},
      readCookies: async () => {
        attempt++;
        if (attempt === 1) throw new Error('no tab open');
        return 'tok=recovered';
      },
      readLocalStorage: async () => ({}),
      readSessionStorage: async () => ({}),
      captureRequestHeader: async () => '',
      readIndexedDb: async () => ({}),
    }) as never;
    const lift = createSessionLifter({
      serverName: 'x',
      version: '1',
      domains: ['x.com'],
      declare: { cookies: ['tok'], localStorage: [], sessionStorage: [], captureHeaders: [] },
      _serverFactory: factory,
    });
    await expect(lift()).rejects.toThrow(/no tab open/);
    expect((await lift()).cookies.tok).toBe('recovered');
  });

  it('single-flights concurrent lifts', async () => {
    // Two simultaneous expiries must not open two bridges for the same MCP.
    // Consumers' session managers usually single-flight their login, but the
    // lifter should not depend on that.
    const { factory, calls } = makeStubFactory({ cookies: { a: '1' } });
    const lift = createSessionLifter({
      serverName: 'x',
      version: '1',
      domains: ['x.com'],
      declare: { cookies: ['a'], localStorage: [], sessionStorage: [], captureHeaders: [] },
      _serverFactory: factory,
    });
    const [s1, s2] = await Promise.all([lift(), lift()]);
    expect(calls.listen).toBe(1);
    expect(s1).toBe(s2);
    // ...and the next call after settling starts a fresh lift.
    await lift();
    expect(calls.listen).toBe(2);
  });

  it('honors BootstrapDisabledError the same way bootstrap() does', async () => {
    process.env['X_DISABLE_FETCHPROXY'] = '1';
    try {
      const lift = createSessionLifter({
        serverName: 'x',
        version: '1',
        domains: ['x.com'],
        declare: { cookies: ['a'], localStorage: [], sessionStorage: [], captureHeaders: [] },
      });
      await expect(lift()).rejects.toBeInstanceOf(BootstrapDisabledError);
    } finally {
      delete process.env['X_DISABLE_FETCHPROXY'];
    }
  });

  it('bootstrap() is exactly one invocation of a lifter', async () => {
    // Keeping bootstrap() is deliberate: the tool-invoked capture pattern
    // (vibo, honeybook) is legitimately one-shot. It must not drift from the
    // lifter, so it is implemented in terms of it.
    const { factory, calls } = makeStubFactory({ cookies: { a: '1' } });
    const opts = {
      serverName: 'x',
      version: '1',
      domains: ['x.com'],
      declare: { cookies: ['a'], localStorage: [], sessionStorage: [], captureHeaders: [] },
      _serverFactory: factory,
    };
    const direct = await bootstrap(opts);
    const viaLifter = await createSessionLifter(opts)();
    expect(direct).toEqual(viaLifter);
    expect(calls.listen).toBe(2);
  });
});

describe('storagePath — path-scoped cookies (#198)', () => {
  it('passes the declared path through to readCookies', async () => {
    const { factory, calls } = makeStubFactory({ cookies: { JSESSIONID: 's' } });
    await bootstrap({
      serverName: 'infinitecampus-mcp',
      version: '2.4.3',
      domains: ['600.ncsis.gov'],
      storagePath: '/campus',
      declare: {
        cookies: ['JSESSIONID'],
        localStorage: [],
        sessionStorage: [],
        captureHeaders: [],
      },
      _serverFactory: factory,
    });
    expect(calls.readCookies[0]).toMatchObject({ path: '/campus' });
  });

  it('omits path when not declared, leaving existing consumers untouched', async () => {
    const { factory, calls } = makeStubFactory({ cookies: { a: '1' } });
    await bootstrap({
      serverName: 'x',
      version: '1',
      domains: ['x.com'],
      declare: { cookies: ['a'], localStorage: [], sessionStorage: [], captureHeaders: [] },
      _serverFactory: factory,
    });
    expect(calls.readCookies[0]).not.toHaveProperty('path');
  });

  it('is available on the repeatable lifter too', async () => {
    const { factory, calls } = makeStubFactory({ cookies: { JSESSIONID: 's' } });
    const lift = createSessionLifter({
      serverName: 'infinitecampus-mcp',
      version: '2.4.3',
      domains: ['600.ncsis.gov'],
      storagePath: '/campus',
      declare: {
        cookies: ['JSESSIONID'],
        localStorage: [],
        sessionStorage: [],
        captureHeaders: [],
      },
      _serverFactory: factory,
    });
    await lift();
    await lift();
    expect(calls.readCookies).toHaveLength(2);
    expect(calls.readCookies[1]).toMatchObject({ path: '/campus' });
  });
});
