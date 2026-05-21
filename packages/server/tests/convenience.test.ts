import { describe, it, expect } from 'vitest';
import {
  FetchproxyServer,
  FetchproxyProtocolError,
  FetchproxyHttpError,
} from '../src/index.js';
import type { FetchInit, FetchResult, FetchResultError } from '../src/index.js';
import type { InnerFrame, InnerRequest } from '@fetchproxy/protocol';

class TestServer extends FetchproxyServer {
  public lastInit: FetchInit | null = null;
  public canned: FetchResult | FetchResultError = {
    ok: true,
    status: 200,
    url: '',
    body: '',
  };

  override async fetch(init: FetchInit): Promise<FetchResult | FetchResultError> {
    this.lastInit = init;
    return this.canned;
  }
}

/**
 * Test harness that pretends `listen()` was called by installing a
 * minimal fake host handle on the FetchproxyServer instance, then
 * captures every inner request the server emits and lets the test
 * resolve the corresponding response by replying through `onInner`.
 *
 * Avoids dealing with the real WS handshake just to exercise the
 * `readCookies()` plumbing.
 */
function installFakeHost(server: FetchproxyServer): {
  lastInner: () => InnerRequest | null;
  reply: (resp: InnerFrame) => void;
} {
  let lastInner: InnerRequest | null = null;
  const fakeHostHandle = {
    close: async () => undefined,
    sendOwnInner: async (inner: InnerFrame): Promise<void> => {
      if (inner.type === 'request') lastInner = inner;
    },
    onOwnInner: (_cb: (inner: InnerFrame) => void) => undefined,
  };
  // Reach into the private hostHandle slot so `readCookies()` sees a
  // "listening" server. Wiring this once at the start of a test is much
  // less invasive than spinning up the real listen() machinery.
  (server as unknown as { hostHandle: typeof fakeHostHandle }).hostHandle = fakeHostHandle;
  return {
    lastInner: () => lastInner,
    reply: (resp) => {
      (server as unknown as { onInner(i: InnerFrame): void }).onInner(resp);
    },
  };
}

describe('convenience methods', () => {
  const baseOpts = {
    serverName: 'test-mcp',
    version: '0.0.1',
    domains: ['example.com'],
    // Don't call listen() — we override fetch directly.
  };

  it('request prepends https://${domain} to relative paths', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: 'x' };
    await s.request('GET', '/api/foo');
    expect(s.lastInit!.url).toBe('https://example.com/api/foo');
    expect(s.lastInit!.tabUrl).toBe('https://example.com/');
  });

  it('request uses absolute URL as-is when it stays within the declared domain', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: 'x' };
    await s.request('GET', 'https://api.example.com/path');
    expect(s.lastInit!.url).toBe('https://api.example.com/path');
  });

  it('request throws on absolute URL outside the declared domain', async () => {
    const s = new TestServer(baseOpts);
    await expect(s.request('GET', 'https://otherdomain.com/path')).rejects.toThrow(
      /outside declared domain/,
    );
  });

  it('subdomain opt routes to https://${subdomain}.${domain}', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: 'x' };
    await s.request('GET', '/api/foo', { subdomain: 'www' });
    expect(s.lastInit!.url).toBe('https://www.example.com/api/foo');
    expect(s.lastInit!.tabUrl).toBe('https://www.example.com/');
  });

  it('subdomain accepts dot-separated labels (e.g. "auth.api")', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: 'x' };
    await s.request('GET', '/x', { subdomain: 'auth.api' });
    expect(s.lastInit!.url).toBe('https://auth.api.example.com/x');
  });

  it('different subdomain on different calls', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: 'x' };
    await s.get('/x', { subdomain: 'www' });
    expect(s.lastInit!.url).toBe('https://www.example.com/x');
    await s.get('/x', { subdomain: 'api' });
    expect(s.lastInit!.url).toBe('https://api.example.com/x');
    await s.get('/x');  // no subdomain
    expect(s.lastInit!.url).toBe('https://example.com/x');
  });

  it('request throws FetchproxyProtocolError when fetchproxy returns !ok', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: false, error: 'no tab' };
    await expect(s.request('GET', '/x')).rejects.toThrow(FetchproxyProtocolError);
  });

  it('request throws FetchproxyHttpError when expectStatus mismatches', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 404, url: 'x', body: '' };
    await expect(s.request('GET', '/x', { expectStatus: 200 })).rejects.toThrow(
      FetchproxyHttpError,
    );
  });

  it('request accepts array of expectStatus', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 201, url: 'x', body: '' };
    const r = await s.request('GET', '/x', { expectStatus: [200, 201, 204] });
    expect(r.status).toBe(201);
  });

  it('request does NOT throw on non-2xx if expectStatus omitted', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 404, url: 'x', body: 'not found' };
    const r = await s.request('GET', '/x');
    expect(r.status).toBe(404);
  });

  it('get is a thin wrapper around request', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await s.get('/x');
    expect(s.lastInit!.method).toBe('GET');
  });

  it('post sends body and method', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await s.post('/x', 'hello');
    expect(s.lastInit!.method).toBe('POST');
    expect(s.lastInit!.body).toBe('hello');
  });

  it('put / patch / delete also set the right method', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await s.put('/x', 'data');
    expect(s.lastInit!.method).toBe('PUT');
    await s.patch('/x', 'data');
    expect(s.lastInit!.method).toBe('PATCH');
    await s.delete('/x');
    expect(s.lastInit!.method).toBe('DELETE');
  });

  it('getJson parses JSON body, throws on 4xx by default', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '{"a":1}' };
    const r = await s.getJson<{ a: number }>('/x');
    expect(r.a).toBe(1);

    s.canned = { ok: true, status: 404, url: 'x', body: '{}' };
    await expect(s.getJson('/x')).rejects.toThrow(FetchproxyHttpError);
  });

  it('getJson passes subdomain through', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '{}' };
    await s.getJson('/x', { subdomain: 'api' });
    expect(s.lastInit!.url).toBe('https://api.example.com/x');
  });

  it('postJson stringifies body and sets Content-Type', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '{"ok":true}' };
    await s.postJson('/x', { foo: 'bar' });
    expect(s.lastInit!.method).toBe('POST');
    expect(s.lastInit!.body).toBe('{"foo":"bar"}');
    expect(s.lastInit!.headers?.['Content-Type']).toBe('application/json');
  });

  it('postJson preserves caller-set Content-Type', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '{}' };
    await s.postJson(
      '/x',
      { foo: 'bar' },
      { headers: { 'Content-Type': 'application/vnd.x+json' } },
    );
    expect(s.lastInit!.headers?.['Content-Type']).toBe('application/vnd.x+json');
  });

  it('getHtml returns body as string, throws on 4xx by default', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '<html></html>' };
    const h = await s.getHtml('/x');
    expect(h).toBe('<html></html>');

    s.canned = { ok: true, status: 500, url: 'x', body: '<html>err</html>' };
    await expect(s.getHtml('/x')).rejects.toThrow(FetchproxyHttpError);
  });

  it('FetchproxyHttpError carries the response', async () => {
    const s = new TestServer(baseOpts);
    s.canned = {
      ok: true,
      status: 418,
      url: 'https://example.com/teapot',
      body: 'I am a teapot',
    };
    try {
      await s.getJson('/teapot');
      expect.fail('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(FetchproxyHttpError);
      const httpErr = e as FetchproxyHttpError;
      expect(httpErr.response.status).toBe(418);
      expect(httpErr.response.body).toBe('I am a teapot');
    }
  });
});

describe('subdomain guard', () => {
  const baseOpts = {
    serverName: 'test-mcp',
    version: '0.0.1',
    domains: ['opentable.com'],
  };

  it('rejects a subdomain with a slash', async () => {
    const s = new TestServer(baseOpts);
    await expect(s.get('/x', { subdomain: 'www/foo' })).rejects.toThrow(/DNS label/);
  });

  it('rejects a subdomain with a URL scheme', async () => {
    const s = new TestServer(baseOpts);
    await expect(s.get('/x', { subdomain: 'https://www' })).rejects.toThrow(/DNS label/);
  });

  it('rejects a subdomain with a port', async () => {
    const s = new TestServer(baseOpts);
    await expect(s.get('/x', { subdomain: 'www:8080' })).rejects.toThrow(/DNS label/);
  });

  it('rejects an empty subdomain', async () => {
    const s = new TestServer(baseOpts);
    await expect(s.get('/x', { subdomain: '' })).rejects.toThrow(/DNS label/);
  });

  it('rejects a subdomain starting with a dot', async () => {
    const s = new TestServer(baseOpts);
    await expect(s.get('/x', { subdomain: '.www' })).rejects.toThrow(/DNS label/);
  });

  it('rejects a subdomain starting with a hyphen', async () => {
    const s = new TestServer(baseOpts);
    await expect(s.get('/x', { subdomain: '-www' })).rejects.toThrow(/DNS label/);
  });

  it('accepts a single DNS label', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await expect(s.get('/x', { subdomain: 'www' })).resolves.toBeDefined();
  });

  it('accepts dot-separated labels', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await expect(s.get('/x', { subdomain: 'auth.api' })).resolves.toBeDefined();
  });

  it('accepts labels with hyphens', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await expect(s.get('/x', { subdomain: 'us-west' })).resolves.toBeDefined();
  });

  it('subdomain case is preserved in URL', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await s.get('/x', { subdomain: 'WWW' });
    expect(s.lastInit!.url).toBe('https://WWW.opentable.com/x');
  });
});

describe('multi-domain MCPs', () => {
  const multiOpts = {
    serverName: 'test-mcp',
    version: '0.0.1',
    domains: ['honeybook.com', 'hbsplit.com'],
  };

  it('ctor rejects empty domains array', () => {
    expect(
      () =>
        new TestServer({
          serverName: 'test-mcp',
          version: '0.0.1',
          domains: [],
        }),
    ).toThrow(/non-empty/);
  });

  it('ctor rejects non-array domains', () => {
    expect(
      () =>
        new TestServer({
          serverName: 'test-mcp',
          version: '0.0.1',
          // @ts-expect-error — intentional bad input
          domains: 'honeybook.com',
        }),
    ).toThrow(/non-empty/);
  });

  it('single-domain MCP works without per-call domain opt', async () => {
    const s = new TestServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
    });
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await s.get('/x');
    expect(s.lastInit!.url).toBe('https://example.com/x');
  });

  it('multi-domain MCP throws when domain opt omitted', async () => {
    const s = new TestServer(multiOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await expect(s.get('/x')).rejects.toThrow(/multiple domains/);
  });

  it('multi-domain MCP resolves with valid domain opt', async () => {
    const s = new TestServer(multiOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await s.get('/x', { domain: 'honeybook.com' });
    expect(s.lastInit!.url).toBe('https://honeybook.com/x');
    expect(s.lastInit!.tabUrl).toBe('https://honeybook.com/');
    await s.get('/y', { domain: 'hbsplit.com' });
    expect(s.lastInit!.url).toBe('https://hbsplit.com/y');
  });

  it('multi-domain MCP combines domain + subdomain', async () => {
    const s = new TestServer(multiOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await s.get('/x', { domain: 'honeybook.com', subdomain: 'api' });
    expect(s.lastInit!.url).toBe('https://api.honeybook.com/x');
    expect(s.lastInit!.tabUrl).toBe('https://api.honeybook.com/');
  });

  it('multi-domain MCP throws when domain opt is not in declared list', async () => {
    const s = new TestServer(multiOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await expect(s.get('/x', { domain: 'evil.com' })).rejects.toThrow(
      /not in the declared domains/,
    );
  });

  it('multi-domain MCP: absolute URLs into any declared domain are accepted', async () => {
    const s = new TestServer(multiOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    await s.get('https://api.honeybook.com/x', { domain: 'honeybook.com' });
    expect(s.lastInit!.url).toBe('https://api.honeybook.com/x');
    await s.get('https://www.hbsplit.com/x', { domain: 'hbsplit.com' });
    expect(s.lastInit!.url).toBe('https://www.hbsplit.com/x');
  });

  it('multi-domain MCP: absolute URL outside the domain set is rejected', async () => {
    const s = new TestServer(multiOpts);
    await expect(
      s.get('https://otherdomain.com/x', { domain: 'honeybook.com' }),
    ).rejects.toThrow(/outside declared domains/);
  });

  it('postJson and getJson pass domain through', async () => {
    const s = new TestServer(multiOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '{}' };
    await s.getJson('/x', { domain: 'honeybook.com' });
    expect(s.lastInit!.url).toBe('https://honeybook.com/x');
    await s.postJson('/y', { a: 1 }, { domain: 'hbsplit.com' });
    expect(s.lastInit!.url).toBe('https://hbsplit.com/y');
    expect(s.lastInit!.method).toBe('POST');
  });
});

describe('capabilities option', () => {
  it("defaults to ['fetch'] when capabilities omitted", () => {
    // Same as before — no caller-visible effect on convenience methods.
    const s = new TestServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
    });
    expect(s.role).toBeNull();
  });

  it('rejects an empty capabilities array', () => {
    expect(
      () =>
        new TestServer({
          serverName: 'test-mcp',
          version: '0.0.1',
          domains: ['example.com'],
          capabilities: [],
        }),
    ).toThrow(/non-empty/);
  });

  it('rejects an unknown capability', () => {
    expect(
      () =>
        new TestServer({
          serverName: 'test-mcp',
          version: '0.0.1',
          domains: ['example.com'],
          // @ts-expect-error - intentional bad input
          capabilities: ['fetch', 'frobnicate'],
        }),
    ).toThrow(/unknown capability/);
  });

  it("accepts ['fetch', 'read_cookies']", () => {
    expect(
      () =>
        new FetchproxyServer({
          serverName: 'test-mcp',
          version: '0.0.1',
          domains: ['example.com'],
          capabilities: ['fetch', 'read_cookies'],
        }),
    ).not.toThrow();
  });
});

describe('readCookies()', () => {
  it('throws if "read_cookies" was not declared in capabilities', async () => {
    const s = new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      // Default capabilities = ['fetch']
    });
    await expect(s.readCookies()).rejects.toThrow(/read_cookies/);
  });

  it('throws if called before listen()', async () => {
    const s = new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      capabilities: ['fetch', 'read_cookies'],
    });
    await expect(s.readCookies()).rejects.toThrow(/before listen/);
  });

  it("sends a read_cookies inner request pinned to the declared domain's tabUrl", async () => {
    const s = new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      capabilities: ['fetch', 'read_cookies'],
    });
    const fake = installFakeHost(s);
    fake.reply; // satisfy ts unused-vars
    // Kick off and immediately reply with canned cookies.
    const promise = s.readCookies();
    // Allow the microtask that calls sendOwnInner to flush.
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    expect(inner).not.toBeNull();
    expect(inner!.type).toBe('request');
    expect(inner!.op).toBe('read_cookies');
    if (inner!.op === 'read_cookies') {
      expect(inner!.init.tabUrl).toBe('https://example.com/');
    }
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'read_cookies',
      cookies: 'sid=abc; pref=light',
    });
    await expect(promise).resolves.toBe('sid=abc; pref=light');
  });

  it('routes subdomain into the tabUrl', async () => {
    const s = new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      capabilities: ['fetch', 'read_cookies'],
    });
    const fake = installFakeHost(s);
    const promise = s.readCookies({ subdomain: 'auth' });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    expect(inner).not.toBeNull();
    if (inner!.op === 'read_cookies') {
      expect(inner!.init.tabUrl).toBe('https://auth.example.com/');
    }
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'read_cookies',
      cookies: '',
    });
    await promise;
  });

  it('multi-domain MCP requires { domain } on readCookies', async () => {
    const s = new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['honeybook.com', 'hbsplit.com'],
      capabilities: ['fetch', 'read_cookies'],
    });
    installFakeHost(s);
    await expect(s.readCookies()).rejects.toThrow(/multiple domains/);
  });

  it('multi-domain MCP resolves with explicit { domain }', async () => {
    const s = new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['honeybook.com', 'hbsplit.com'],
      capabilities: ['fetch', 'read_cookies'],
    });
    const fake = installFakeHost(s);
    const promise = s.readCookies({ domain: 'hbsplit.com' });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    if (inner!.op === 'read_cookies') {
      expect(inner!.init.tabUrl).toBe('https://hbsplit.com/');
    }
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'read_cookies',
      cookies: 'k=v',
    });
    await expect(promise).resolves.toBe('k=v');
  });

  it('surfaces an error response as FetchproxyProtocolError', async () => {
    const s = new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      capabilities: ['fetch', 'read_cookies'],
    });
    const fake = installFakeHost(s);
    const promise = s.readCookies();
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: false,
      op: 'read_cookies',
      error: 'no tab matching https://example.com/',
    });
    await expect(promise).rejects.toThrow(FetchproxyProtocolError);
    await expect(promise).rejects.toThrow(/no tab matching/);
  });
});

// -------------------------------------------------------------------
// 0.3.0 — scope declarations + new bootstrap verbs.
// -------------------------------------------------------------------

describe('0.3.0 scope declarations on FetchproxyServer', () => {
  it('rejects an unknown cookieKeys entry at the call site', async () => {
    const s = new FetchproxyServer({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      capabilities: ['fetch', 'read_cookies'],
      cookieKeys: ['MTOKEN', 'CKAT'],
    });
    installFakeHost(s);
    await expect(s.readCookies({ keys: ['NOT_DECLARED'] })).rejects.toThrow(
      /not in declared cookieKeys/,
    );
  });

  it('rejects readCookies({ keys }) when no cookieKeys were declared', async () => {
    const s = new FetchproxyServer({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      capabilities: ['fetch', 'read_cookies'],
    });
    installFakeHost(s);
    await expect(s.readCookies({ keys: ['anything'] })).rejects.toThrow(
      /not in declared cookieKeys/,
    );
  });

  it('emits the new {origin, keys} inner shape when keys is provided', async () => {
    const s = new FetchproxyServer({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      capabilities: ['fetch', 'read_cookies'],
      cookieKeys: ['MTOKEN', 'CKAT'],
    });
    const fake = installFakeHost(s);
    const promise = s.readCookies({ keys: ['MTOKEN'] });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    expect(inner).not.toBeNull();
    expect(inner!.type).toBe('request');
    if (inner!.op === 'read_cookies') {
      expect('origin' in inner!.init).toBe(true);
      if ('origin' in inner!.init) {
        expect(inner!.init.origin).toBe('https://ourfamilywizard.com');
        expect(inner!.init.keys).toEqual(['MTOKEN']);
      }
    }
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'read_cookies',
      values: { MTOKEN: 'ey...' },
    });
    // Back-compat surface is a Promise<string>, so the values map is
    // serialised the same way `document.cookie` would render.
    await expect(promise).resolves.toBe('MTOKEN=ey...');
  });

  it("readCookies() without keys arg keeps the legacy {tabUrl} shape", async () => {
    const s = new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      capabilities: ['fetch', 'read_cookies'],
    });
    const fake = installFakeHost(s);
    const promise = s.readCookies();
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    if (inner!.op === 'read_cookies' && 'tabUrl' in inner!.init) {
      expect(inner!.init.tabUrl).toBe('https://example.com/');
    } else {
      throw new Error('expected legacy tabUrl shape');
    }
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'read_cookies',
      cookies: 'k=v',
    });
    await expect(promise).resolves.toBe('k=v');
  });
});

describe('readLocalStorage()', () => {
  it('throws if "read_local_storage" was not declared', async () => {
    const s = new FetchproxyServer({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      // no capabilities decl -> defaults to ['fetch']
      localStorageKeys: ['auth'],
    });
    installFakeHost(s);
    await expect(s.readLocalStorage({ keys: ['auth'] })).rejects.toThrow(
      /read_local_storage/,
    );
  });

  it('throws if called before listen()', async () => {
    const s = new FetchproxyServer({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      capabilities: ['fetch', 'read_local_storage'],
      localStorageKeys: ['auth'],
    });
    await expect(s.readLocalStorage({ keys: ['auth'] })).rejects.toThrow(/before listen/);
  });

  it('rejects an undeclared localStorage key', async () => {
    const s = new FetchproxyServer({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      capabilities: ['fetch', 'read_local_storage'],
      localStorageKeys: ['auth'],
    });
    installFakeHost(s);
    await expect(s.readLocalStorage({ keys: ['nope'] })).rejects.toThrow(
      /not in declared localStorageKeys/,
    );
  });

  it('rejects an empty keys arg', async () => {
    const s = new FetchproxyServer({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      capabilities: ['fetch', 'read_local_storage'],
      localStorageKeys: ['auth'],
    });
    installFakeHost(s);
    await expect(s.readLocalStorage({ keys: [] })).rejects.toThrow(/non-empty/);
  });

  it('emits a read_local_storage inner request and resolves to values', async () => {
    const s = new FetchproxyServer({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      capabilities: ['fetch', 'read_local_storage'],
      localStorageKeys: ['auth', 'tokenExpiry'],
    });
    const fake = installFakeHost(s);
    const promise = s.readLocalStorage({ keys: ['auth', 'tokenExpiry'] });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    expect(inner).not.toBeNull();
    expect(inner!.op).toBe('read_local_storage');
    if (inner!.op === 'read_local_storage') {
      expect(inner!.init.origin).toBe('https://ourfamilywizard.com');
      expect(inner!.init.keys).toEqual(['auth', 'tokenExpiry']);
    }
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'read_local_storage',
      values: { auth: 'ey...', tokenExpiry: '1730000000000' },
    });
    await expect(promise).resolves.toEqual({
      auth: 'ey...',
      tokenExpiry: '1730000000000',
    });
  });

  it('surfaces an error response as FetchproxyProtocolError', async () => {
    const s = new FetchproxyServer({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      capabilities: ['fetch', 'read_local_storage'],
      localStorageKeys: ['auth'],
    });
    const fake = installFakeHost(s);
    const promise = s.readLocalStorage({ keys: ['auth'] });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: false,
      op: 'read_local_storage',
      error: 'no tab matching',
    });
    await expect(promise).rejects.toThrow(FetchproxyProtocolError);
  });
});

describe('readSessionStorage()', () => {
  it('throws if "read_session_storage" was not declared', async () => {
    const s = new FetchproxyServer({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
    });
    installFakeHost(s);
    await expect(s.readSessionStorage({ keys: ['x'] })).rejects.toThrow(
      /read_session_storage/,
    );
  });

  it('emits a read_session_storage inner request', async () => {
    const s = new FetchproxyServer({
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      capabilities: ['fetch', 'read_session_storage'],
      sessionStorageKeys: ['anon-id'],
    });
    const fake = installFakeHost(s);
    const promise = s.readSessionStorage({ keys: ['anon-id'] });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    expect(inner!.op).toBe('read_session_storage');
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'read_session_storage',
      values: { 'anon-id': 'abc' },
    });
    await expect(promise).resolves.toEqual({ 'anon-id': 'abc' });
  });
});

describe('captureRequestHeader()', () => {
  const headerOpts = {
    serverName: 'honeybook-mcp',
    version: '0.1.0',
    domains: ['honeybook.com'],
    capabilities: ['fetch', 'capture_request_header'] as const,
    captureHeaders: [
      { urlPattern: 'https://api.honeybook.com/api/v2/*', headerName: 'hb-api-fingerprint' },
    ],
  };

  it('throws if "capture_request_header" was not declared', async () => {
    const s = new FetchproxyServer({
      serverName: 'honeybook-mcp',
      version: '0.1.0',
      domains: ['honeybook.com'],
    });
    installFakeHost(s);
    await expect(
      s.captureRequestHeader({
        urlPattern: 'https://api.honeybook.com/api/v2/*',
        headerName: 'hb-api-fingerprint',
      }),
    ).rejects.toThrow(/capture_request_header/);
  });

  it('rejects an undeclared (urlPattern, headerName) pair', async () => {
    const s = new FetchproxyServer(headerOpts);
    installFakeHost(s);
    await expect(
      s.captureRequestHeader({
        urlPattern: 'https://api.honeybook.com/api/v3/*',
        headerName: 'hb-api-fingerprint',
      }),
    ).rejects.toThrow(/not declared/);
  });

  it('rejects an undeclared headerName even when urlPattern matches', async () => {
    const s = new FetchproxyServer(headerOpts);
    installFakeHost(s);
    await expect(
      s.captureRequestHeader({
        urlPattern: 'https://api.honeybook.com/api/v2/*',
        headerName: 'X-Other',
      }),
    ).rejects.toThrow(/not declared/);
  });

  it('emits a capture_request_header inner request and resolves to the value', async () => {
    const s = new FetchproxyServer(headerOpts);
    const fake = installFakeHost(s);
    const promise = s.captureRequestHeader({
      urlPattern: 'https://api.honeybook.com/api/v2/*',
      headerName: 'hb-api-fingerprint',
    });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    expect(inner).not.toBeNull();
    expect(inner!.op).toBe('capture_request_header');
    if (inner!.op === 'capture_request_header') {
      expect(inner!.init.urlPattern).toBe('https://api.honeybook.com/api/v2/*');
      expect(inner!.init.headerName).toBe('hb-api-fingerprint');
    }
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'capture_request_header',
      value: 'fp-abc123',
    });
    await expect(promise).resolves.toBe('fp-abc123');
  });

  it('threads timeoutMs onto the inner request', async () => {
    const s = new FetchproxyServer(headerOpts);
    const fake = installFakeHost(s);
    const promise = s.captureRequestHeader({
      urlPattern: 'https://api.honeybook.com/api/v2/*',
      headerName: 'hb-api-fingerprint',
      timeoutMs: 5000,
    });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    if (inner!.op === 'capture_request_header') {
      expect(inner!.init.timeoutMs).toBe(5000);
    }
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'capture_request_header',
      value: 'x',
    });
    await promise;
  });

  it('surfaces a timeout error response as FetchproxyProtocolError', async () => {
    const s = new FetchproxyServer(headerOpts);
    const fake = installFakeHost(s);
    const promise = s.captureRequestHeader({
      urlPattern: 'https://api.honeybook.com/api/v2/*',
      headerName: 'hb-api-fingerprint',
    });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: false,
      op: 'capture_request_header',
      error: 'timeout',
    });
    await expect(promise).rejects.toThrow(FetchproxyProtocolError);
    await expect(promise).rejects.toThrow(/timeout/);
  });
});

describe('URL guard (assertUrlInDomains)', () => {
  it('rejects path arg that cannot be parsed as a URL', async () => {
    // ws-server.ts:153 — `new URL(...)` throw caught and re-wrapped.
    // The shape that hits this is a path that starts with `http://`
    // or `https://` (so we DON'T pre-prepend) but is otherwise
    // malformed enough that the URL constructor rejects it.
    const s = new TestServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
    });
    await expect(
      s.get('https://[::1'), // unclosed IPv6 literal
    ).rejects.toThrow(/not a valid URL/);
  });
});

describe('onInner cross-map defensive paths', () => {
  // The `pending` and `pendingReadCookies` maps are keyed by the same
  // unique request id stream, so under normal operation the response's
  // op matches the awaiter's verb. These tests drive the defensive
  // branches in onInner where the wrong-op response reaches the wrong
  // awaiter — the awaiter must wake with a protocol error rather than
  // silently hanging or surfacing the wrong response shape.

  it("a read_cookies response landing on a fetch awaiter wakes with an error", async () => {
    const s = new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      capabilities: ['fetch', 'read_cookies'],
    });
    const fake = installFakeHost(s);
    const promise = s.get('/x'); // fetch awaiter
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    expect(inner).not.toBeNull();
    // Reply with the WRONG op on purpose.
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'read_cookies',
      cookies: 'should never be returned',
    });
    await expect(promise).rejects.toThrow(/unexpected read_cookies response/);
  });

  it("a fetch response landing on a read_cookies awaiter wakes with an error", async () => {
    const s = new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      capabilities: ['fetch', 'read_cookies'],
    });
    const fake = installFakeHost(s);
    const promise = s.readCookies();
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    expect(inner).not.toBeNull();
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/',
      body: 'oops',
    });
    await expect(promise).rejects.toThrow(/unexpected fetch response/);
  });
});

describe('applyJsonDefaults honors caller-supplied expectStatus', () => {
  it('does not override an explicit expectStatus passed to getJson', async () => {
    // ws-server.ts:569 — short-circuit when the caller already set the
    // field. The default 2xx-set must NOT clobber a caller's strict
    // single-status check.
    const s = new TestServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
    });
    // Canned 201 — would pass the default 2xx set, but the caller's
    // strict `expectStatus: 200` should reject it.
    s.canned = { ok: true, status: 201, url: 'https://example.com/x', body: '{}' };
    await expect(s.getJson('/x', { expectStatus: 200 })).rejects.toThrow(
      FetchproxyHttpError,
    );
  });
});
