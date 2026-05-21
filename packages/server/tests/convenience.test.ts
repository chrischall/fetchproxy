import { describe, it, expect } from 'vitest';
import {
  FetchproxyServer,
  FetchproxyProtocolError,
  FetchproxyHttpError,
} from '../src/index.js';
import type { FetchInit, FetchResult, FetchResultError } from '../src/index.js';

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

describe('convenience methods', () => {
  const baseOpts = {
    serverName: 'test-mcp',
    version: '0.0.1',
    domain: 'example.com',
    // Don't call listen() — we override fetch directly.
  };

  it('request prepends origin to relative paths', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: 'x' };
    await s.request('GET', '/api/foo');
    expect(s.lastInit!.url).toBe('https://example.com/api/foo');
  });

  it('request uses absolute URL as-is', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: 'x' };
    await s.request('GET', 'https://otherdomain.com/path');
    expect(s.lastInit!.url).toBe('https://otherdomain.com/path');
  });

  it('request uses custom origin', async () => {
    const s = new TestServer({ ...baseOpts, origin: 'https://www.example.com' });
    s.canned = { ok: true, status: 200, url: 'x', body: 'x' };
    await s.request('GET', '/api/foo');
    expect(s.lastInit!.url).toBe('https://www.example.com/api/foo');
  });

  it('request uses custom tabUrl', async () => {
    const s = new TestServer({ ...baseOpts, tabUrl: 'https://app.example.com/' });
    s.canned = { ok: true, status: 200, url: 'x', body: 'x' };
    await s.request('GET', '/api/foo');
    expect(s.lastInit!.tabUrl).toBe('https://app.example.com/');
  });

  it('default tabUrl is derived from origin', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: 'x' };
    await s.request('GET', '/x');
    expect(s.lastInit!.tabUrl).toBe('https://example.com/');
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
