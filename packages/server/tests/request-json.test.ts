import { describe, it, expect } from 'vitest';
import { FetchproxyServer } from '../src/index.js';
import type { FetchInit, FetchResult, FetchResultError } from '../src/index.js';

/**
 * `requestJson<T>` is the generalization of the per-site `fetchJson<T>`
 * helper that zillow/redfin/compass/homes hand-rolled char-for-char in
 * their `src/client.ts`. Scope is serialization + header defaults +
 * 204-handling + JSON.parse ONLY — it returns BOTH the parsed `data`
 * and the raw `FetchResult` so callers keep their per-site
 * `throwIfNotOk` / `throwIfSignInPage` guards (sign-in URL patterns
 * differ per site, so those stay in the consumer).
 *
 * These tests drive the request envelope by overriding `fetch()` so we
 * never touch the WebSocket — the same pattern `convenience.test.ts`
 * uses.
 */
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

const baseOpts = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
};

describe('requestJson<T>', () => {
  it('GET: sets Accept but no Content-Type, sends no body, parses the JSON', async () => {
    const s = new TestServer(baseOpts);
    s.canned = {
      ok: true,
      status: 200,
      url: 'https://example.com/api',
      body: JSON.stringify({ hello: 'world' }),
    };
    const { data, result } = await s.requestJson<{ hello: string }>('GET', '/api');
    expect(s.lastInit!.method).toBe('GET');
    expect(s.lastInit!.url).toBe('https://example.com/api');
    expect(s.lastInit!.headers).toEqual({ Accept: 'application/json' });
    expect(s.lastInit!.body).toBeUndefined();
    expect(data).toEqual({ hello: 'world' });
    // The raw FetchResult is handed back so callers can run their own
    // per-site throwIfNotOk / throwIfSignInPage guards.
    expect(result.status).toBe(200);
    expect(result.url).toBe('https://example.com/api');
  });

  it('POST with a body: JSON.stringifies it and sets Content-Type', async () => {
    const s = new TestServer(baseOpts);
    s.canned = {
      ok: true,
      status: 201,
      url: 'https://example.com/api',
      body: JSON.stringify({ id: 7 }),
    };
    const { data } = await s.requestJson<{ id: number }>('POST', '/api', {
      body: { name: 'x' },
    });
    expect(s.lastInit!.method).toBe('POST');
    expect(s.lastInit!.headers).toEqual({
      Accept: 'application/json',
      'Content-Type': 'application/json',
    });
    expect(s.lastInit!.body).toBe(JSON.stringify({ name: 'x' }));
    expect(data).toEqual({ id: 7 });
  });

  it('POST without a body: no Content-Type, no body sent', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '{}' };
    await s.requestJson('POST', '/api');
    expect(s.lastInit!.headers).toEqual({ Accept: 'application/json' });
    expect(s.lastInit!.body).toBeUndefined();
  });

  it('merges caller headers and lets them override the defaults', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '{}' };
    await s.requestJson('POST', '/api', {
      body: { a: 1 },
      headers: { 'Content-Type': 'application/vnd.api+json', 'X-Token': 'abc' },
    });
    expect(s.lastInit!.headers).toEqual({
      Accept: 'application/json',
      'Content-Type': 'application/vnd.api+json',
      'X-Token': 'abc',
    });
  });

  it('204: returns null data without attempting to parse', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 204, url: 'x', body: '' };
    // The return type is `T | null`, so a real `T` is safe here: the 204
    // arm narrows `data` to `null` rather than lying about it being a `T`.
    const { data, result } = await s.requestJson<{ id: number }>('DELETE', '/api');
    expect(data).toBeNull();
    expect(result.status).toBe(204);
  });

  it('empty body on a 200: returns null data without attempting to parse', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '' };
    const { data } = await s.requestJson<{ id: number }>('GET', '/api');
    expect(data).toBeNull();
  });

  it('honors subdomain + domain selectors via request() resolution', async () => {
    const s = new TestServer({ ...baseOpts, domains: ['example.com', 'other.com'] });
    s.canned = { ok: true, status: 200, url: 'x', body: '{}' };
    await s.requestJson('GET', '/x', { subdomain: 'api', domain: 'other.com' });
    expect(s.lastInit!.url).toBe('https://api.other.com/x');
  });

  it('throws a descriptive error when the body is not JSON (includes method + path)', async () => {
    const s = new TestServer(baseOpts);
    s.canned = { ok: true, status: 200, url: 'x', body: '<html>nope</html>' };
    await expect(s.requestJson('GET', '/api')).rejects.toThrow(
      /GET \/api .*not JSON/,
    );
  });

  it('does NOT swallow bridge errors — surfaces them as thrown (callers keep their guards on the result)', async () => {
    // requestJson reuses request()'s URL resolution + bridge-error
    // translation; a bridge failure (no tab / SW down) still throws a
    // typed error, exactly like the verb helpers.
    const s = new TestServer(baseOpts);
    s.canned = { ok: false, error: 'no tab', kind: 'no_tab' };
    await expect(s.requestJson('GET', '/api')).rejects.toThrow();
  });
});
