import { describe, it, expect } from 'vitest';
import { FetchproxyServer } from '../src/index.js';
import type { FetchInit, FetchResult, FetchResultError } from '../src/index.js';

// B-BUG-7: 204 is in getJson/postJson's default accepted statuses, but both
// JSON.parse'd the empty body and threw after the request had succeeded —
// for postJson, after the write had already happened.

class TestServer extends FetchproxyServer {
  public canned: FetchResult | FetchResultError = { ok: true, status: 200, url: '', body: '' };
  override async fetch(_init: FetchInit): Promise<FetchResult | FetchResultError> {
    return this.canned;
  }
}

const opts = { serverName: 'test-mcp', version: '0.0.1', domains: ['example.com'] };

describe('B-BUG-7: getJson/postJson on an empty 2xx body', () => {
  for (const [label, status, body] of [
    ['204 with empty body', 204, ''],
    ['200 with empty body', 200, ''],
    ['202 with whitespace body', 202, '  \n'],
  ] as const) {
    it(`getJson returns null for ${label}`, async () => {
      const s = new TestServer(opts);
      s.canned = { ok: true, status, url: 'x', body };
      await expect(s.getJson('/x')).resolves.toBeNull();
    });
    it(`postJson returns null for ${label}`, async () => {
      const s = new TestServer(opts);
      s.canned = { ok: true, status, url: 'x', body };
      await expect(s.postJson('/x', { a: 1 })).resolves.toBeNull();
    });
  }

  it('still parses a non-empty JSON body', async () => {
    const s = new TestServer(opts);
    s.canned = { ok: true, status: 201, url: 'x', body: '{"id":7}' };
    await expect(s.postJson('/x', {})).resolves.toEqual({ id: 7 });
  });

  it('still throws on a non-empty body that is not JSON', async () => {
    const s = new TestServer(opts);
    s.canned = { ok: true, status: 200, url: 'x', body: '<html>' };
    await expect(s.getJson('/x')).rejects.toThrow();
  });
});
