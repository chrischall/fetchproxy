import { describe, it, expect } from 'vitest';
import {
  FetchproxyServer,
  FetchproxyBridgeDownError,
  FetchproxyTimeoutError,
  FetchproxyProtocolError,
  FetchproxyHttpError,
  classifyBridgeError,
} from '../src/index.js';
import type { BridgeError } from '../src/index.js';
import { installFakeHost } from './helpers/fake-host.js';

const baseOpts = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
  capabilities: ['fetch' as const, 'capture_request_header' as const],
  captureHeaders: [
    { urlPattern: 'https://example.com/x*', headerName: 'Authorization' },
  ],
};

const SW_ERROR =
  'tab fetch failed: Error: Could not establish connection. Receiving end does not exist.';

// (1) Restore role/port/elapsedMs on typed errors. Realty cohort
// migration agents flagged this as the most-missed papercut — they
// were forced to snapshot bridgeStatus() post-throw to surface role
// in healthcheck output.
describe('typed errors carry role/port/elapsedMs from the server', () => {
  it('FetchproxyTimeoutError exposes role + port + elapsedMs from the throw site', async () => {
    const s = new FetchproxyServer({ ...baseOpts, fetchTimeoutMs: 5 });
    installFakeHost(s);
    const before = Date.now();
    const err = await s.get('/x').catch((e) => e);
    expect(err).toBeInstanceOf(FetchproxyTimeoutError);
    expect((err as FetchproxyTimeoutError).role).toBe('host');
    expect((err as FetchproxyTimeoutError).port).toBe(37149);
    expect((err as FetchproxyTimeoutError).elapsedMs).toBeGreaterThanOrEqual(5);
    expect((err as FetchproxyTimeoutError).elapsedMs).toBeLessThan(
      Date.now() - before + 200,
    );
  });

  it('FetchproxyBridgeDownError exposes role + port on fetch path', async () => {
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 0 });
    const harness = installFakeHost(s);
    const pending = s.get('/x').catch((e) => e);
    await Promise.resolve();
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: false,
      op: 'fetch',
      error: SW_ERROR,
    });
    const err = await pending;
    expect(err).toBeInstanceOf(FetchproxyBridgeDownError);
    expect((err as FetchproxyBridgeDownError).role).toBe('host');
    expect((err as FetchproxyBridgeDownError).port).toBe(37149);
  });

  it('FetchproxyBridgeDownError exposes role + port on captureRequestHeader path', async () => {
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 0 });
    const harness = installFakeHost(s);
    const pending = s.captureRequestHeader().catch((e) => e);
    await Promise.resolve();
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: false,
      op: 'capture_request_header',
      error: SW_ERROR,
    });
    const err = await pending;
    expect(err).toBeInstanceOf(FetchproxyBridgeDownError);
    expect((err as FetchproxyBridgeDownError).role).toBe('host');
    expect((err as FetchproxyBridgeDownError).port).toBe(37149);
  });
});

// (2) BridgeHealth carries the per-server config so MCPs can drop
// their bespoke status() shims and surface bridgeHealth() directly.
describe('bridgeHealth includes serverVersion + fetchTimeoutMs + bridgeReviveDelayMs', () => {
  it('snapshots the resolved option values, not the raw caller input', () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      version: '1.2.3',
      fetchTimeoutMs: 9000,
      bridgeReviveDelayMs: 500,
    });
    const h = s.bridgeHealth();
    expect(h.serverVersion).toBe('1.2.3');
    expect(h.fetchTimeoutMs).toBe(9000);
    expect(h.bridgeReviveDelayMs).toBe(500);
  });

  it('reports defaults (30000 / 2000) when caller omits the knobs', () => {
    const s = new FetchproxyServer(baseOpts);
    const h = s.bridgeHealth();
    expect(h.fetchTimeoutMs).toBe(30000);
    expect(h.bridgeReviveDelayMs).toBe(2000);
  });
});

// (3) Auto-derive tabUrl/host from absolute URLs in request() so
// downstream MCPs unify on `subdomain: 'www'` without a conditional
// spread for absolute-URL paths.
describe('request() auto-derives tabUrl from absolute URL host', () => {
  class TabUrlSpy extends FetchproxyServer {
    public lastInit: { url: string; tabUrl: string } | null = null;
    override async fetch(init: {
      url: string;
      method: string;
      tabUrl: string;
      headers?: Record<string, string>;
      body?: string;
    }): Promise<{ ok: true; status: number; url: string; body: string }> {
      this.lastInit = { url: init.url, tabUrl: init.tabUrl };
      return { ok: true, status: 200, url: init.url, body: '' };
    }
  }

  it('absolute URL to a different subdomain: tabUrl points at the URL host, not the subdomain default', async () => {
    const s = new TabUrlSpy({ ...baseOpts, domains: ['compass.com'] });
    await s.request('GET', 'https://photos.compass.com/123', {
      subdomain: 'www',
    });
    expect(s.lastInit!.url).toBe('https://photos.compass.com/123');
    // Should route through a photos.compass.com tab, not www.compass.com.
    expect(s.lastInit!.tabUrl).toBe('https://photos.compass.com/');
  });

  it('relative path: subdomain default still applies (back-compat)', async () => {
    const s = new TabUrlSpy({ ...baseOpts, domains: ['compass.com'] });
    await s.request('GET', '/api/foo', { subdomain: 'www' });
    expect(s.lastInit!.url).toBe('https://www.compass.com/api/foo');
    expect(s.lastInit!.tabUrl).toBe('https://www.compass.com/');
  });

  it('absolute URL with no subdomain opt: still derives tabUrl from URL host', async () => {
    const s = new TabUrlSpy({ ...baseOpts, domains: ['compass.com'] });
    await s.request('GET', 'https://photos.compass.com/123');
    expect(s.lastInit!.tabUrl).toBe('https://photos.compass.com/');
  });
});

// (5) classifyBridgeError() helper — single discriminator for the
// catch ladder that the cohort migration showed every healthcheck
// tool now needs.
describe('classifyBridgeError() discriminator', () => {
  it('returns "timeout" for FetchproxyTimeoutError', () => {
    const err = new FetchproxyTimeoutError({ url: 'x', timeoutMs: 1 });
    expect(classifyBridgeError(err)).toBe('timeout');
  });

  it('returns "bridge_down" for FetchproxyBridgeDownError', () => {
    const err = new FetchproxyBridgeDownError({ originalError: 'x' });
    expect(classifyBridgeError(err)).toBe('bridge_down');
  });

  it('returns "http" for FetchproxyHttpError', () => {
    const err = new FetchproxyHttpError({
      status: 500,
      url: 'x',
      body: '',
    });
    expect(classifyBridgeError(err)).toBe('http');
  });

  it('returns "protocol" for generic FetchproxyProtocolError', () => {
    const err = new FetchproxyProtocolError('something');
    expect(classifyBridgeError(err)).toBe('protocol');
  });

  it('returns "other" for arbitrary Error subclasses', () => {
    expect(classifyBridgeError(new Error('x'))).toBe('other');
    expect(classifyBridgeError(new TypeError('x'))).toBe('other');
    expect(classifyBridgeError('not even an error')).toBe('other');
  });

  it('subclass before parent: a FetchproxyBridgeDownError (extends FetchproxyProtocolError) classifies as bridge_down', () => {
    const err = new FetchproxyBridgeDownError({ originalError: 'x' });
    expect(err).toBeInstanceOf(FetchproxyProtocolError);
    expect(classifyBridgeError(err)).toBe('bridge_down'); // NOT 'protocol'
  });

  it('exports BridgeError type alias for the discriminator return', () => {
    // Compile-time check: the union has exactly the documented arms.
    const arms: BridgeError[] = ['timeout', 'bridge_down', 'http', 'protocol', 'other'];
    expect(arms).toHaveLength(5);
  });
});
