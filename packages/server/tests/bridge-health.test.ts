import { describe, it, expect } from 'vitest';
import { FetchproxyServer } from '../src/index.js';
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

describe('bridgeHealth()', () => {
  it('starts with null timestamps and zero failures', () => {
    const s = new FetchproxyServer(baseOpts);
    const h = s.bridgeHealth();
    expect(h.lastSuccessAt).toBeNull();
    expect(h.lastFailureAt).toBeNull();
    expect(h.lastFailureReason).toBeNull();
    expect(h.consecutiveFailures).toBe(0);
    expect(h.lastExtensionMessageAt).toBeNull();
    expect(h.port).toBe(37149);
    // Role is null until listen() resolves.
    expect(h.role).toBeNull();
  });

  it('lastExtensionMessageAt updates on every inner frame from the extension (#23 ask 4)', async () => {
    const s = new FetchproxyServer(baseOpts);
    const harness = installFakeHost(s);
    expect(s.bridgeHealth().lastExtensionMessageAt).toBeNull();
    const before = Date.now();
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await Promise.resolve();
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/x',
      body: 'ok',
    });
    await pending;
    const ts = s.bridgeHealth().lastExtensionMessageAt;
    expect(ts).not.toBeNull();
    expect(ts!).toBeGreaterThanOrEqual(before);
  });

  it('records success on a successful fetch round-trip', async () => {
    const s = new FetchproxyServer(baseOpts);
    const harness = installFakeHost(s);
    const before = Date.now();
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await Promise.resolve();
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/x',
      body: 'ok',
    });
    await pending;
    const h = s.bridgeHealth();
    expect(h.lastSuccessAt).not.toBeNull();
    expect(h.lastSuccessAt!).toBeGreaterThanOrEqual(before);
    expect(h.consecutiveFailures).toBe(0);
    expect(h.lastFailureAt).toBeNull();
  });

  it('records failure on a bridge-down fetch result and increments consecutiveFailures', async () => {
    // bridgeReviveDelayMs:0 so each call resolves on its one reply
    // rather than hanging on the retry waiting for a second.
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 0 });
    const harness = installFakeHost(s);
    for (let i = 0; i < 3; i++) {
      const pending = s.fetch({
        url: 'https://example.com/x',
        method: 'GET',
        tabUrl: 'https://example.com/',
      });
      await Promise.resolve();
      harness.reply({
        type: 'response',
        id: harness.lastInner()!.id,
        ok: false,
        op: 'fetch',
        error: 'tab fetch failed: Error: Could not establish connection.',
      });
      await pending;
    }
    const h = s.bridgeHealth();
    expect(h.consecutiveFailures).toBe(3);
    expect(h.lastFailureReason).toMatch(/Could not establish/);
  });

  it('a success after failures resets consecutiveFailures', async () => {
    const s = new FetchproxyServer(baseOpts);
    const harness = installFakeHost(s);
    // Two failures
    for (let i = 0; i < 2; i++) {
      const p = s.fetch({
        url: 'https://example.com/x',
        method: 'GET',
        tabUrl: 'https://example.com/',
      });
      await Promise.resolve();
      harness.reply({
        type: 'response',
        id: harness.lastInner()!.id,
        ok: false,
        op: 'fetch',
        error: 'no tab matching https://example.com/',
      });
      await p;
    }
    expect(s.bridgeHealth().consecutiveFailures).toBe(2);
    // Then a success
    const p2 = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await Promise.resolve();
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/x',
      body: 'ok',
    });
    await p2;
    expect(s.bridgeHealth().consecutiveFailures).toBe(0);
  });

  it('records failure on a timeout', async () => {
    const s = new FetchproxyServer({ ...baseOpts, fetchTimeoutMs: 5 });
    installFakeHost(s);
    await s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    const h = s.bridgeHealth();
    expect(h.consecutiveFailures).toBe(1);
    expect(h.lastFailureReason).toMatch(/did not respond within 5ms/);
  });

  it('records success on captureRequestHeader success', async () => {
    const s = new FetchproxyServer(baseOpts);
    const harness = installFakeHost(s);
    const pending = s.captureRequestHeader({
      urlPattern: 'https://example.com/x*',
      headerName: 'Authorization',
    });
    await Promise.resolve();
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: true,
      op: 'capture_request_header',
      value: 'Bearer eyJ',
    });
    await pending;
    expect(s.bridgeHealth().lastSuccessAt).not.toBeNull();
    expect(s.bridgeHealth().consecutiveFailures).toBe(0);
  });

  it('records failure on captureRequestHeader bridge-down (after retry exhaustion)', async () => {
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 1 });
    const harness = installFakeHost(s);
    const pending = s.captureRequestHeader({
      urlPattern: 'https://example.com/x*',
      headerName: 'Authorization',
    });
    await Promise.resolve();
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: false,
      op: 'capture_request_header',
      error: 'tab fetch failed: Error: Could not establish connection.',
    });
    await new Promise((r) => setTimeout(r, 10));
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: false,
      op: 'capture_request_header',
      error: 'tab fetch failed: Error: Could not establish connection.',
    });
    await pending.catch(() => undefined);
    const h = s.bridgeHealth();
    // One user-visible failure, regardless of internal retry count.
    expect(h.consecutiveFailures).toBe(1);
    expect(h.lastFailureReason).toMatch(/capture_request_header|Could not establish/);
  });
});
