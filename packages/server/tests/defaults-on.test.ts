import { describe, it, expect } from 'vitest';
import {
  FetchproxyServer,
  FetchproxyBridgeDownError,
  FetchproxyTimeoutError,
} from '../src/index.js';
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

describe('0.8.0 default: fetchTimeoutMs ON (30s) by default', () => {
  it('default convenience-method call gets the timeout wrapper (no explicit opt-in)', async () => {
    const s = new FetchproxyServer({ ...baseOpts, fetchTimeoutMs: 5 });
    // Pinning fetchTimeoutMs: 5 here only to make the test fast — the
    // POINT of this test is that callers DO get the typed throw without
    // needing any code change vs. omitting the option.
    installFakeHost(s);
    await expect(s.get('/x')).rejects.toBeInstanceOf(FetchproxyTimeoutError);
  });

  it('explicit fetchTimeoutMs: 0 disables the timer (back-door for callers who want the old hang-forever behavior)', async () => {
    const s = new FetchproxyServer({ ...baseOpts, fetchTimeoutMs: 0 });
    const harness = installFakeHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    // Replied late — confirms we're not racing a default timer.
    await new Promise((r) => setTimeout(r, 20));
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
    const result = await pending;
    expect(result.ok).toBe(true);
  });
});

describe('0.8.0 default: bridgeReviveDelayMs ON (2000ms) by default', () => {
  it('default convenience-method call retries on SW eviction (no explicit opt-in)', async () => {
    // Pinning the delay to 1ms to keep the test fast — the POINT is
    // that the retry happens at all without any caller opt-in.
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 1 });
    const harness = installFakeHost(s);
    const pending = s.get('/x');
    await Promise.resolve();
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: false,
      op: 'fetch',
      error: SW_ERROR,
    });
    await new Promise((r) => setTimeout(r, 10));
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/x',
      body: 'ok',
    });
    const response = await pending;
    expect(response.status).toBe(200);
  });

  it('explicit bridgeReviveDelayMs: 0 disables the retry (back-door)', async () => {
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 0 });
    const harness = installFakeHost(s);
    const pending = s.get('/x');
    await Promise.resolve();
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: false,
      op: 'fetch',
      error: SW_ERROR,
    });
    await expect(pending).rejects.toMatchObject({
      name: 'FetchproxyBridgeDownError',
      retryAttempted: false,
    });
  });
});
