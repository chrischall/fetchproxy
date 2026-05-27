import { describe, it, expect } from 'vitest';
import {
  FetchproxyServer,
  FetchproxyBridgeDownError,
  FetchproxyTimeoutError,
  FetchproxyProtocolError,
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

const SW_ERROR = 'tab fetch failed: Error: Could not establish connection. Receiving end does not exist.';

describe('fetch() — lazy-revive on content_script_unreachable', () => {
  it('retries once after bridgeReviveDelayMs and returns the second result', async () => {
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 1 });
    const harness = installFakeHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await Promise.resolve();
    // First reply: SW unreachable.
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: false,
      op: 'fetch',
      error: SW_ERROR,
    });
    // Give the lazy-revive timer + the retry a chance to fire.
    await new Promise((r) => setTimeout(r, 10));
    // Second reply: success.
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
    if (result.ok) expect(result.body).toBe('ok');
  });

  it('does NOT retry when bridgeReviveDelayMs is unset (default 0 = disabled, back-compat)', async () => {
    const s = new FetchproxyServer(baseOpts);
    const harness = installFakeHost(s);
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
      error: SW_ERROR,
    });
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.kind).toBe('content_script_unreachable');
  });

  it('does NOT retry on non-SW errors (no_tab, domain_denied, …)', async () => {
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 1 });
    const harness = installFakeHost(s);
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
      error: 'no tab matching https://example.com/',
    });
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.kind).toBe('no_tab');
  });
});

describe('fetch() — fetchTimeoutMs', () => {
  it('returns {ok:false, kind:"timeout"} when the bridge never responds within fetchTimeoutMs', async () => {
    const s = new FetchproxyServer({ ...baseOpts, fetchTimeoutMs: 5 });
    installFakeHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    // Never reply — let the timer fire.
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.kind).toBe('timeout');
      expect(result.error).toMatch(/did not respond within 5ms/);
    }
  });

  it('no timer when fetchTimeoutMs is unset (back-compat — hangs until response)', async () => {
    const s = new FetchproxyServer(baseOpts);
    const harness = installFakeHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await Promise.resolve();
    // Reply after a tick to confirm we waited for it rather than timing out.
    await new Promise((r) => setTimeout(r, 5));
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

describe('convenience methods (request/get/post) — typed errors', () => {
  it('throws FetchproxyBridgeDownError on SW-unreachable (instanceof FetchproxyProtocolError for back-compat)', async () => {
    const s = new FetchproxyServer(baseOpts);
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
    await expect(pending).rejects.toBeInstanceOf(FetchproxyBridgeDownError);
    await expect(pending).rejects.toBeInstanceOf(FetchproxyProtocolError);
    await expect(pending).rejects.toMatchObject({ retryAttempted: false });
  });

  it('throws FetchproxyBridgeDownError(retryAttempted=true) when bridgeReviveDelayMs fires and the retry also fails', async () => {
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
      ok: false,
      op: 'fetch',
      error: SW_ERROR,
    });
    await expect(pending).rejects.toMatchObject({
      name: 'FetchproxyBridgeDownError',
      retryAttempted: true,
    });
  });

  it('throws FetchproxyTimeoutError when fetchTimeoutMs fires', async () => {
    const s = new FetchproxyServer({ ...baseOpts, fetchTimeoutMs: 5 });
    installFakeHost(s);
    await expect(s.get('/x')).rejects.toBeInstanceOf(FetchproxyTimeoutError);
    expect(new FetchproxyTimeoutError({ url: 'x', timeoutMs: 1 })).toBeInstanceOf(
      FetchproxyProtocolError
    );
  });
});

describe('captureRequestHeader() — lazy-revive', () => {
  it('retries once on SW-unreachable then succeeds', async () => {
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 1 });
    const harness = installFakeHost(s);
    const pending = s.captureRequestHeader({
      urlPattern: 'https://example.com/x*',
      headerName: 'Authorization',
    });
    await Promise.resolve();
    const first = harness.lastInner()!;
    harness.reply({
      type: 'response',
      id: first.id,
      ok: false,
      op: 'capture_request_header',
      error: SW_ERROR,
    });
    await new Promise((r) => setTimeout(r, 10));
    const second = harness.lastInner()!;
    expect(second.id).not.toBe(first.id);
    harness.reply({
      type: 'response',
      id: second.id,
      ok: true,
      op: 'capture_request_header',
      value: 'Bearer eyJ...',
    });
    await expect(pending).resolves.toBe('Bearer eyJ...');
  });

  it('throws FetchproxyBridgeDownError after retry-exhaustion (retryAttempted=true)', async () => {
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
      error: SW_ERROR,
    });
    await new Promise((r) => setTimeout(r, 10));
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: false,
      op: 'capture_request_header',
      error: SW_ERROR,
    });
    await expect(pending).rejects.toMatchObject({
      name: 'FetchproxyBridgeDownError',
      retryAttempted: true,
      op: 'capture_request_header',
      url: 'https://example.com/x*',
    });
    await expect(pending).rejects.toThrow(/https:\/\/example\.com\/x\*/);
  });

  it('throws FetchproxyBridgeDownError immediately (retryAttempted=false) when bridgeReviveDelayMs is unset', async () => {
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
      ok: false,
      op: 'capture_request_header',
      error: SW_ERROR,
    });
    await expect(pending).rejects.toMatchObject({
      name: 'FetchproxyBridgeDownError',
      retryAttempted: false,
      url: 'https://example.com/x*',
    });
  });

  it('non-SW capture errors still throw plain FetchproxyProtocolError (back-compat)', async () => {
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
      error: 'no tab matching https://example.com/',
    });
    await expect(pending).rejects.toBeInstanceOf(FetchproxyProtocolError);
    await expect(pending.catch((e) => e)).resolves.not.toBeInstanceOf(
      FetchproxyBridgeDownError
    );
  });
});
