import { describe, it, expect } from 'vitest';
import {
  FetchproxyServer,
  FetchproxyBridgeDownError,
} from '../src/index.js';
import { installFakeHost } from './helpers/fake-host.js';

const baseOpts = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
  capabilities: ['fetch' as const],
};

const SW_ERROR =
  'tab fetch failed: Error: Could not establish connection. Receiving end does not exist.';

describe('retryAttempted on result envelope — race-safe per-call context (#60 follow-up)', () => {
  // The PR #60 reviewer noted that the original `_lastRetryAttempted`
  // side-channel field could be overwritten by a concurrent fetch()
  // call between the moment A's fetch() resolved and A's request()
  // continuation ran. The architectural fix: thread retry state
  // through the result envelope itself (additive
  // `retryAttempted?: boolean` field) so each call carries its own
  // outcome — no shared mutable slot.

  it('successful retry: result.ok=true carries retryAttempted=true', async () => {
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
    const result = await pending;
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.retryAttempted).toBe(true);
  });

  it('no-retry success: result.ok=true carries retryAttempted=false (not undefined)', async () => {
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
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/x',
      body: 'ok',
    });
    const result = await pending;
    if (result.ok) expect(result.retryAttempted).toBe(false);
  });

  it('failed-retry envelope: result.ok=false carries retryAttempted=true', async () => {
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
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.retryAttempted).toBe(true);
      expect(result.kind).toBe('content_script_unreachable');
    }
  });

  it('convenience methods derive retryAttempted from the envelope, not a shared field', async () => {
    // After the fix, _lastRetryAttempted is gone — request() reads
    // result.retryAttempted directly. This test asserts the typed
    // error carries the right flag even under interleaved calls.
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 1 });
    const harness = installFakeHost(s);
    const pendingA = s.get('/a').catch((e) => e);
    await Promise.resolve();
    const aFirstId = harness.lastInner()!.id;
    harness.reply({
      type: 'response',
      id: aFirstId,
      ok: false,
      op: 'fetch',
      error: SW_ERROR,
    });
    await new Promise((r) => setTimeout(r, 10));
    // A's retry frame was just emitted; capture its id.
    const aRetryId = harness.lastInner()!.id;
    expect(aRetryId).toBe(aFirstId + 1);
    // Fire a second call B before resolving A's retry. B is non-SW
    // so it doesn't retry — its envelope will carry retryAttempted=false.
    const pendingB = s.get('/b').catch((e) => e);
    await Promise.resolve();
    const bFirstId = harness.lastInner()!.id;
    expect(bFirstId).toBe(aRetryId + 1);
    // Resolve B first (non-SW), then A's retry (still SW-down).
    harness.reply({
      type: 'response',
      id: bFirstId,
      ok: false,
      op: 'fetch',
      error: 'no tab matching https://example.com/',
    });
    harness.reply({
      type: 'response',
      id: aRetryId,
      ok: false,
      op: 'fetch',
      error: SW_ERROR,
    });
    const [aErr, bErr] = await Promise.all([pendingA, pendingB]);
    expect(aErr).toBeInstanceOf(FetchproxyBridgeDownError);
    expect((aErr as FetchproxyBridgeDownError).retryAttempted).toBe(true);
    // B's error is not a bridge-down (it was no_tab), so we don't
    // assert retryAttempted on it — the field only applies to the
    // SW-eviction path.
    expect(bErr).not.toBeInstanceOf(FetchproxyBridgeDownError);
  });
});
