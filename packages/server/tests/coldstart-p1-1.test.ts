import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  FetchproxyServer,
  FetchproxyBridgeDownError,
  FetchproxyTimeoutError,
} from '../src/index.js';
import type { InnerFrame, InnerRequest } from '@fetchproxy/protocol';
import { installFakeHost } from './helpers/fake-host.js';

// Issue #90 (P1-1) — service-worker eviction cold-start tax.
//
// Three independent gaps were defeating the keep-alive + lazy-revive:
//   1. The 25s default left too little margin under Chrome's ~30s SW
//      eviction window — tightened to 20s so the ping reliably wins.
//   2. The one-shot lazy-revive only covered `content_script_unreachable`,
//      not `timeout`. A fully-cold worker often surfaces the first
//      post-idle call as a server-side timeout, which sailed straight
//      through to the caller.
//   3. The bridge-down remediation text told the user to click the
//      toolbar icon; the error's own diagnostic says the real fix is a
//      loaded, signed-in tab for that domain.

const baseOpts = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
  capabilities: ['fetch' as const],
};

const SW_ERROR =
  'tab fetch failed: Error: Could not establish connection. Receiving end does not exist.';

interface RecordingHost {
  sent: InnerFrame[];
  lastRequest: () => InnerRequest | null;
  reply: (frame: InnerFrame) => void;
}

function installRecordingHost(server: FetchproxyServer): RecordingHost {
  const sent: InnerFrame[] = [];
  const fakeHostHandle = {
    close: async () => undefined,
    sendOwnInner: async (inner: InnerFrame): Promise<void> => {
      sent.push(inner);
    },
    onOwnInner: (_cb: (inner: InnerFrame) => void) => undefined,
    onExtensionDisconnect: (_cb: () => void) => undefined,
    onPendingPair: (_cb: (code: string) => void) => undefined,
    pendingPairCode: (): string | null => null,
  };
  (server as unknown as { hostHandle: typeof fakeHostHandle }).hostHandle = fakeHostHandle;
  (server as unknown as { role: 'host' | 'peer' | null }).role = 'host';
  return {
    sent,
    lastRequest: () => {
      for (let i = sent.length - 1; i >= 0; i--) {
        const f = sent[i];
        if (f && f.type === 'request') return f;
      }
      return null;
    },
    reply: (frame) => {
      (server as unknown as { onInner(i: InnerFrame): void }).onInner(frame);
    },
  };
}

const pings = (host: RecordingHost): InnerFrame[] => host.sent.filter((f) => f.type === 'ping');

// ---------------------------------------------------------------------------
// (1) tighter default keep-alive interval — win the eviction race
// ---------------------------------------------------------------------------

describe('#90 keepAliveIntervalMs default tightened below the eviction window', () => {
  it('defaults to 20_000 (more margin under the ~30s SW eviction window than the old 25s)', () => {
    const s = new FetchproxyServer(baseOpts);
    const h = s.bridgeHealth();
    expect(h.keepAlive.intervalMs).toBe(20_000);
    expect(h.keepAlive.enabled).toBe(true);
  });

  it('still honours an explicit override', () => {
    const s = new FetchproxyServer({ ...baseOpts, keepAliveIntervalMs: 12_000 });
    expect(s.bridgeHealth().keepAlive.intervalMs).toBe(12_000);
  });

  it('still disables when keepAliveIntervalMs: 0', () => {
    const s = new FetchproxyServer({ ...baseOpts, keepAliveIntervalMs: 0 });
    const h = s.bridgeHealth();
    expect(h.keepAlive.enabled).toBe(false);
    expect(h.keepAlive.intervalMs).toBe(0);
  });

  describe('timer fires at the new 20s default', () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it('does not ping before 20s but ticks once at exactly 20s', async () => {
      const s = new FetchproxyServer(baseOpts);
      const host = installRecordingHost(s);
      const pending = s.fetch({
        url: 'https://example.com/x',
        method: 'GET',
        tabUrl: 'https://example.com/',
      });
      await Promise.resolve();
      host.reply({
        type: 'response',
        id: host.lastRequest()!.id,
        ok: true,
        op: 'fetch',
        status: 200,
        url: 'https://example.com/x',
        body: 'ok',
      });
      await pending;
      // 19.999s — old 25s default would obviously not fire, and neither
      // should 20s.
      await vi.advanceTimersByTimeAsync(19_999);
      expect(pings(host).length).toBe(0);
      // Cross the 20s boundary — the timer ticks.
      await vi.advanceTimersByTimeAsync(1);
      expect(pings(host).length).toBe(1);
      await s.close();
    });
  });
});

// ---------------------------------------------------------------------------
// (2) retry-after-warm now covers the timeout cold-start, not just
//     content_script_unreachable
// ---------------------------------------------------------------------------

describe('#90 fetch() lazy-revive covers the first post-idle timeout', () => {
  // Fake timers give deterministic control over fetchTimeoutMs (so the
  // FIRST attempt times out exactly when we want) and over the revive
  // delay — without it the retry's own timeout races the test's reply.
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('a cold-start timeout is retried once after warming and succeeds (never surfaces to caller)', async () => {
    // fetchTimeoutMs so the first attempt times out (cold SW);
    // bridgeReviveDelayMs so the retry fires after a controlled delay.
    const s = new FetchproxyServer({
      ...baseOpts,
      fetchTimeoutMs: 100,
      bridgeReviveDelayMs: 10,
    });
    const host = installRecordingHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await Promise.resolve();
    // First attempt is in flight — one request frame, no reply (cold SW).
    expect(host.sent.filter((f) => f.type === 'request').length).toBe(1);
    // Cross the 100ms fetch timeout → first attempt resolves as timeout.
    await vi.advanceTimersByTimeAsync(100);
    // Cross the 10ms revive delay → the warm-and-retry frame goes out.
    await vi.advanceTimersByTimeAsync(10);
    const reqs = host.sent.filter((f) => f.type === 'request');
    expect(reqs.length).toBe(2);
    const second = host.lastRequest()!;
    // The SW has warmed up — reply to the retry with a success.
    host.reply({
      type: 'response',
      id: second.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/x',
      body: 'warmed',
    });
    const result = await pending;
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.body).toBe('warmed');
      expect(result.retryAttempted).toBe(true);
    }
    await s.close();
  });

  it('a timeout that persists on retry still surfaces as kind:timeout with retryAttempted:true', async () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      fetchTimeoutMs: 100,
      bridgeReviveDelayMs: 10,
    });
    const host = installRecordingHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    // First timeout → revive delay → second timeout.
    await vi.advanceTimersByTimeAsync(100); // first attempt times out
    await vi.advanceTimersByTimeAsync(10); // revive delay elapses
    await vi.advanceTimersByTimeAsync(100); // retry attempt times out
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.kind).toBe('timeout');
      expect(result.retryAttempted).toBe(true);
    }
    // Two request frames were emitted (original + revive retry).
    expect(host.sent.filter((f) => f.type === 'request').length).toBe(2);
    await s.close();
  });

  it('the timeout revive path ticks the swEviction counters', async () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      fetchTimeoutMs: 100,
      bridgeReviveDelayMs: 10,
    });
    const host = installRecordingHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await vi.advanceTimersByTimeAsync(100); // first attempt times out
    await vi.advanceTimersByTimeAsync(10); // revive delay elapses
    expect(host.sent.filter((f) => f.type === 'request').length).toBe(2);
    host.reply({
      type: 'response',
      id: host.lastRequest()!.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/x',
      body: 'warmed',
    });
    await pending;
    const h = s.bridgeHealth();
    expect(h.swEviction.lazyReviveAttempts).toBe(1);
    expect(h.swEviction.lazyReviveSuccesses).toBe(1);
    expect(h.swEviction.lastEvictionDetectedAt).not.toBeNull();
    await s.close();
  });

  it('does NOT retry a timeout when bridgeReviveDelayMs: 0 (opt-out preserved)', async () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      fetchTimeoutMs: 100,
      bridgeReviveDelayMs: 0,
    });
    const host = installRecordingHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await vi.advanceTimersByTimeAsync(100); // first attempt times out
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.kind).toBe('timeout');
      expect(result.retryAttempted).toBe(false);
    }
    // Only ONE request frame — no retry was attempted.
    expect(host.sent.filter((f) => f.type === 'request').length).toBe(1);
    await s.close();
  });

  it('a persistent cold-start timeout throws FetchproxyTimeoutError from convenience methods', async () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      fetchTimeoutMs: 100,
      bridgeReviveDelayMs: 10,
    });
    installRecordingHost(s);
    const pending = s.get('/x');
    // Surface unhandled-rejection noise quietly until we assert below.
    pending.catch(() => undefined);
    await vi.advanceTimersByTimeAsync(100); // first attempt times out
    await vi.advanceTimersByTimeAsync(10); // revive delay elapses
    await vi.advanceTimersByTimeAsync(100); // retry times out
    await expect(pending).rejects.toBeInstanceOf(FetchproxyTimeoutError);
    await s.close();
  });
});

// ---------------------------------------------------------------------------
// (3) remediation text matches the error's own diagnostic
// ---------------------------------------------------------------------------

describe('#90 FetchproxyBridgeDownError remediation text', () => {
  it('points at a loaded, signed-in tab — not the toolbar icon', () => {
    const err = new FetchproxyBridgeDownError({
      originalError: SW_ERROR,
      retryAttempted: true,
    });
    // The real fix per the diagnostic: a loaded, signed-in tab.
    expect(err.hint).toMatch(/signed.?in/i);
    expect(err.hint).toMatch(/loaded/i);
    expect(err.hint).toMatch(/\btab\b/i);
    // The misleading "click the toolbar icon" guidance is gone.
    expect(err.hint).not.toMatch(/toolbar icon/i);
    expect(err.message).not.toMatch(/toolbar icon/i);
  });

  it('still surfaces the original error and the chrome://extensions fallback', () => {
    const err = new FetchproxyBridgeDownError({
      originalError: SW_ERROR,
      retryAttempted: false,
    });
    expect(err.hint).toContain(SW_ERROR);
    expect(err.hint).toMatch(/chrome:\/\/extensions/);
  });
});
