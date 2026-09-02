import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { FetchproxyServer } from '../src/index.js';
import type { InnerFrame, InnerRequest } from '@fetchproxy/protocol';
import { installFakeHost } from './helpers/fake-host.js';

// Issue #72 — flip `keepAliveIntervalMs` default to 25_000.
// Issue #73 — extend `bridgeHealth()` with keepAlive / swEviction
// observability counters.
// Issue #90 (P1-1) — tighten that default from 25_000 → 20_000 (25s
// still lost the cold-start race against a ~30s eviction window).
//
// Both issues touch the same region of ws-server.ts and ship together
// as a 0.10.0 feature pair. The round-3 #71 cohort wave (zillow#87,
// redfin#77, compass#72, homes#49, onehome#46, opentable#57, resy#38)
// showed every consumer was opting into the same 25_000 value, so the
// flip is safe even without the observability surface — and the
// observability surface lets downstream healthcheck tools verify
// the keep-alive is actually preventing SW eviction in the field.

const baseOpts = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
  capabilities: ['fetch' as const, 'capture_request_header' as const],
  captureHeaders: [
    { host: 'example.com', path: '/x*', headerName: 'Authorization' },
  ],
};

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
    extensionConnected: () => true,
    sessionLinked: () => true,
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

const pings = (host: RecordingHost): InnerFrame[] =>
  host.sent.filter((f) => f.type === 'ping');

// ---------------------------------------------------------------------------
// Issue #72 — default flip to 25_000
// ---------------------------------------------------------------------------

describe('#72 keepAliveIntervalMs default flip', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('fires the keep-alive timer when no keepAliveIntervalMs is passed (default 20s since #90)', async () => {
    const s = new FetchproxyServer(baseOpts);
    const host = installRecordingHost(s);
    // Trigger one fetch round-trip so noteActivityForKeepalive stamps
    // lastActiveAt and starts the timer under the new default.
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    // Flush microtasks.
    await Promise.resolve();
    const req = host.lastRequest()!;
    host.reply({
      type: 'response',
      id: req.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/x',
      body: 'ok',
    });
    await pending;
    // No pings yet (timer hasn't ticked).
    expect(pings(host).length).toBe(0);
    // Just before the 20s default — still no tick.
    await vi.advanceTimersByTimeAsync(19_999);
    expect(pings(host).length).toBe(0);
    // Cross the 20_000ms boundary — timer ticks once.
    await vi.advanceTimersByTimeAsync(1);
    expect(pings(host).length).toBe(1);
    // Another full interval — twice total.
    await vi.advanceTimersByTimeAsync(20_000);
    expect(pings(host).length).toBe(2);
    // close() must stop the timer cleanly so the test doesn't leak.
    await s.close();
  });

  it('disables the timer entirely when keepAliveIntervalMs: 0', async () => {
    const s = new FetchproxyServer({ ...baseOpts, keepAliveIntervalMs: 0 });
    const host = installRecordingHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await Promise.resolve();
    const req = host.lastRequest()!;
    host.reply({
      type: 'response',
      id: req.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/x',
      body: 'ok',
    });
    await pending;
    // Even after several "intervals" worth of fake-clock advancement the
    // timer is not armed — sendKeepalivePing was never reached.
    await vi.advanceTimersByTimeAsync(25_000 * 5);
    expect(pings(host).length).toBe(0);
    await s.close();
  });

  it('honors an explicit override (e.g. 10_000)', async () => {
    const s = new FetchproxyServer({ ...baseOpts, keepAliveIntervalMs: 10_000 });
    const host = installRecordingHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await Promise.resolve();
    const req = host.lastRequest()!;
    host.reply({
      type: 'response',
      id: req.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/x',
      body: 'ok',
    });
    await pending;
    await vi.advanceTimersByTimeAsync(10_000);
    expect(pings(host).length).toBe(1);
    await s.close();
  });
});

// ---------------------------------------------------------------------------
// Issue #73 — bridgeHealth() observability surface
// ---------------------------------------------------------------------------

describe('#73 bridgeHealth().keepAlive observability', () => {
  it('exposes resolved defaults when caller passes nothing', () => {
    const s = new FetchproxyServer(baseOpts);
    const h = s.bridgeHealth();
    expect(h.keepAlive.enabled).toBe(true);
    // #90 (P1-1): default tightened from 25_000 → 20_000 (more margin
    // under Chrome's ~30s SW-eviction window — 25s lost the race).
    expect(h.keepAlive.intervalMs).toBe(20_000);
    expect(h.keepAlive.maxIdleMs).toBe(5 * 60 * 1000); // 300_000
    expect(h.keepAlive.lastPingAt).toBeNull();
    expect(h.keepAlive.totalPings).toBe(0);
    expect(h.keepAlive.idleSinceMs).toBeNull();
  });

  it('reports enabled: false and the literal 0 when keepAliveIntervalMs: 0', () => {
    const s = new FetchproxyServer({ ...baseOpts, keepAliveIntervalMs: 0 });
    const h = s.bridgeHealth();
    expect(h.keepAlive.enabled).toBe(false);
    expect(h.keepAlive.intervalMs).toBe(0);
  });

  it('reports the caller-supplied intervalMs/maxIdleMs verbatim', () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      keepAliveIntervalMs: 17_000,
      keepAliveMaxIdleMs: 90_000,
    });
    const h = s.bridgeHealth();
    expect(h.keepAlive.intervalMs).toBe(17_000);
    expect(h.keepAlive.maxIdleMs).toBe(90_000);
  });

  it('idleSinceMs becomes a non-negative number once activity is recorded', async () => {
    const s = new FetchproxyServer(baseOpts);
    expect(s.bridgeHealth().keepAlive.idleSinceMs).toBeNull();
    s.markActive();
    const idle = s.bridgeHealth().keepAlive.idleSinceMs;
    expect(idle).not.toBeNull();
    expect(idle!).toBeGreaterThanOrEqual(0);
  });
});

describe('#73 keepAlive counters increment per tick', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('totalPings increments per tick and lastPingAt updates', async () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      // Override default 25_000 with a smaller value just so the fake
      // clock test stays cheap; the counter wiring is the same.
      keepAliveIntervalMs: 100,
      keepAliveMaxIdleMs: 10_000,
    });
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
    expect(s.bridgeHealth().keepAlive.totalPings).toBe(0);
    expect(s.bridgeHealth().keepAlive.lastPingAt).toBeNull();
    await vi.advanceTimersByTimeAsync(100);
    expect(s.bridgeHealth().keepAlive.totalPings).toBe(1);
    const stamp1 = s.bridgeHealth().keepAlive.lastPingAt;
    expect(stamp1).not.toBeNull();
    await vi.advanceTimersByTimeAsync(100);
    expect(s.bridgeHealth().keepAlive.totalPings).toBe(2);
    const stamp2 = s.bridgeHealth().keepAlive.lastPingAt;
    expect(stamp2).not.toBeNull();
    expect(stamp2!).toBeGreaterThan(stamp1!);
    await s.close();
  });

  it('totalPings is monotonic across close() (no reset semantics)', async () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      keepAliveIntervalMs: 50,
      keepAliveMaxIdleMs: 10_000,
    });
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
    await vi.advanceTimersByTimeAsync(150); // 3 ticks
    const beforeClose = s.bridgeHealth().keepAlive.totalPings;
    expect(beforeClose).toBeGreaterThanOrEqual(2);
    await s.close();
    expect(s.bridgeHealth().keepAlive.totalPings).toBe(beforeClose);
  });
});

// ---------------------------------------------------------------------------
// Issue #73 — swEviction lazy-revive counters
// ---------------------------------------------------------------------------

describe('#73 bridgeHealth().swEviction observability', () => {
  it('starts with zero attempts/successes and null lastEvictionDetectedAt', () => {
    const s = new FetchproxyServer(baseOpts);
    const h = s.bridgeHealth();
    expect(h.swEviction.lazyReviveAttempts).toBe(0);
    expect(h.swEviction.lazyReviveSuccesses).toBe(0);
    expect(h.swEviction.lastEvictionDetectedAt).toBeNull();
  });

  it('increments lazyReviveAttempts+Successes when a fetch revive succeeds on retry', async () => {
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 1 });
    const harness = installFakeHost(s);
    const before = Date.now();
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await Promise.resolve();
    // First attempt: content_script_unreachable — the symptom of MV3 SW
    // eviction; the classifier maps this error message into that kind.
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: false,
      op: 'fetch',
      error: 'tab fetch failed: Error: Could not establish connection.',
    });
    // Wait past the 1ms revive delay so the retry frame goes out.
    await new Promise((r) => setTimeout(r, 10));
    // Retry: succeed.
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
    expect(h.swEviction.lazyReviveAttempts).toBe(1);
    expect(h.swEviction.lazyReviveSuccesses).toBe(1);
    expect(h.swEviction.lastEvictionDetectedAt).not.toBeNull();
    expect(h.swEviction.lastEvictionDetectedAt!).toBeGreaterThanOrEqual(before);
  });

  it('increments lazyReviveAttempts but NOT Successes when the retry also fails', async () => {
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
      error: 'tab fetch failed: Error: Could not establish connection.',
    });
    await new Promise((r) => setTimeout(r, 10));
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: false,
      op: 'fetch',
      error: 'tab fetch failed: Error: Could not establish connection.',
    });
    await pending;
    const h = s.bridgeHealth();
    expect(h.swEviction.lazyReviveAttempts).toBe(1);
    expect(h.swEviction.lazyReviveSuccesses).toBe(0);
    expect(h.swEviction.lastEvictionDetectedAt).not.toBeNull();
  });

  it('does NOT increment lazyReviveAttempts when bridgeReviveDelayMs: 0 but DOES record lastEvictionDetectedAt', async () => {
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 0 });
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
      error: 'tab fetch failed: Error: Could not establish connection.',
    });
    await pending;
    const h = s.bridgeHealth();
    // Retry was disabled — no attempt was made.
    expect(h.swEviction.lazyReviveAttempts).toBe(0);
    expect(h.swEviction.lazyReviveSuccesses).toBe(0);
    // But the eviction symptom was still observed.
    expect(h.swEviction.lastEvictionDetectedAt).not.toBeNull();
  });

  it('increments counters on the captureRequestHeader revive path too', async () => {
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 1 });
    const harness = installFakeHost(s);
    const pending = s.captureRequestHeader({
      host: 'example.com',
      path: '/x*',
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
      ok: true,
      op: 'capture_request_header',
      value: 'Bearer eyJ',
    });
    await pending;
    const h = s.bridgeHealth();
    expect(h.swEviction.lazyReviveAttempts).toBe(1);
    expect(h.swEviction.lazyReviveSuccesses).toBe(1);
    expect(h.swEviction.lastEvictionDetectedAt).not.toBeNull();
  });

  it('does not increment any counter on non-eviction failures', async () => {
    // bridgeReviveDelayMs: 0 so the failure resolves on the first reply.
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 0 });
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
      // Generic failure — classifyFetchError maps this to 'no_matching_tab',
      // NOT content_script_unreachable.
      error: 'no tab matching https://example.com/',
    });
    await pending;
    const h = s.bridgeHealth();
    expect(h.swEviction.lazyReviveAttempts).toBe(0);
    expect(h.swEviction.lazyReviveSuccesses).toBe(0);
    expect(h.swEviction.lastEvictionDetectedAt).toBeNull();
  });
});
