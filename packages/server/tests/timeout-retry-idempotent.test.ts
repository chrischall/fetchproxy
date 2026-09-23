import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  FetchproxyServer,
  FetchproxyTimeoutError,
  retryOnceOnTimeout,
} from '../src/index.js';
import type { InnerFrame, InnerRequest } from '@fetchproxy/protocol';

// B-BUG-1: a `timeout` only means the reply has not arrived yet — the
// extension may already have run the request in the tab. Re-sending a
// POST/PUT/PATCH/DELETE after it can double-book or double-pay, so the
// cold-start timeout retry is limited to idempotent methods unless the
// caller opts in per call. The `content_script_unreachable` retry stays
// on for every method: that request provably never reached a tab.

const baseOpts = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
  capabilities: ['fetch' as const],
  fetchTimeoutMs: 100,
  bridgeReviveDelayMs: 10,
};

const SW_ERROR =
  'tab fetch failed: Error: Could not establish connection. Receiving end does not exist.';

function installRecordingHost(server: FetchproxyServer) {
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
    requests: (): InnerRequest[] =>
      sent.filter((f): f is InnerRequest => f.type === 'request'),
    reply: (frame: InnerFrame) => {
      (server as unknown as { onInner(i: InnerFrame): void }).onInner(frame);
    },
  };
}

const init = (method: string) => ({
  url: 'https://example.com/book',
  method,
  tabUrl: 'https://example.com/',
});

describe('B-BUG-1: timeout retry is limited to idempotent requests', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'post']) {
    it(`fetch() sends a timed-out ${method} exactly once`, async () => {
      const s = new FetchproxyServer(baseOpts);
      const host = installRecordingHost(s);
      const pending = s.fetch(init(method));
      await vi.advanceTimersByTimeAsync(100); // first attempt times out
      await vi.advanceTimersByTimeAsync(500); // well past the revive delay
      const result = await pending;
      expect(host.requests().length).toBe(1);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.kind).toBe('timeout');
        expect(result.retryAttempted).toBe(false);
      }
      // The timeout is still the eviction signal, even when not retried.
      expect(s.bridgeHealth().swEviction.lastEvictionDetectedAt).not.toBeNull();
      expect(s.bridgeHealth().swEviction.lazyReviveAttempts).toBe(0);
      await s.close();
    });
  }

  for (const method of ['GET', 'HEAD', 'OPTIONS', 'get']) {
    it(`fetch() still retries a timed-out ${method}`, async () => {
      const s = new FetchproxyServer(baseOpts);
      const host = installRecordingHost(s);
      const pending = s.fetch(init(method));
      await vi.advanceTimersByTimeAsync(100);
      await vi.advanceTimersByTimeAsync(10);
      expect(host.requests().length).toBe(2);
      await vi.advanceTimersByTimeAsync(100);
      await pending;
      await s.close();
    });
  }

  it('fetch() retries a timed-out POST when the caller opts in with retryOnTimeout', async () => {
    const s = new FetchproxyServer(baseOpts);
    const host = installRecordingHost(s);
    const pending = s.fetch(init('POST'), { retryOnTimeout: true });
    await vi.advanceTimersByTimeAsync(100);
    await vi.advanceTimersByTimeAsync(10);
    expect(host.requests().length).toBe(2);
    await vi.advanceTimersByTimeAsync(100);
    const result = await pending;
    expect(!result.ok && result.retryAttempted).toBe(true);
    await s.close();
  });

  it('fetch() does not retry a timed-out GET when the caller opts out with retryOnTimeout: false', async () => {
    const s = new FetchproxyServer(baseOpts);
    const host = installRecordingHost(s);
    const pending = s.fetch(init('GET'), { retryOnTimeout: false });
    await vi.advanceTimersByTimeAsync(100);
    await vi.advanceTimersByTimeAsync(500);
    await pending;
    expect(host.requests().length).toBe(1);
    await s.close();
  });

  it('a POST that never reached a tab (content_script_unreachable) is still retried', async () => {
    const s = new FetchproxyServer(baseOpts);
    const host = installRecordingHost(s);
    const pending = s.fetch(init('POST'));
    await vi.advanceTimersByTimeAsync(0);
    host.reply({ type: 'response', id: host.requests()[0]!.id, ok: false, op: 'fetch', error: SW_ERROR });
    await vi.advanceTimersByTimeAsync(10);
    expect(host.requests().length).toBe(2);
    host.reply({
      type: 'response',
      id: host.requests()[1]!.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/book',
      body: 'booked',
    });
    const result = await pending;
    expect(result.ok).toBe(true);
    await s.close();
  });

  it('post() sends once and throws a FetchproxyTimeoutError marked not retry-safe', async () => {
    const s = new FetchproxyServer(baseOpts);
    const host = installRecordingHost(s);
    const pending = s.post('/book', '{}').catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(100);
    await vi.advanceTimersByTimeAsync(500);
    const err = await pending;
    expect(host.requests().length).toBe(1);
    expect(err).toBeInstanceOf(FetchproxyTimeoutError);
    expect((err as FetchproxyTimeoutError).retrySafe).toBe(false);
    await s.close();
  });

  it('request() forwards retryOnTimeout so a known-idempotent write can opt in', async () => {
    const s = new FetchproxyServer(baseOpts);
    const host = installRecordingHost(s);
    const pending = s
      .request('PUT', '/book', { body: '{}', retryOnTimeout: true })
      .catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(100);
    await vi.advanceTimersByTimeAsync(10);
    expect(host.requests().length).toBe(2);
    await vi.advanceTimersByTimeAsync(100);
    const err = await pending;
    expect((err as FetchproxyTimeoutError).retrySafe).toBe(true);
    await s.close();
  });

  it('get() timeouts are marked retry-safe', async () => {
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 0 });
    installRecordingHost(s);
    const pending = s.get('/x').catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(100);
    const err = await pending;
    expect((err as FetchproxyTimeoutError).retrySafe).toBe(true);
    await s.close();
  });
});

describe('B-BUG-1: retryOnceOnTimeout does not re-send a non-idempotent request', () => {
  it('does not retry a timeout marked retrySafe: false', async () => {
    const fn = vi.fn(async () => {
      throw new FetchproxyTimeoutError({ url: 'u', timeoutMs: 1, retrySafe: false });
    });
    await expect(retryOnceOnTimeout(fn)).rejects.toBeInstanceOf(FetchproxyTimeoutError);
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('still retries a retry-safe timeout once (default for errors built without the flag)', async () => {
    let n = 0;
    const fn = vi.fn(async () => {
      if (n++ === 0) throw new FetchproxyTimeoutError({ url: 'u', timeoutMs: 1 });
      return 'ok';
    });
    await expect(retryOnceOnTimeout(fn)).resolves.toBe('ok');
    expect(fn).toHaveBeenCalledTimes(2);
  });
});
