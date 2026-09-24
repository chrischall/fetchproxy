import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { FetchproxyServer, FetchproxyTimeoutError, classifyRowError } from '../src/index.js';
import type { InnerFrame } from '@fetchproxy/protocol';

// Audit #928: B-BUG-1 stopped the library from re-sending a timed-out write,
// but the message still read "did not respond within Nms" — to the model
// reading a tool error that says "nothing happened, try again", so the POST
// was re-issued one layer up. A timeout that was deliberately NOT re-sent must
// say it may already have run, in the host-loss path's words.

const MAY_HAVE_RUN = /may already have run in the browser — check before retrying/;

const baseOpts = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
  capabilities: ['fetch' as const],
  fetchTimeoutMs: 100,
  bridgeReviveDelayMs: 10,
};

function installSilentHost(server: FetchproxyServer): void {
  const fakeHostHandle = {
    close: async () => undefined,
    sendOwnInner: async (_inner: InnerFrame): Promise<void> => undefined,
    onOwnInner: (_cb: (inner: InnerFrame) => void) => undefined,
    onExtensionDisconnect: (_cb: () => void) => undefined,
    onPendingPair: (_cb: (code: string) => void) => undefined,
    pendingPairCode: (): string | null => null,
    extensionConnected: () => true,
    sessionLinked: () => true,
  };
  (server as unknown as { hostHandle: typeof fakeHostHandle }).hostHandle = fakeHostHandle;
  (server as unknown as { role: 'host' | 'peer' | null }).role = 'host';
}

describe('FetchproxyTimeoutError wording for a request that was not re-sent', () => {
  it('says a retrySafe:false timeout may already have run and was not re-sent', () => {
    const err = new FetchproxyTimeoutError({ url: 'https://example.com/book', timeoutMs: 100, retrySafe: false });
    expect(err.message).toMatch(MAY_HAVE_RUN);
    expect(err.message).toMatch(/not re-sent/);
  });

  it('leaves a retry-safe timeout message alone', () => {
    const err = new FetchproxyTimeoutError({ url: 'https://example.com/x', timeoutMs: 100 });
    expect(err.message).not.toMatch(/may already have run/);
  });
});

describe('server timeout paths carry the wording', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('post() throws a timeout whose message warns it may already have run', async () => {
    const s = new FetchproxyServer(baseOpts);
    installSilentHost(s);
    const pending = s.post('/book', '{}').catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(600);
    const err = await pending;
    expect(err).toBeInstanceOf(FetchproxyTimeoutError);
    expect((err as Error).message).toMatch(MAY_HAVE_RUN);
    await s.close();
  });

  it('fetch() envelope for a timed-out POST warns it may already have run', async () => {
    const s = new FetchproxyServer(baseOpts);
    installSilentHost(s);
    const pending = s.fetch({ url: 'https://example.com/book', method: 'POST', tabUrl: 'https://example.com/' });
    await vi.advanceTimersByTimeAsync(600);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(MAY_HAVE_RUN);
    await s.close();
  });

  it('fetch() envelope for a timed-out GET does not', async () => {
    const s = new FetchproxyServer({ ...baseOpts, bridgeReviveDelayMs: 0 });
    installSilentHost(s);
    const pending = s.fetch({ url: 'https://example.com/x', method: 'GET', tabUrl: 'https://example.com/' });
    await vi.advanceTimersByTimeAsync(600);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).not.toMatch(/may already have run/);
    await s.close();
  });
});

describe('classifyRowError for a timeout that was not re-sent', () => {
  it('does not claim a retry happened and carries the may-have-run warning', () => {
    const err = new FetchproxyTimeoutError({ url: 'https://example.com/book', timeoutMs: 100, retrySafe: false });
    const out = classifyRowError(err);
    expect(out.kind).toBe('timeout');
    expect(out.message).not.toMatch(/after retry/);
    expect(out.message).toMatch(/not retried/);
    expect(out.message).toMatch(MAY_HAVE_RUN);
  });

  it('keeps the "after retry" wording for a retry-safe timeout', () => {
    const out = classifyRowError(new FetchproxyTimeoutError({ url: 'u', timeoutMs: 1 }));
    expect(out.message).toMatch(/^bridge timeout after retry: /);
  });
});
