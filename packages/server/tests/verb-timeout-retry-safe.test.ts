import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { FetchproxyServer, FetchproxyTimeoutError, retryOnceOnTimeout } from '../src/index.js';
import type { InnerFrame, InnerRequest } from '@fetchproxy/protocol';

// B-BUG-1 follow-up: the non-fetch verbs time out through `_withVerbTimeout`,
// whose FetchproxyTimeoutError used to default to `retrySafe: true`. Inside
// `retryOnceOnTimeout` a timed-out `download()` was therefore re-sent and
// saved a duplicate "file (1)". The verbs with a side effect — `download`,
// `writeCookies` — and `graphqlQuery` (a declared operation may be a
// mutation, and the server cannot see which) must be marked not retry-safe,
// matching what the host-loss resend (`isResendableRequest`) already decides.

const baseOpts = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
  capabilities: [
    'fetch' as const,
    'download' as const,
    'write_cookies' as const,
    'read_local_storage' as const,
    'graphql' as const,
  ],
  cookieKeys: ['sid'],
  localStorageKeys: ['token'],
  graphqlOps: [{ name: 'book', operationName: 'BookTable' }],
  fetchTimeoutMs: 100,
  verbDeadlineGraceMs: 0,
  bridgeReviveDelayMs: 0,
};

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
    requests: (): InnerRequest[] => sent.filter((f): f is InnerRequest => f.type === 'request'),
  };
}

async function timeoutOf(s: FetchproxyServer, call: () => Promise<unknown>): Promise<unknown> {
  const pending = call().catch((e: unknown) => e);
  await vi.advanceTimersByTimeAsync(1_000);
  return pending;
}

describe('non-fetch verb timeouts carry the right retrySafe', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('download() times out not retry-safe, and retryOnceOnTimeout sends it once', async () => {
    const s = new FetchproxyServer(baseOpts);
    const host = installRecordingHost(s);
    const err = await timeoutOf(s, () =>
      retryOnceOnTimeout(() => s.download({ url: 'https://example.com/f.pdf' })),
    );
    expect(err).toBeInstanceOf(FetchproxyTimeoutError);
    expect((err as FetchproxyTimeoutError).retrySafe).toBe(false);
    expect(host.requests().filter((r) => r.op === 'download')).toHaveLength(1);
    await s.close();
  });

  it('writeCookies() times out not retry-safe', async () => {
    const s = new FetchproxyServer(baseOpts);
    installRecordingHost(s);
    const err = await timeoutOf(s, () => s.writeCookies({ cookies: { sid: 'v' } }));
    expect(err).toBeInstanceOf(FetchproxyTimeoutError);
    expect((err as FetchproxyTimeoutError).retrySafe).toBe(false);
    await s.close();
  });

  it('graphqlQuery() times out not retry-safe by default (a declared op may be a mutation)', async () => {
    const s = new FetchproxyServer(baseOpts);
    const host = installRecordingHost(s);
    const err = await timeoutOf(s, () =>
      retryOnceOnTimeout(() => s.graphqlQuery({ name: 'book', variables: {} })),
    );
    expect(err).toBeInstanceOf(FetchproxyTimeoutError);
    expect((err as FetchproxyTimeoutError).retrySafe).toBe(false);
    expect(host.requests()).toHaveLength(1);
    await s.close();
  });

  it('graphqlQuery() is retry-safe when the caller declares the op a query with retryOnTimeout', async () => {
    const s = new FetchproxyServer(baseOpts);
    const host = installRecordingHost(s);
    const err = await timeoutOf(s, () =>
      retryOnceOnTimeout(() =>
        s.graphqlQuery({ name: 'book', variables: {}, retryOnTimeout: true }),
      ),
    );
    expect((err as FetchproxyTimeoutError).retrySafe).toBe(true);
    expect(host.requests()).toHaveLength(2);
    await s.close();
  });

  it('a read verb (readLocalStorage) stays retry-safe', async () => {
    const s = new FetchproxyServer(baseOpts);
    installRecordingHost(s);
    const err = await timeoutOf(s, () => s.readLocalStorage({ keys: ['token'] }));
    expect(err).toBeInstanceOf(FetchproxyTimeoutError);
    expect((err as FetchproxyTimeoutError).retrySafe).toBe(true);
    await s.close();
  });

  // The host-loss resend (B-BUG-6) makes the same call: a graphql op is
  // re-sent through a re-elected bridge only when the caller vouched for it.
  it('graphqlQuery() is only held for a host-loss resend when marked retryOnTimeout', async () => {
    const s = new FetchproxyServer(baseOpts);
    const host = installRecordingHost(s);
    const resendable = (s as unknown as { resendable: Map<number, InnerRequest> }).resendable;
    const a = s.graphqlQuery({ name: 'book', variables: {} }).catch(() => undefined);
    const b = s
      .graphqlQuery({ name: 'book', variables: {}, retryOnTimeout: true })
      .catch(() => undefined);
    await vi.advanceTimersByTimeAsync(0);
    const [first, second] = host.requests();
    expect(resendable.has(first!.id)).toBe(false);
    expect(resendable.has(second!.id)).toBe(true);
    await vi.advanceTimersByTimeAsync(1_000);
    await Promise.all([a, b]);
    await s.close();
  });
});
