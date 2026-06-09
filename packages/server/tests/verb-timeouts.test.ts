import { describe, it, expect, afterEach, vi, beforeEach } from 'vitest';
import type { InnerFrame } from '@fetchproxy/protocol';
import { FetchproxyServer, FetchproxyTimeoutError } from '../src/index.js';

/**
 * FP-B2: only `fetch()` was bounded by `fetchTimeoutMs`. Every other verb
 * (`readCookies`, `readLocalStorage`/`readSessionStorage`, `captureRequestHeader`,
 * `captureRedirect`, `download`, `readIndexedDb`) awaited its `pending` reply
 * with NO timeout race — a wedged extension hung the tool call until the host
 * killed it.
 *
 * These tests drive each verb through the public API with a fake host whose
 * `sendOwnInner` resolves (the frame "reaches the bridge") but never replies.
 * Each verb must reject with a `FetchproxyTimeoutError` after `fetchTimeoutMs`
 * AND drop its pending-map entry so a late bridge reply can't leak / crash.
 */
describe('per-verb response timeouts (FP-B2)', () => {
  const servers: FetchproxyServer[] = [];

  type Internal = {
    hostHandle: unknown;
    role: 'host' | 'peer' | null;
    pendingReadCookies: Map<number, unknown>;
    pendingStorage: Map<number, unknown>;
    pendingCapture: Map<number, unknown>;
    pendingRedirect: Map<number, unknown>;
    pendingDownload: Map<number, unknown>;
    pendingIdb: Map<number, unknown>;
    ensureConnected(): Promise<void>;
    throwIfPendingPair(): void;
  };

  function makeServer(timeoutMs: number): {
    server: FetchproxyServer;
    internal: Internal;
  } {
    const server = new FetchproxyServer({
      serverName: 'opentable-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      capabilities: [
        'fetch',
        'read_cookies',
        'read_local_storage',
        'read_session_storage',
        'capture_request_header',
        'capture_redirect',
        'download',
        'read_indexed_db',
      ],
      cookieKeys: ['sid'],
      localStorageKeys: ['tok'],
      sessionStorageKeys: ['tok'],
      captureHeaders: [{ host: 'example.com', headerName: 'authorization' }],
      indexedDbScopes: [
        { origin: 'https://example.com', database: 'db', store: 'kv', keys: ['k'] },
      ],
      fetchTimeoutMs: timeoutMs,
    });
    servers.push(server);
    const internal = server as unknown as Internal;
    // Fake host: the send succeeds (frame "lands"), but no reply ever arrives.
    internal.hostHandle = {
      close: async () => undefined,
      sendOwnInner: async () => undefined,
      onOwnInner: () => undefined,
      onExtensionDisconnect: () => undefined,
      onPendingPair: () => undefined,
      pendingPairCode: () => null,
    };
    internal.role = 'host';
    // Skip the real lazy-connect / pair-pending gates — we're exercising the
    // post-send wait, not the connection handshake.
    internal.ensureConnected = async () => undefined;
    internal.throwIfPendingPair = () => undefined;
    return { server, internal };
  }

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(async () => {
    vi.useRealTimers();
    await Promise.all(servers.splice(0).map((s) => s.close()));
  });

  async function expectTimeout(
    p: Promise<unknown>,
    timeoutMs: number,
    pendingMap: () => Map<number, unknown>,
  ): Promise<void> {
    // Swallow the eventual rejection so advancing timers doesn't surface an
    // unhandled rejection before we assert on it.
    const settled = p.then(
      () => ({ ok: true as const }),
      (err: unknown) => ({ ok: false as const, err }),
    );
    await vi.advanceTimersByTimeAsync(timeoutMs + 5);
    const res = await settled;
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.err).toBeInstanceOf(FetchproxyTimeoutError);
    }
    // Pending entry must be cleaned up so a late reply can't leak.
    expect(pendingMap().size).toBe(0);
  }

  it('readCookies times out and cleans up its pending entry', async () => {
    const { server, internal } = makeServer(1000);
    await expectTimeout(
      server.readCookies({ keys: ['sid'] }),
      1000,
      () => internal.pendingReadCookies,
    );
  });

  it('readLocalStorage times out and cleans up its pending entry', async () => {
    const { server, internal } = makeServer(1000);
    await expectTimeout(
      server.readLocalStorage({ keys: ['tok'] }),
      1000,
      () => internal.pendingStorage,
    );
  });

  it('readSessionStorage times out and cleans up its pending entry', async () => {
    const { server, internal } = makeServer(1000);
    await expectTimeout(
      server.readSessionStorage({ keys: ['tok'] }),
      1000,
      () => internal.pendingStorage,
    );
  });

  it('captureRequestHeader times out and cleans up its pending entry', async () => {
    const { server, internal } = makeServer(1000);
    await expectTimeout(
      server.captureRequestHeader({ host: 'example.com', headerName: 'authorization' }),
      1000,
      () => internal.pendingCapture,
    );
  });

  it('captureRedirect times out and cleans up its pending entry', async () => {
    const { server, internal } = makeServer(1000);
    await expectTimeout(
      server.captureRedirect({ host: 'example.com' }),
      1000,
      () => internal.pendingRedirect,
    );
  });

  it('download times out and cleans up its pending entry', async () => {
    const { server, internal } = makeServer(1000);
    await expectTimeout(
      server.download({ url: 'https://example.com/file' }),
      1000,
      () => internal.pendingDownload,
    );
  });

  it('readIndexedDb times out and cleans up its pending entry', async () => {
    const { server, internal } = makeServer(1000);
    await expectTimeout(
      server.readIndexedDb({ database: 'db', store: 'kv', keys: ['k'] }),
      1000,
      () => internal.pendingIdb,
    );
  });

  it('does not time out when fetchTimeoutMs is 0 (opt-out)', async () => {
    const { server, internal } = makeServer(0);
    let settled = false;
    server.readCookies({ keys: ['sid'] }).then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    await vi.advanceTimersByTimeAsync(60_000);
    expect(settled).toBe(false);
    expect(internal.pendingReadCookies.size).toBe(1);
  });

  // Avoid leaving the unsettled never-replied promise dangling between the
  // opt-out test and teardown: the pending map is cleared on close().
  it('clears pending maps on close (no leak across opt-out)', async () => {
    const { server, internal } = makeServer(0);
    void server.readCookies({ keys: ['sid'] }).catch(() => undefined);
    await vi.advanceTimersByTimeAsync(10);
    expect(internal.pendingReadCookies.size).toBe(1);
    vi.useRealTimers();
    await server.close();
    expect(internal.pendingReadCookies.size).toBe(0);
  });
});
