import { describe, it, expect, afterEach } from 'vitest';
import type { InnerFrame } from '@fetchproxy/protocol';
import { FetchproxyServer } from '../src/index.js';
import { FetchproxySessionNotReadyError } from '../src/session-ready.js';

/**
 * Regression for the pending-map leak: every verb registers its reply resolver
 * (`this.pending*`) *before* sending the frame, so when the send throws — most
 * commonly now the bounded `FetchproxySessionNotReadyError` — no reply will ever
 * arrive and the resolver must be dropped rather than left until `close()`.
 * `sendInnerFrame` owns that cleanup; here we drive it directly through the same
 * `as unknown` seam the fake-host helper uses.
 */
describe('sendInnerFrame pending-map cleanup', () => {
  const servers: FetchproxyServer[] = [];
  afterEach(async () => {
    await Promise.all(servers.splice(0).map((s) => s.close()));
  });

  type Internal = {
    hostHandle: unknown;
    pending: Map<number, unknown>;
    pendingReadCookies: Map<number, unknown>;
    pendingStorage: Map<number, unknown>;
    sendInnerFrame(inner: InnerFrame): Promise<void>;
  };

  function makeServer(): { server: FetchproxyServer; internal: Internal } {
    const server = new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
    });
    servers.push(server);
    const internal = server as unknown as Internal;
    // Fake host whose send rejects as if the session never became ready.
    internal.hostHandle = {
      close: async () => undefined,
      sendOwnInner: async () => {
        throw new FetchproxySessionNotReadyError({ mcpId: 'test-mcp', pairCode: null });
      },
      onOwnInner: () => undefined,
      onExtensionDisconnect: () => undefined,
      onPendingPair: () => undefined,
      pendingPairCode: () => null,
    };
    return { server, internal };
  }

  it('drops the just-registered resolver (and rethrows) when the send throws', async () => {
    const { internal } = makeServer();
    const id = 12_345;
    // Mimic a verb registering its reply resolver before the send.
    internal.pendingReadCookies.set(id, () => {});

    await expect(
      internal.sendInnerFrame({
        type: 'request',
        id,
        op: 'read_cookies',
        init: { tabUrl: 'https://example.com/' },
      } as InnerFrame),
    ).rejects.toBeInstanceOf(FetchproxySessionNotReadyError);

    expect(internal.pendingReadCookies.has(id)).toBe(false);
  });

  it('clears the id from whichever op map holds it (ids are unique across maps)', async () => {
    const { internal } = makeServer();
    const id = 999;
    internal.pending.set(id, () => {});
    internal.pendingStorage.set(id, () => {});

    await expect(
      internal.sendInnerFrame({
        type: 'request',
        id,
        op: 'fetch',
        init: { url: 'https://example.com/' },
      } as InnerFrame),
    ).rejects.toBeInstanceOf(FetchproxySessionNotReadyError);

    expect(internal.pending.has(id)).toBe(false);
    expect(internal.pendingStorage.has(id)).toBe(false);
  });
});
