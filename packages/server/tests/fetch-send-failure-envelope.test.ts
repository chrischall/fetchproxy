import { describe, it, expect, afterEach } from 'vitest';
import { FetchproxyServer } from '../src/index.js';
import { FetchproxySessionNotReadyError } from '../src/session-ready.js';

// B-BUG-13: fetch() documents a `{ok:false}` envelope for bridge failures, but
// a send that failed before reaching the bridge (session never confirmed, no
// extension connected) REJECTED instead, and bridgeHealth() never counted it.

const servers: FetchproxyServer[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

function makeServer(sendError: Error): FetchproxyServer {
  const server = new FetchproxyServer({
    serverName: 'test-mcp',
    version: '0.0.1',
    domains: ['example.com'],
    bridgeReviveDelayMs: 1,
  });
  servers.push(server);
  const internal = server as unknown as { hostHandle: unknown; role: string };
  internal.role = 'host';
  internal.hostHandle = {
    close: async () => undefined,
    sendOwnInner: async () => {
      throw sendError;
    },
    onOwnInner: () => undefined,
    onExtensionDisconnect: () => undefined,
    onPendingPair: () => undefined,
    pendingPairCode: () => null,
    extensionConnected: () => true,
    sessionLinked: () => false,
  };
  return server;
}

const init = { url: 'https://example.com/x', method: 'GET', tabUrl: 'https://example.com/' };

describe('B-BUG-13: fetch() send failures resolve to the ok:false envelope', () => {
  it('a session-not-ready send failure resolves with kind session_not_ready', async () => {
    const s = makeServer(new FetchproxySessionNotReadyError({ mcpId: 'test-mcp', pairCode: null }));
    const r = await s.fetch(init);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.kind).toBe('session_not_ready');
      expect(r.error).toMatch(/no confirmed browser session/);
      expect(r.retryAttempted).toBe(false);
    }
    const h = s.bridgeHealth();
    expect(h.consecutiveFailures).toBe(1);
    expect(h.lastFailureReason).toMatch(/^session_not_ready:/);
  });

  it('a "no extension connected" send failure also resolves rather than rejecting', async () => {
    const s = makeServer(new Error('host: no extension connected'));
    const r = await s.fetch(init);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.kind).toBe('session_not_ready');
  });

  it('request() still throws the original typed error', async () => {
    const err = new FetchproxySessionNotReadyError({ mcpId: 'test-mcp', pairCode: '1234-5678' });
    const s = makeServer(err);
    await expect(s.get('/x')).rejects.toBe(err);
  });
});
