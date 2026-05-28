import { describe, it, expect } from 'vitest';
import { FetchproxyServer } from '../src/index.js';
import type { InnerFrame, InnerRequest } from '@fetchproxy/protocol';

// Issue #67 — server-side proactive keepalive ping. The 0.8.0
// alarms-based keepalive in extension-core fires only when the SW is
// already alive; under real usage the SW still gets evicted mid-MCP-
// session. A server-initiated ping while the MCP is active is the
// belt-and-braces fix.

const baseOpts = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
  capabilities: ['fetch' as const],
};

interface RecordingHost {
  sent: InnerFrame[];
  lastRequest: () => InnerRequest | null;
  reply: (frame: InnerFrame) => void;
}

// Test-only fake host: like installFakeHost in helpers/, but captures
// EVERY outbound inner frame so keepalive pings are observable.
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

async function doOneFetch(server: FetchproxyServer, host: RecordingHost): Promise<void> {
  const pending = server.fetch({
    url: 'https://example.com/x',
    method: 'GET',
    tabUrl: 'https://example.com/',
  });
  // Let the request frame land in `sent`.
  await Promise.resolve();
  const req = host.lastRequest();
  if (!req) throw new Error('test setup: no request captured');
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
}

const pings = (host: RecordingHost): InnerFrame[] =>
  host.sent.filter((f) => f.type === 'ping');

describe('keepAliveIntervalMs — server-side proactive keepalive (#67)', () => {
  it('does NOT send ping frames when keepAliveIntervalMs is unset (back-compat)', async () => {
    const s = new FetchproxyServer(baseOpts);
    const host = installRecordingHost(s);
    await doOneFetch(s, host);
    // Wait long enough that *if* a keepalive were running it would have
    // fired several times.
    await new Promise((r) => setTimeout(r, 200));
    expect(pings(host).length).toBe(0);
    await s.close();
  });

  it('sends ping frames every keepAliveIntervalMs once activity is observed', async () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      keepAliveIntervalMs: 50,
      keepAliveMaxIdleMs: 5_000,
    });
    const host = installRecordingHost(s);
    await doOneFetch(s, host);
    // Sleep ~175ms — at 50ms interval that's 3 ticks. Use >=2 to stay
    // stable on slow CI runners.
    await new Promise((r) => setTimeout(r, 175));
    expect(pings(host).length).toBeGreaterThanOrEqual(2);
    await s.close();
  });

  it('stops the ping interval once keepAliveMaxIdleMs has elapsed without activity', async () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      keepAliveIntervalMs: 30,
      keepAliveMaxIdleMs: 100,
    });
    const host = installRecordingHost(s);
    await doOneFetch(s, host);
    // Wait past keepAliveMaxIdleMs. The ping interval should self-quiesce.
    await new Promise((r) => setTimeout(r, 250));
    const pingsBefore = pings(host).length;
    // Pause further, no new activity recorded. New pings should not arrive.
    await new Promise((r) => setTimeout(r, 200));
    const pingsAfter = pings(host).length;
    // Allow at most one extra ping that may have been in flight when
    // the gate flipped (timer fired before the idle check ran).
    expect(pingsAfter - pingsBefore).toBeLessThanOrEqual(1);
    await s.close();
  });

  it('close() stops the ping interval', async () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      keepAliveIntervalMs: 30,
      keepAliveMaxIdleMs: 5_000,
    });
    const host = installRecordingHost(s);
    await doOneFetch(s, host);
    await new Promise((r) => setTimeout(r, 100));
    await s.close();
    const pingsAtClose = pings(host).length;
    await new Promise((r) => setTimeout(r, 150));
    expect(pings(host).length).toBe(pingsAtClose);
  });

  it('markActive() bumps the idle gate so pings keep firing without a fetch', async () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      keepAliveIntervalMs: 30,
      keepAliveMaxIdleMs: 100,
    });
    const host = installRecordingHost(s);
    await doOneFetch(s, host);
    // Re-bump activity right before the idle window closes.
    await new Promise((r) => setTimeout(r, 75));
    s.markActive();
    await new Promise((r) => setTimeout(r, 90));
    // Without markActive the gate would close at ~100ms; with it the
    // gate stays open through ~165ms so >=3 ticks of 30ms can fire.
    expect(pings(host).length).toBeGreaterThanOrEqual(3);
    await s.close();
  });

  it('markActive() is a no-op when keepAliveIntervalMs is unset', async () => {
    const s = new FetchproxyServer(baseOpts);
    const host = installRecordingHost(s);
    s.markActive();
    await new Promise((r) => setTimeout(r, 150));
    expect(pings(host).length).toBe(0);
    await s.close();
  });
});
