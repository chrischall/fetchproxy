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

interface RecordingPeer extends RecordingHost {
  triggerRenegotiate: () => void;
}

// Peer-role analogue of installRecordingHost. The peer handle surface
// differs from the host handle (sendInner vs sendOwnInner, onRenegotiate
// instead of onExtensionDisconnect, no onOwnInner), so doConnect's peer
// branch wires the keepalive to a different lifecycle hook. We need a
// separate fake to exercise that branch — including the
// `onRenegotiate → stopKeepalive` wiring added alongside the keepalive.
//
// The fake reproduces doConnect's peer-branch wiring so a test simply
// observing `peer.triggerRenegotiate()` exercises the same code path
// real callers do (we can't run doConnect itself without a real WS).
function installRecordingPeer(server: FetchproxyServer): RecordingPeer {
  const sent: InnerFrame[] = [];
  let renegotiateCb: (() => void) | null = null;
  const fakePeerHandle = {
    close: () => undefined,
    sendInner: async (inner: InnerFrame): Promise<void> => {
      sent.push(inner);
    },
    onInner: (_cb: (inner: InnerFrame) => void) => undefined,
    onRenegotiate: (cb: () => void) => {
      renegotiateCb = cb;
    },
    onPendingPair: (_cb: (code: string) => void) => undefined,
    pendingPairCode: (): string | null => null,
  };
  (server as unknown as { peerHandle: typeof fakePeerHandle }).peerHandle = fakePeerHandle;
  (server as unknown as { role: 'host' | 'peer' | null }).role = 'peer';
  // Mirror doConnect's peer-branch wiring: onRenegotiate → stopKeepalive.
  // The production path runs this inside doConnect; the fake skips
  // doConnect entirely, so we have to re-create the subscription here for
  // the wiring to be exercised under test.
  fakePeerHandle.onRenegotiate(() => {
    (server as unknown as { stopKeepalive(): void }).stopKeepalive();
  });
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
    triggerRenegotiate: () => {
      if (renegotiateCb) renegotiateCb();
    },
  };
}

async function doOneFetch(
  server: FetchproxyServer,
  host: RecordingHost,
): Promise<void> {
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
  it('does NOT send ping frames when keepAliveIntervalMs: 0 (opt-out)', async () => {
    // 0.10.0+ (#72): the default flipped to 25_000; the only way to
    // disable the keep-alive is to pass `0` explicitly.
    const s = new FetchproxyServer({ ...baseOpts, keepAliveIntervalMs: 0 });
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

  it('markActive() is a no-op when keepAliveIntervalMs: 0 (opt-out)', async () => {
    // 0.10.0+ (#72): opt-out via 0, since 25_000 is the new default.
    const s = new FetchproxyServer({ ...baseOpts, keepAliveIntervalMs: 0 });
    const host = installRecordingHost(s);
    s.markActive();
    await new Promise((r) => setTimeout(r, 150));
    expect(pings(host).length).toBe(0);
    await s.close();
  });

  // Peer-role coverage: the host branch above exercises
  // `hostHandle.sendOwnInner` from `sendKeepalivePing`. The peer branch
  // calls `peerHandle.sendInner` instead, and doConnect wires
  // `onRenegotiate → stopKeepalive` (instead of the host's
  // `onExtensionDisconnect → stopKeepalive`). Both deserve their own tests.
  it('sends ping frames over peerHandle.sendInner when role is peer', async () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      keepAliveIntervalMs: 50,
      keepAliveMaxIdleMs: 5_000,
    });
    const peer = installRecordingPeer(s);
    await doOneFetch(s, peer);
    await new Promise((r) => setTimeout(r, 175));
    // Same threshold as the host-side equivalent — at 50ms interval over
    // ~175ms we expect >=2 ticks even on slow CI.
    expect(pings(peer).length).toBeGreaterThanOrEqual(2);
    await s.close();
  });

  it('peer onRenegotiate stops the ping interval', async () => {
    const s = new FetchproxyServer({
      ...baseOpts,
      keepAliveIntervalMs: 30,
      keepAliveMaxIdleMs: 5_000,
    });
    const peer = installRecordingPeer(s);
    await doOneFetch(s, peer);
    await new Promise((r) => setTimeout(r, 100));
    const pingsBefore = pings(peer).length;
    expect(pingsBefore).toBeGreaterThan(0);
    // Simulate the host telling us "session renegotiated" — the keepalive
    // should quiesce immediately because doConnect (mirrored by
    // installRecordingPeer) wired onRenegotiate → stopKeepalive.
    peer.triggerRenegotiate();
    await new Promise((r) => setTimeout(r, 150));
    const pingsAfter = pings(peer).length;
    // Allow one extra in-flight ping in the same tick the gate flipped.
    expect(pingsAfter - pingsBefore).toBeLessThanOrEqual(1);
    await s.close();
  });
});
