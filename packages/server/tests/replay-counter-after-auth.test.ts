import { describe, it, expect, afterEach, vi, type MockInstance } from 'vitest';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sealInnerFrame, type InnerFrame } from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { SessionState } from '../src/session.js';
import { connectMockExtension } from './helpers/mock-extension.js';
import { linkedPeer, type FakeConcentrator } from './helpers/concentrator.js';
import type { ExtensionPin, ExtensionTrustPort } from '../src/extension-trust.js';

/**
 * The replay counter is advanced by a frame that AUTHENTICATED, never by one
 * that merely arrived.
 *
 * `SessionState.acceptInboundSeq` used to be called before the AES-GCM open,
 * so anything that could put a frame on the socket could set `lastInbound` to
 * a number of its choosing — and every genuine frame after it, carrying a
 * lower seq, was then silently dropped as a replay. One unauthenticated frame
 * with `seq: 2 ** 40` wedged the session for good on the peer and the
 * extension; on the host it tore the socket down and took the in-flight
 * genuine frames with it. The gate is now a claim (`claimInboundSeq`) taken
 * before the open and an answer recorded after it — `commitInboundSeq` when
 * the frame authenticated, `releaseInboundSeq` when it did not, which is what
 * leaves the counter where it was.
 */

const FORGED_SEQ = 9;

/** A frame that passes `validateFrame` and fails AES-GCM authentication. */
function forgedFrame(mcpId: string, seq: number): Record<string, unknown> {
  return {
    type: 'frame',
    mcpId,
    seq,
    iv: Buffer.from(new Uint8Array(12).fill(7)).toString('base64'),
    ciphertext: Buffer.from(new Uint8Array(48).fill(9)).toString('base64'),
  };
}

function blankTrust(): ExtensionTrustPort {
  let pin: ExtensionPin | null = null;
  return {
    allowNew: false,
    read: async () => pin,
    write: async (next) => {
      pin = next;
    },
  };
}

describe('replay counter advances only after a frame authenticates', () => {
  let host: HostHandle | null = null;
  let peer: InternalPeerHandle | null = null;
  let rig: FakeConcentrator | null = null;

  afterEach(async () => {
    vi.restoreAllMocks();
    if (host) await host.close();
    host = null;
    if (peer) peer.close();
    peer = null;
    if (rig) {
      await rig.close();
      rig = null;
    }
  });

  it('host: a forged frame does not reject the genuine frame behind it', async () => {
    // The host tears the socket down over a frame it cannot open, so the
    // window this bug lives in is the frames already in flight behind the
    // forged one: the counter used to move the instant the forged frame was
    // READ, which rejected every one of them before the teardown even ran.
    // Both frames therefore go out in a single TCP write (see the cork
    // below), so the host reads them in one pass of the WS receiver.
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});

    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-replay-host-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
    const mcpId = 'opentable-mcp:0.9.1:abc1234567890def';

    host = await startHost({
      httpServer: el.server,
      ownIdentity: identity,
      ownMcpId: mcpId,
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });

    const ext = await connectMockExtension(port);
    const sessionKey = await ext.completeHandshake(mcpId);
    await vi.waitFor(() => expect(host!.sessionLinked()).toBe(true));

    const received: InnerFrame[] = [];
    host.onOwnInner((inner) => received.push(inner));

    const genuine = await sealInnerFrame(sessionKey, mcpId, 1, { type: 'pong' }, 'e2s');
    // One write, so both frames reach the host's receiver in the same pass
    // and the second is dispatched while the first is still awaiting its
    // (failing) decrypt. Without the cork the two could land in separate
    // reads, and the teardown would beat the genuine frame for reasons that
    // have nothing to do with the counter.
    const sock = (ext.ws as unknown as { _socket: { cork(): void; uncork(): void } })._socket;
    sock.cork();
    ext.ws.send(JSON.stringify(forgedFrame(mcpId, FORGED_SEQ)));
    ext.ws.send(JSON.stringify(genuine));
    sock.uncork();

    await vi.waitFor(() => expect(received).toHaveLength(1));
    expect(received[0]).toMatchObject({ type: 'pong' });
    // And the forged frame was still refused — this is not the open getting
    // laxer, only the counter getting later.
    expect(errors).toHaveBeenCalled();
    ext.close();
  });

  it('peer: a forged frame leaves the counter where the last genuine one put it', async () => {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-replay-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
    const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';

    // 3.0.0: the full v4 handshake. The key cannot be reached any other way.
    const linked = await linkedPeer({
      mcpId,
      identity,
      startPeer: startPeer as unknown as Parameters<typeof linkedPeer>[0]['startPeer'],
    });
    rig = linked.rig;
    peer = linked.peer as unknown as InternalPeerHandle;
    const sessionKey = linked.sessionKey;
    const hostWs = await linked.rig.socket();

    const received: InnerFrame[] = [];
    peer.onInner((inner) => received.push(inner));

    hostWs.send(JSON.stringify(forgedFrame(mcpId, FORGED_SEQ)));
    // The peer drops a frame it cannot open silently and keeps the socket, so
    // there is nothing to wait FOR — give the drop a turn of the loop, then
    // send the genuine frame whose seq the forged one would have swallowed.
    await new Promise((r) => setTimeout(r, 20));
    hostWs.send(
      JSON.stringify(await sealInnerFrame(sessionKey, mcpId, 1, { type: 'pong' }, 'e2s')),
    );

    await vi.waitFor(() => expect(received).toHaveLength(1));
    expect(received[0]).toMatchObject({ type: 'pong' });

    // The counter DID move for the frame that authenticated: replaying it is
    // still refused.
    hostWs.send(
      JSON.stringify(await sealInnerFrame(sessionKey, mcpId, 1, { type: 'pong' }, 'e2s')),
    );
    await new Promise((r) => setTimeout(r, 20));
    expect(received).toHaveLength(1);
  });

  // A claim refused because too many are outstanding is not a replay, and the
  // log is the only place anyone can tell the two apart: both drop the frame
  // unread, but one is the gate doing its job and the other is a flood (or
  // claims leaking). Forcing the verdict through the prototype is the honest
  // way to reach it — genuinely holding 1024 claims open means 1024 frames
  // parked mid-decrypt at once.
  const saturated = (calls: unknown[][]) =>
    calls.filter((c) => /saturat/i.test(String(c[0])));

  /**
   * Latched per session (#376): a run of saturated refusals logs ONCE, on the
   * transition into saturation — a line per dropped frame turned a flood into
   * a log flood. The next `'ok'` claim re-arms it, and the one saturation after
   * that logs again. A replay neither logs nor touches the latch.
   */
  async function expectSaturationLatched(opts: {
    claim: MockInstance<SessionState['claimInboundSeq']>;
    warns: MockInstance<Console['warn']>;
    send: (seq: number) => Promise<void>;
    received: InnerFrame[];
  }): Promise<void> {
    const { claim, warns, send, received } = opts;
    const settle = async (calls: number) => {
      await vi.waitFor(() => expect(claim).toHaveBeenCalledTimes(calls));
      await new Promise((r) => setTimeout(r, 20));
    };
    let seq = 0;
    let calls = 0;
    const next = async (verdict?: 'replay' | 'saturated') => {
      if (verdict) claim.mockReturnValueOnce(verdict);
      seq += 1;
      calls += 1;
      await send(seq);
      await settle(calls);
    };

    await next('replay');
    expect(saturated(warns.mock.calls)).toHaveLength(0);

    for (let i = 0; i < 5; i += 1) await next('saturated');
    expect(saturated(warns.mock.calls)).toHaveLength(1);
    expect(String(saturated(warns.mock.calls)[0]![0])).toContain('opentable-mcp');
    expect(received).toHaveLength(0);

    // The set drained: the next frame claims for real and is delivered.
    await next();
    expect(received).toHaveLength(1);

    for (let i = 0; i < 3; i += 1) await next('saturated');
    expect(saturated(warns.mock.calls)).toHaveLength(2);

    await next('replay');
    expect(saturated(warns.mock.calls)).toHaveLength(2);
  }

  it('host: a saturated claim is logged, and a replay is not logged as one', async () => {
    const warns = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-saturated-host-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
    const mcpId = 'opentable-mcp:0.9.1:abc1234567890def';
    host = await startHost({
      httpServer: el.server,
      ownIdentity: identity,
      ownMcpId: mcpId,
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });
    const ext = await connectMockExtension(port);
    const sessionKey = await ext.completeHandshake(mcpId);
    await vi.waitFor(() => expect(host!.sessionLinked()).toBe(true));
    const received: InnerFrame[] = [];
    host.onOwnInner((inner) => received.push(inner));

    await expectSaturationLatched({
      claim: vi.spyOn(SessionState.prototype, 'claimInboundSeq'),
      warns,
      received,
      send: async (seq) =>
        ext.ws.send(
          JSON.stringify(await sealInnerFrame(sessionKey, mcpId, seq, { type: 'pong' }, 'e2s')),
        ),
    });
    ext.close();
  });

  it('peer: a saturated claim is logged, and a replay is not logged as one', async () => {
    const warns = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const idDir = mkdtempSync(join(tmpdir(), 'fp-saturated-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
    const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';
    const linked = await linkedPeer({
      mcpId,
      identity,
      startPeer: startPeer as unknown as Parameters<typeof linkedPeer>[0]['startPeer'],
    });
    rig = linked.rig;
    peer = linked.peer as unknown as InternalPeerHandle;
    const sessionKey = linked.sessionKey;
    const hostWs = await linked.rig.socket();
    const received: InnerFrame[] = [];
    peer.onInner((inner) => received.push(inner));

    await expectSaturationLatched({
      claim: vi.spyOn(SessionState.prototype, 'claimInboundSeq'),
      warns,
      received,
      send: async (seq) =>
        hostWs.send(
          JSON.stringify(await sealInnerFrame(sessionKey, mcpId, seq, { type: 'pong' }, 'e2s')),
        ),
    });
  });
});
