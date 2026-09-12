import { describe, it, expect, afterEach, vi } from 'vitest';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sealInnerFrame, type InnerFrame } from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { connectMockExtension } from './helpers/mock-extension.js';
import { linkedPeer, type FakeConcentrator } from './helpers/concentrator.js';
import type { ExtensionPin, ExtensionTrustPort } from '../src/extension-trust.js';

/**
 * One seq, one frame — including when the two copies arrive in the SAME read.
 *
 * Splitting the inbound gate into a question (`isFreshInboundSeq`) asked
 * before the AES-GCM open and an answer (`commitInboundSeq`) recorded after it
 * put an `await` between the two. A question changes nothing, so two identical
 * frames read in one pass of the WS receiver both got their yes before either
 * could commit, and both were processed. Deterministic, not a race you need
 * luck for.
 *
 * The gate is now a synchronous CLAIM: the first frame takes the seq out of
 * circulation the instant it is read, so the duplicate behind it is refused
 * exactly as one arriving a second later would be. A claim is given back when
 * the frame does not authenticate, which is what keeps the property the
 * split existed for — the counter does not move for a frame that never
 * happened.
 *
 * The frames therefore go out in ONE write (see the cork below). A test that
 * awaits the first before delivering the second does not reproduce the bug and
 * would pass against the code this fixes.
 */

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

/** Write everything `send` does inside as ONE TCP write. */
function inOneWrite(ws: WebSocket, send: () => void): void {
  const sock = (ws as unknown as { _socket: { cork(): void; uncork(): void } })._socket;
  sock.cork();
  send();
  sock.uncork();
}

describe('a duplicate frame in one read is processed exactly once', () => {
  let host: HostHandle | null = null;
  let peer: InternalPeerHandle | null = null;
  let rig: FakeConcentrator | null = null;

  afterEach(async () => {
    vi.restoreAllMocks();
    if (host) await host.close();
    host = null;
    if (peer) peer.close();
    peer = null;
    if (rig) await rig.close();
    rig = null;
  });

  it('host: two copies of one frame in a single write are delivered once', async () => {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-dup-host-'));
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

    const dup = JSON.stringify(
      await sealInnerFrame(sessionKey, mcpId, 1, { type: 'pong' }, 'e2s'),
    );
    inOneWrite(ext.ws, () => {
      ext.ws.send(dup);
      ext.ws.send(dup);
    });

    await vi.waitFor(() => expect(received).toHaveLength(1));
    // The second copy is not merely late — give the loop room and prove it
    // never lands.
    await new Promise((r) => setTimeout(r, 50));
    expect(received).toHaveLength(1);

    // And the session is not wedged by its own claim: the next seq is taken.
    ext.ws.send(
      JSON.stringify(await sealInnerFrame(sessionKey, mcpId, 2, { type: 'pong' }, 'e2s')),
    );
    await vi.waitFor(() => expect(received).toHaveLength(2));
    ext.close();
  });

  it('peer: two copies of one frame in a single write are delivered once', async () => {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-dup-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
    const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';

    // 3.0.0: the full v4 handshake, because there is no shorter route to a
    // session key — a placeholder signature, no relayed extension hello and
    // an ECDH against the peer's long-term identity are all gone.
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

    const dup = JSON.stringify(
      await sealInnerFrame(sessionKey, mcpId, 1, { type: 'pong' }, 'e2s'),
    );
    inOneWrite(hostWs, () => {
      hostWs.send(dup);
      hostWs.send(dup);
    });

    await vi.waitFor(() => expect(received).toHaveLength(1));
    await new Promise((r) => setTimeout(r, 50));
    expect(received).toHaveLength(1);

    // A frame that FAILS authentication gives its claim back, so the seq it
    // named is still open to the genuine frame that carries it. This is the
    // property the split gate exists for, and the claim must not cost it.
    const warns = vi.spyOn(console, 'warn').mockImplementation(() => {});
    hostWs.send(JSON.stringify(forgedFrame(mcpId, 7)));
    await new Promise((r) => setTimeout(r, 20));
    hostWs.send(
      JSON.stringify(await sealInnerFrame(sessionKey, mcpId, 7, { type: 'pong' }, 'e2s')),
    );
    await vi.waitFor(() => expect(received).toHaveLength(2));
    warns.mockRestore();
  });
});
