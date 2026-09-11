import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ecdhX25519,
  generateX25519,
  hkdfSha256,
  sealInnerFrame,
  validateFrame,
  HKDF_SESSION_INFO,
  type InnerFrame,
  type ReadyFrame,
} from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { connectMockExtension } from './helpers/mock-extension.js';
import { listenEphemeral } from './helpers/ephemeral-port.js';
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
 * genuine frames with it. The gate is now a question (`isFreshInboundSeq`)
 * asked before the open and an answer (`commitInboundSeq`) recorded after it.
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
  let wss: WebSocketServer | null = null;

  afterEach(async () => {
    vi.restoreAllMocks();
    if (host) await host.close();
    host = null;
    if (peer) peer.close();
    peer = null;
    if (wss) {
      await new Promise<void>((r) => wss!.close(() => r()));
      wss = null;
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

    const genuine = await sealInnerFrame(sessionKey, mcpId, 1, { type: 'pong' });
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

    wss = new WebSocketServer({ port: 0 });
    const port = await listenEphemeral(wss);

    let hostWs: WebSocket | null = null;
    let sessionKey: Uint8Array | null = null;
    const enc = new TextEncoder();

    wss.on('connection', (ws: WebSocket) => {
      hostWs = ws;
      ws.on('message', async (data) => {
        const frame = validateFrame(JSON.parse(data.toString()));
        if (frame.type !== 'hello' || frame.role !== 'server') return;
        const identityX25519Pub = new Uint8Array(Buffer.from(frame.identityX25519Pub, 'base64'));
        const peerNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));
        const ephemeral = await generateX25519();
        const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
        sessionKey = await hkdfSha256(shared, peerNonce, enc.encode(HKDF_SESSION_INFO), 32);
        const ready: ReadyFrame = {
          type: 'ready',
          mcpId: frame.mcpId,
          extensionSessionPub: Buffer.from(ephemeral.publicKey).toString('base64'),
          sessionSig: Buffer.from('placeholder-sig').toString('base64'),
        };
        ws.send(JSON.stringify(ready));
      });
    });

    peer = await startPeer({
      host: '127.0.0.1',
      port,
      identity,
      mcpId,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
    });

    const received: InnerFrame[] = [];
    peer.onInner((inner) => received.push(inner));
    // sendInner awaits session-ready, so the key exists once this resolves.
    await peer.sendInner({ type: 'ping' });
    expect(sessionKey).not.toBeNull();

    hostWs!.send(JSON.stringify(forgedFrame(mcpId, FORGED_SEQ)));
    // The peer drops a frame it cannot open silently and keeps the socket, so
    // there is nothing to wait FOR — give the drop a turn of the loop, then
    // send the genuine frame whose seq the forged one would have swallowed.
    await new Promise((r) => setTimeout(r, 20));
    hostWs!.send(JSON.stringify(await sealInnerFrame(sessionKey!, mcpId, 1, { type: 'pong' })));

    await vi.waitFor(() => expect(received).toHaveLength(1));
    expect(received[0]).toMatchObject({ type: 'pong' });

    // The counter DID move for the frame that authenticated: replaying it is
    // still refused.
    hostWs!.send(JSON.stringify(await sealInnerFrame(sessionKey!, mcpId, 1, { type: 'pong' })));
    await new Promise((r) => setTimeout(r, 20));
    expect(received).toHaveLength(1);
  });
});
