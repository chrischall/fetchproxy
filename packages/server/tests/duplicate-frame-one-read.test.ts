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
import { listenEphemeral, loopbackWss } from './helpers/ephemeral-port.js';
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

    const dup = JSON.stringify(await sealInnerFrame(sessionKey, mcpId, 1, { type: 'pong' }));
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
    ext.ws.send(JSON.stringify(await sealInnerFrame(sessionKey, mcpId, 2, { type: 'pong' })));
    await vi.waitFor(() => expect(received).toHaveLength(2));
    ext.close();
  });

  it('peer: two copies of one frame in a single write are delivered once', async () => {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-dup-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
    const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';

    wss = loopbackWss();
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
    await peer.sendInner({ type: 'ping' });
    expect(sessionKey).not.toBeNull();

    const dup = JSON.stringify(await sealInnerFrame(sessionKey!, mcpId, 1, { type: 'pong' }));
    inOneWrite(hostWs!, () => {
      hostWs!.send(dup);
      hostWs!.send(dup);
    });

    await vi.waitFor(() => expect(received).toHaveLength(1));
    await new Promise((r) => setTimeout(r, 50));
    expect(received).toHaveLength(1);

    // A frame that FAILS authentication gives its claim back, so the seq it
    // named is still open to the genuine frame that carries it. This is the
    // property the split gate exists for, and the claim must not cost it.
    const warns = vi.spyOn(console, 'warn').mockImplementation(() => {});
    hostWs!.send(JSON.stringify(forgedFrame(mcpId, 7)));
    await new Promise((r) => setTimeout(r, 20));
    hostWs!.send(JSON.stringify(await sealInnerFrame(sessionKey!, mcpId, 7, { type: 'pong' })));
    await vi.waitFor(() => expect(received).toHaveLength(2));
    warns.mockRestore();
  });
});
