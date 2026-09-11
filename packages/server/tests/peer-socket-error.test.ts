import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import {
  ecdhX25519,
  generateX25519,
  hkdfSha256,
  validateFrame,
  HKDF_SESSION_INFO,
  type ReadyFrame,
} from '@fetchproxy/protocol';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { listenEphemeral, loopbackWss } from './helpers/ephemeral-port.js';

/**
 * A peer's socket keeps a PERSISTENT 'error' listener once the handshake is
 * done.
 *
 * A socket error is an EventEmitter 'error': with no listener it is an
 * uncaught exception that takes the whole MCP process down. The only listener
 * the peer had was the `once('error', reject)` its handshake races against
 * 'open' — which the frame cap makes a live problem rather than a theoretical
 * one, since `ws` reports an oversize frame by emitting here
 * (WS_ERR_UNSUPPORTED_MESSAGE_LENGTH) before closing with 1009. The host could
 * therefore kill every peer by sending one big frame. host.ts has had the
 * listener since the cap landed; this is its mirror.
 *
 * TWO emits, because the old shape left the handshake's `once` attached: the
 * first error was swallowed into a reject of an already-settled promise and
 * the SECOND was the crash.
 */

describe('a peer survives a socket error after the handshake', () => {
  let peer: InternalPeerHandle | null = null;
  let wss: WebSocketServer | null = null;

  afterEach(async () => {
    vi.restoreAllMocks();
    if (peer) peer.close();
    peer = null;
    if (wss) {
      await new Promise<void>((r) => wss!.close(() => r()));
      wss = null;
    }
  });

  it('reports it and keeps running, rather than throwing out of the emitter', async () => {
    const warns = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-error-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
    const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';

    wss = loopbackWss();
    const port = await listenEphemeral(wss);
    const enc = new TextEncoder();

    wss.on('connection', (ws: WebSocket) => {
      ws.on('message', async (data) => {
        const frame = validateFrame(JSON.parse(data.toString()));
        if (frame.type !== 'hello' || frame.role !== 'server') return;
        const identityX25519Pub = new Uint8Array(Buffer.from(frame.identityX25519Pub, 'base64'));
        const peerNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));
        const ephemeral = await generateX25519();
        const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
        await hkdfSha256(shared, peerNonce, enc.encode(HKDF_SESSION_INFO), 32);
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
    await peer.session;

    const socketErrors = (): string[] =>
      warns.mock.calls.map((c) => String(c[0])).filter((m) => m.includes('peer: socket error'));

    expect(() =>
      peer!.ws.emit('error', new Error('WS_ERR_UNSUPPORTED_MESSAGE_LENGTH')),
    ).not.toThrow();
    expect(() => peer!.ws.emit('error', new Error('and again'))).not.toThrow();
    expect(socketErrors()).toHaveLength(2);
    expect(socketErrors()[0]).toContain('WS_ERR_UNSUPPORTED_MESSAGE_LENGTH');
  });
});
