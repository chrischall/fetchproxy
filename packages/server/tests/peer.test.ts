import { describe, it, expect, afterEach } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateFrame,
  ed25519Verify,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { loadOrCreateIdentity } from '../src/identity.js';

describe('peer client', () => {
  let wss: WebSocketServer | null = null;
  let peer: InternalPeerHandle | null = null;

  afterEach(async () => {
    if (peer) peer.close();
    peer = null;
    if (wss) {
      await new Promise<void>((r) => wss!.close(() => r()));
      wss = null;
    }
  });

  it('dials host and sends hello with valid signature', async () => {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);

    const port = 41200;
    wss = new WebSocketServer({ port });

    const helloPromise = new Promise<HelloFrameFromServer>((resolve) => {
      wss!.on('connection', (ws: WebSocket) => {
        ws.on('message', (data) => {
          const parsed = JSON.parse(data.toString());
          if (parsed.type === 'hello') {
            const frame = validateFrame(parsed);
            if (frame.type === 'hello' && frame.role === 'server') {
              resolve(frame);
            }
          }
        });
      });
    });

    peer = await startPeer({
      host: '127.0.0.1',
      port,
      identity,
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
    });

    const hello = await helloPromise;

    // Structural assertions
    expect(hello.role).toBe('server');
    expect(hello.mcpId).toBe('opentable-mcp:0.9.1:a3f7c91d2e8b4f56');
    expect(hello.serverName).toBe('opentable-mcp');
    expect(hello.version).toBe('0.9.1');
    expect(hello.domains).toEqual(['opentable.com']);

    // Identity pub keys round-trip from the identity file
    const identityX25519Pub = new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'));
    expect(Buffer.from(identityX25519Pub).equals(Buffer.from(identity.x25519Pub))).toBe(true);

    // sessionSig verifies against identity.ed25519Pub over (mcpId || sessionNonce)
    const sessionNonce = new Uint8Array(Buffer.from(hello.sessionNonce, 'base64'));
    const sessionSig = new Uint8Array(Buffer.from(hello.sessionSig, 'base64'));
    const sigMsg = new Uint8Array(hello.mcpId.length + sessionNonce.length);
    sigMsg.set(new TextEncoder().encode(hello.mcpId), 0);
    sigMsg.set(sessionNonce, hello.mcpId.length);
    const ok = await ed25519Verify(identity.ed25519Pub, sigMsg, sessionSig);
    expect(ok).toBe(true);
  });

  it('sendInner rejects if the host sends a malformed frame', async () => {
    // peer.ts:110 — catch-on-onMessage. When the host pushes something
    // unparseable (not JSON, or a frame validateFrame rejects), the
    // peer's session-derivation promise must reject so any waiting
    // sendInner doesn't hang forever. This is the cousin of the
    // "host closes" rejection — both unblock the awaiter.
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);

    const port = 41202;
    wss = new WebSocketServer({ port });
    wss.on('connection', (ws: WebSocket) => {
      ws.once('message', () => {
        // Receive the peer's hello, then push garbage that JSON.parse
        // would barely choke on (validateFrame definitely will).
        ws.send('this-is-not-json');
      });
    });

    peer = await startPeer({
      host: '127.0.0.1',
      port,
      identity,
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
    });

    await expect(peer.sendInner({ type: 'ping' })).rejects.toThrow();
  });

  it('sendInner rejects if the host WS closes before ready arrives', async () => {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);

    const port = 41201;
    wss = new WebSocketServer({ port });
    // Host that takes the hello and then immediately closes — never sends ready.
    wss.on('connection', (ws: WebSocket) => {
      ws.once('message', () => ws.close());
    });

    peer = await startPeer({
      host: '127.0.0.1',
      port,
      identity,
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
    });

    await expect(peer.sendInner({ type: 'ping' })).rejects.toThrow(
      /peer WS closed before ready/,
    );
  });

  it('fires onClose listeners when the host WS closes', async () => {
    // The peer needs to tell its owner (FetchproxyServer) when the host
    // vanished so the owner can tear down the stranded handle and re-elect.
    // peer.ts is intent-agnostic: it fires onClose on ANY ws close.
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);

    const port = 41203;
    wss = new WebSocketServer({ port });
    // Host accepts the hello, then closes — simulates the host dying.
    wss.on('connection', (ws: WebSocket) => {
      ws.once('message', () => ws.close());
    });

    peer = await startPeer({
      host: '127.0.0.1',
      port,
      identity,
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
    });

    const closed = new Promise<void>((resolve) => peer!.onClose(() => resolve()));
    await expect(closed).resolves.toBeUndefined();
  });
});
