import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateFrame,
  ed25519Verify,
  generateX25519,
  ecdhX25519,
  hkdfSha256,
  aesGcmSeal,
  HKDF_SESSION_INFO,
  type HelloFrameFromServer,
  type ReadyFrame,
} from '@fetchproxy/protocol';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { listenEphemeral } from './helpers/ephemeral-port.js';

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

    wss = new WebSocketServer({ port: 0 });
    const port = await listenEphemeral(wss);

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

    wss = new WebSocketServer({ port: 0 });
    const port = await listenEphemeral(wss);
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

    wss = new WebSocketServer({ port: 0 });
    const port = await listenEphemeral(wss);
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

    wss = new WebSocketServer({ port: 0 });
    const port = await listenEphemeral(wss);
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

  it('routes a targeted ok:false through onInner for a frame that decrypts fine but fails validation — instead of silently dropping it or closing the connection', async () => {
    // Regression for the peer-side half of the "kill the whole bridge" bug
    // class: before this fix, peer.ts's openEncryptedFrame call had ONE
    // catch that treated a decrypt failure (stale key — genuinely nothing
    // recoverable) and a post-decrypt VALIDATION failure (e.g. the
    // download bytes:-1 class of bug — a real protocol bug from a source
    // decryption just proved is the CURRENT, legitimate host) identically:
    // silently dropped, with no diagnostic signal and no fast failure for
    // whichever pending call was awaiting that response's id. This test
    // drives a REAL handshake so the frame actually decrypts under the
    // correct session key, then sends a validation-failing payload and
    // asserts it surfaces as a targeted ok:false via onInner — and that a
    // subsequent valid frame still gets delivered normally afterward.
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-'));
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
        const parsed = JSON.parse(data.toString());
        const frame = validateFrame(parsed);
        if (frame.type !== 'hello' || frame.role !== 'server') return;

        // Real ECDH + HKDF derivation, mirroring the extension's side of
        // the handshake exactly (see integration/two-mcps.test.ts) — the
        // point of this test is that the frame DOES decrypt correctly.
        const identityX25519Pub = new Uint8Array(Buffer.from(frame.identityX25519Pub, 'base64'));
        const peerSessionNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));
        const ephemeral = await generateX25519();
        const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
        sessionKey = await hkdfSha256(shared, peerSessionNonce, enc.encode(HKDF_SESSION_INFO), 32);

        // peer.ts does not itself verify `sessionSig` cryptographically
        // (see peer.ts's ready handling) — only validateFrame's structural
        // base64 check applies, so a placeholder value is fine here.
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

    const received: unknown[] = [];
    peer.onInner((inner) => received.push(inner));

    // Confirms the session is established (sendInner awaits session-ready
    // internally) before we start sending frames the peer must decrypt.
    await peer.sendInner({ type: 'ping' });
    expect(sessionKey).not.toBeNull();

    // Send a frame that DECRYPTS FINE (real, current session key) but whose
    // plaintext fails schema validation — the download bytes:-1 class of
    // bug, reused here as a concrete, realistic example.
    const malformed = JSON.stringify({
      type: 'response',
      id: 77,
      ok: true,
      op: 'download',
      value: { path: '/tmp/streamed.bin', bytes: -1 },
    });
    const iv1 = new Uint8Array(12).fill(1);
    const ct1 = await aesGcmSeal(sessionKey!, iv1, enc.encode(malformed));
    hostWs!.send(
      JSON.stringify({
        type: 'frame',
        mcpId,
        seq: 1,
        iv: Buffer.from(iv1).toString('base64'),
        ciphertext: Buffer.from(ct1).toString('base64'),
      }),
    );

    await vi.waitFor(() => expect(received).toHaveLength(1));
    expect(received[0]).toMatchObject({ type: 'response', id: 77, ok: false });
    expect((received[0] as { error: string }).error).toContain('protocol validation');

    // The connection must still be alive: a subsequent VALID frame should
    // be delivered normally, proving this degraded gracefully rather than
    // tearing down the session.
    const iv2 = new Uint8Array(12).fill(2);
    const validInner = JSON.stringify({
      type: 'response',
      id: 88,
      ok: true,
      status: 200,
      url: 'https://opentable.com/x',
      body: 'still alive',
    });
    const ct2 = await aesGcmSeal(sessionKey!, iv2, enc.encode(validInner));
    hostWs!.send(
      JSON.stringify({
        type: 'frame',
        mcpId,
        seq: 2,
        iv: Buffer.from(iv2).toString('base64'),
        ciphertext: Buffer.from(ct2).toString('base64'),
      }),
    );

    await vi.waitFor(() => expect(received).toHaveLength(2));
    expect(received[1]).toMatchObject({ type: 'response', id: 88, ok: true, status: 200 });
  });
});
