import { describe, it, expect, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateFrame,
  generateX25519,
  generateEd25519,
  ed25519Sign,
  readySignaturePayload,
  transcriptHash,
  fromB64,
  ecdhX25519,
  hkdfSha256,
  sealInnerFrame,
  openEncryptedFrame,
  pairTranscript,
  HKDF_SESSION_INFO,
  type HelloFrameFromExtension,
  type HelloFrameFromServer,
  type ReadyFrame,
} from '@fetchproxy/protocol';
import { FetchproxyServer } from '../../src/index.js';
import { getEphemeralPort } from '../helpers/ephemeral-port.js';

/**
 * 0.4.0 mutual-auth + read_indexed_db end-to-end. A mock extension
 * generates its own identity keys, signs the ReadyFrame, and the
 * host verifies the signature before deriving the session key. The
 * MCP then issues a `readIndexedDb` call against a declared scope,
 * which the mock extension answers with canned data.
 *
 * Second-half: a different extension identity attempting to connect
 * with a valid-shape ReadyFrame but an unknown identity-pair triggers
 * the joint pair code path (different pair code → user-detectable).
 */
describe('integration: 0.4.0 mutual auth + read_indexed_db', () => {
  let server: FetchproxyServer | null = null;
  let extWs: WebSocket | null = null;

  afterEach(async () => {
    if (extWs && extWs.readyState === extWs.OPEN) extWs.close();
    if (server) await server.close();
    server = null;
    extWs = null;
    await new Promise((r) => setTimeout(r, 50));
  });

  it('mutual auth succeeds; read_indexed_db round-trips canned data', async () => {
    const port = await getEphemeralPort();
    const idDir = mkdtempSync(join(tmpdir(), 'fp-int-mutual-'));

    let receivedPairCode: string | null = null;

    server = new FetchproxyServer({
      port,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
      capabilities: ['fetch', 'read_indexed_db'],
      indexedDbScopes: [
        {
          origin: 'https://resy.com',
          database: 'resy',
          store: 'auth',
          keys: ['userToken', 'userId'],
        },
      ],
      identityDir: idDir,
      onPairCode: (code) => {
        receivedPairCode = code;
      },
    });
    await server.listen();
    await server.connect();

    extWs = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((resolve, reject) => {
      extWs!.once('open', () => resolve());
      extWs!.once('error', reject);
    });

    // Mock extension: long-term identity + per-WS nonce.
    const extIdX = await generateX25519();
    const extIdEd = await generateEd25519();
    const extSessionNonce = new Uint8Array(32).fill(0xc1);

    let sessionKey: Uint8Array | null = null;
    let mcpId: string | null = null;
    let outboundSeq = 0;
    let mcpIdentityX25519Pub: Uint8Array | null = null;
    let helloFrame: HelloFrameFromServer | null = null;

    const ready = new Promise<void>((resolveReady) => {
      extWs!.on('message', async (data) => {
        try {
          const parsed = JSON.parse(data.toString());
          const frame = validateFrame(parsed);

          if (frame.type === 'hello' && frame.role === 'server') {
            helloFrame = frame;
            mcpIdentityX25519Pub = new Uint8Array(Buffer.from(frame.identityX25519Pub, 'base64'));
            const mcpSessionNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));
            const ephemeral = await generateX25519();
            // 3.0.0 (protocol 4): the ECDH is ephemeral x ephemeral — the MCP's
            // half is `sessionPub` on the hello, not its long-term identity key —
            // and the HKDF salt is the transcript over both nonces and both
            // ephemerals. Neither change is a compile error, so this mock is
            // what holds the server to them.
            const mcpSessionPub = fromB64(frame.sessionPub);
            const shared = await ecdhX25519(ephemeral.privateKey, mcpSessionPub);
            sessionKey = await hkdfSha256(
              shared,
              await transcriptHash(
                mcpSessionNonce,
                extSessionNonce,
                mcpSessionPub,
                ephemeral.publicKey,
              ),
              new TextEncoder().encode(HKDF_SESSION_INFO),
              32,
            );
            mcpId = frame.mcpId;
            const sig = await ed25519Sign(
              extIdEd.privateKey,
              readySignaturePayload(
                mcpSessionNonce,
                extSessionNonce,
                ephemeral.publicKey,
                mcpSessionPub,
              ),
            );
            const readyFrame: ReadyFrame = {
              type: 'ready',
              mcpId,
              extensionSessionPub: Buffer.from(ephemeral.publicKey).toString('base64'),
              // 3.0.0: names the MCP ephemeral this ready answers, so a server
              // can tell a stale one (discard) from a forged one (1008).
              mcpSessionPub: frame.sessionPub,
              sessionSig: Buffer.from(sig).toString('base64'),
            };
            extWs!.send(JSON.stringify(readyFrame));
            resolveReady();
            return;
          }
          if (frame.type === 'frame') {
            if (!sessionKey || !mcpId || frame.mcpId !== mcpId) return;
            const inner = await openEncryptedFrame(sessionKey, frame, 's2e');
            if (inner.type === 'request' && inner.op === 'read_indexed_db') {
              outboundSeq += 1;
              const sealed = await sealInnerFrame(
                sessionKey,
                mcpId,
                outboundSeq,
                {
                  type: 'response',
                  id: inner.id,
                  ok: true,
                  op: 'read_indexed_db',
                  values: { userToken: 'ey...token', userId: 'u-7' },
                },
                'e2s',
              );
              extWs!.send(JSON.stringify(sealed));
            }
          }
        } catch (e) {
          console.error('mock extension error:', e);
        }
      });

      // Extension hello with v2 identity claims + per-WS nonce.
      const extHello: HelloFrameFromExtension = {
        type: 'hello',
        protocolVersion: 4,
        role: 'extension',
        platform: 'chrome',
        extensionId: 'fetchproxy',
        version: '0.4.0',
        identityX25519Pub: Buffer.from(extIdX.publicKey).toString('base64'),
        identityEd25519Pub: Buffer.from(extIdEd.publicKey).toString('base64'),
        sessionNonce: Buffer.from(extSessionNonce).toString('base64'),
      };
      extWs!.send(JSON.stringify(extHello));
    });

    await ready;

    // The pair code the MCP derived must match the joint derivation, which
    // since 3.0.0 (protocol 4) is the whole pair transcript: both identities,
    // both hello nonces and the MCP's session ephemeral. This is the
    // user-visible signal.
    expect(receivedPairCode).not.toBeNull();
    expect(mcpIdentityX25519Pub).not.toBeNull();
    expect(helloFrame).not.toBeNull();
    const expected = await pairTranscript(
      mcpIdentityX25519Pub!,
      extIdX.publicKey,
      new Uint8Array(Buffer.from(helloFrame!.sessionNonce, 'base64')),
      extSessionNonce,
      new Uint8Array(Buffer.from(helloFrame!.sessionPub, 'base64')),
    );
    expect(receivedPairCode).toBe(expected);

    // Read_indexed_db round-trip — the gated server method against
    // declared (database, store, keys) and the response shape.
    const values = await server.readIndexedDb({
      database: 'resy',
      store: 'auth',
      keys: ['userToken', 'userId'],
    });
    expect(values).toEqual({ userToken: 'ey...token', userId: 'u-7' });

    // Server-hello must have surfaced the IndexedDB scope declaration on the wire.
    expect(helloFrame).not.toBeNull();
    expect(helloFrame!.indexedDbScopes).toEqual([
      {
        origin: 'https://resy.com',
        database: 'resy',
        store: 'auth',
        keys: ['userToken', 'userId'],
      },
    ]);
  }, 30_000);

  it('host closes WS with 1008 when ReadyFrame signature is invalid (MITM detection)', async () => {
    const port = await getEphemeralPort();
    const idDir = mkdtempSync(join(tmpdir(), 'fp-int-mutual-bad-'));

    server = new FetchproxyServer({
      port,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
      identityDir: idDir,
    });
    await server.listen();
    await server.connect();

    extWs = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((resolve, reject) => {
      extWs!.once('open', () => resolve());
      extWs!.once('error', reject);
    });
    // Silence post-close EPIPE noise.
    extWs.on('error', () => {
      /* expected */
    });

    const extIdX = await generateX25519();
    const extIdEd = await generateEd25519();

    const closed = new Promise<{ code: number; reason: string }>((resolve) => {
      extWs!.once('close', (code: number, reason: Buffer) =>
        resolve({ code, reason: reason.toString() }),
      );
    });

    extWs.on('message', async (data) => {
      try {
        const parsed = JSON.parse(data.toString());
        const frame = validateFrame(parsed);
        if (frame.type === 'hello' && frame.role === 'server') {
          // Send a ReadyFrame whose signature is over the WRONG payload —
          // attacker substituting their own session signing. The host
          // should reject with 1008.
          const ephemeral = await generateX25519();
          const wrongPayload = new Uint8Array(64).fill(0xff);
          const badSig = await ed25519Sign(extIdEd.privateKey, wrongPayload);
          const readyFrame: ReadyFrame = {
            type: 'ready',
            mcpId: frame.mcpId,
            extensionSessionPub: Buffer.from(ephemeral.publicKey).toString('base64'),
            // 3.0.0: it has to name the CURRENT MCP ephemeral, or §1a's Rule C
            // discards it before any signature is checked — which is the right
            // v4 behaviour for a stale ready and the wrong test for a forged
            // one. The two outcomes are deliberately different, so this case
            // has to reach the second.
            mcpSessionPub: frame.sessionPub,
            sessionSig: Buffer.from(badSig).toString('base64'),
          };
          extWs!.send(JSON.stringify(readyFrame));
        }
      } catch {
        // ignore
      }
    });

    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: 4,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: Buffer.from(extIdX.publicKey).toString('base64'),
      identityEd25519Pub: Buffer.from(extIdEd.publicKey).toString('base64'),
      sessionNonce: Buffer.from(new Uint8Array(32).fill(0xc1)).toString('base64'),
    };
    extWs.send(JSON.stringify(extHello));

    const { code } = await closed;
    expect(code).toBe(1008);
  }, 30_000);
});
