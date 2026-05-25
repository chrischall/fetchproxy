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
  concatBytes,
  ecdhX25519,
  hkdfSha256,
  sealInnerFrame,
  openEncryptedFrame,
  HKDF_SESSION_INFO,
  type HelloFrameFromExtension,
  type HelloFrameFromServer,
  type ReadyFrame,
} from '@fetchproxy/protocol';
import { FetchproxyServer } from '../../src/index.js';

/**
 * End-to-end exercise of all four 0.3.0 bootstrap verbs through the
 * real WebSocket concentrator. A mock extension dials the host, auto-
 * approves the pair, and replies to each verb with canned data. The
 * MCP's `FetchproxyServer` methods should round-trip back the canned
 * data.
 *
 * Mirrors `read-cookies.test.ts` for shape and lifecycle — this is the
 * gold-standard integration test for the new verbs.
 */
describe('integration: all 0.3.0 bootstrap verbs', () => {
  let server: FetchproxyServer | null = null;
  let extWs: WebSocket | null = null;

  afterEach(async () => {
    if (extWs && extWs.readyState === extWs.OPEN) extWs.close();
    if (server) await server.close();
    server = null;
    extWs = null;
    // Small grace period for sockets to settle so the next test gets a clean port.
    await new Promise((r) => setTimeout(r, 50));
  });

  it('routes every declared verb through the bridge and pins scope on the wire', async () => {
    const port = 41030;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-int-allverbs-'));

    server = new FetchproxyServer({
      port,
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      capabilities: [
        'fetch',
        'read_cookies',
        'read_local_storage',
        'read_session_storage',
        'capture_request_header',
      ],
      cookieKeys: ['MTOKEN', 'CKAT'],
      localStorageKeys: ['auth', 'tokenExpiry'],
      sessionStorageKeys: ['anon-id'],
      captureHeaders: [
        { urlPattern: 'https://api.ourfamilywizard.com/v1/*', headerName: 'x-csrf' },
      ],
      identityDir: idDir,
    });
    await server.listen();

    extWs = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((resolve, reject) => {
      extWs!.once('open', () => resolve());
      extWs!.once('error', reject);
    });

    let sessionKey: Uint8Array | null = null;
    let mcpId: string | null = null;
    let outboundSeq = 0;
    let helloFrame: HelloFrameFromServer | null = null;

    // 0.4.0: mock-extension identity used to sign the ReadyFrame's
    // (mcpNonce || extNonce) binding signature.
    const extIdX = await generateX25519();
    const extIdEd = await generateEd25519();
    const extSessionNonce = new Uint8Array(32);
    (globalThis.crypto as Crypto).getRandomValues(extSessionNonce);

    const ready = new Promise<void>((resolveReady) => {
      extWs!.on('message', async (data) => {
        try {
          const parsed = JSON.parse(data.toString());
          const frame = validateFrame(parsed);

          if (frame.type === 'hello' && frame.role === 'server') {
            helloFrame = frame;
            const identityX25519Pub = new Uint8Array(
              Buffer.from(frame.identityX25519Pub, 'base64'),
            );
            const mcpSessionNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));
            const ephemeral = await generateX25519();
            const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
            sessionKey = await hkdfSha256(
              shared,
              mcpSessionNonce,
              new TextEncoder().encode(HKDF_SESSION_INFO),
              32,
            );
            mcpId = frame.mcpId;
            const sig = await ed25519Sign(
              extIdEd.privateKey,
              concatBytes(mcpSessionNonce, extSessionNonce),
            );
            const readyFrame: ReadyFrame = {
              type: 'ready',
              mcpId,
              extensionSessionPub: Buffer.from(ephemeral.publicKey).toString('base64'),
              sessionSig: Buffer.from(sig).toString('base64'),
            };
            extWs!.send(JSON.stringify(readyFrame));
            resolveReady();
            return;
          }
          if (frame.type === 'frame') {
            if (!sessionKey || !mcpId || frame.mcpId !== mcpId) return;
            const inner = await openEncryptedFrame(sessionKey, frame);
            if (inner.type !== 'request') return;
            outboundSeq += 1;
            // Reply with a canned payload matched to the inner verb.
            if (inner.op === 'read_cookies' && 'origin' in inner.init) {
              const sealed = await sealInnerFrame(sessionKey, mcpId, outboundSeq, {
                type: 'response',
                id: inner.id,
                ok: true,
                op: 'read_cookies',
                values: { MTOKEN: 'mt-val', CKAT: 'ck-val' },
              });
              extWs!.send(JSON.stringify(sealed));
            } else if (inner.op === 'read_local_storage') {
              const sealed = await sealInnerFrame(sessionKey, mcpId, outboundSeq, {
                type: 'response',
                id: inner.id,
                ok: true,
                op: 'read_local_storage',
                values: { auth: 'ey...', tokenExpiry: '1730000000000' },
              });
              extWs!.send(JSON.stringify(sealed));
            } else if (inner.op === 'read_session_storage') {
              const sealed = await sealInnerFrame(sessionKey, mcpId, outboundSeq, {
                type: 'response',
                id: inner.id,
                ok: true,
                op: 'read_session_storage',
                values: { 'anon-id': 'abc-123' },
              });
              extWs!.send(JSON.stringify(sealed));
            } else if (inner.op === 'capture_request_header') {
              const sealed = await sealInnerFrame(sessionKey, mcpId, outboundSeq, {
                type: 'response',
                id: inner.id,
                ok: true,
                op: 'capture_request_header',
                value: 'csrf-fp-abc',
              });
              extWs!.send(JSON.stringify(sealed));
            }
          }
        } catch (e) {
          console.error('mock extension error:', e);
        }
      });

      // Send the extension hello so the host forwards the server hello.
      const extHello: HelloFrameFromExtension = {
        type: 'hello',
        protocolVersion: 2,
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

    // The wire-level hello must have surfaced every declared scope field.
    expect(helloFrame).not.toBeNull();
    expect(helloFrame!.cookieKeys).toEqual(['MTOKEN', 'CKAT']);
    expect(helloFrame!.localStorageKeys).toEqual(['auth', 'tokenExpiry']);
    expect(helloFrame!.sessionStorageKeys).toEqual(['anon-id']);
    expect(helloFrame!.captureHeaders).toEqual([
      { urlPattern: 'https://api.ourfamilywizard.com/v1/*', headerName: 'x-csrf' },
    ]);

    // 1. read_cookies — new shape
    const cookies = await server.readCookies({ keys: ['MTOKEN', 'CKAT'] });
    // Back-compat surface joins the values map; the bootstrap helper
    // separately parses it back into a record.
    expect(cookies).toContain('MTOKEN=mt-val');
    expect(cookies).toContain('CKAT=ck-val');

    // 2. read_local_storage
    const ls = await server.readLocalStorage({ keys: ['auth', 'tokenExpiry'] });
    expect(ls).toEqual({ auth: 'ey...', tokenExpiry: '1730000000000' });

    // 3. read_session_storage
    const ss = await server.readSessionStorage({ keys: ['anon-id'] });
    expect(ss).toEqual({ 'anon-id': 'abc-123' });

    // 4. capture_request_header
    const csrf = await server.captureRequestHeader({
      urlPattern: 'https://api.ourfamilywizard.com/v1/*',
      headerName: 'x-csrf',
    });
    expect(csrf).toBe('csrf-fp-abc');
  }, 30_000);
});
