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

const enc = new TextEncoder();

/**
 * Helper: connect a mock extension to the host, complete the mutual-auth
 * handshake, and return everything needed to exchange encrypted frames.
 */
async function connectMockExtension(port: number) {
  const extIdX = await generateX25519();
  const extIdEd = await generateEd25519();
  const extSessionNonce = new Uint8Array(32);
  crypto.getRandomValues(extSessionNonce);

  const ws = new WebSocket(`ws://127.0.0.1:${port}`);
  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });

  const extHello: HelloFrameFromExtension = {
    type: 'hello',
    protocolVersion: 2,
    role: 'extension',
    platform: 'chrome',
    extensionId: 'fetchproxy',
    version: '0.5.0',
    identityX25519Pub: Buffer.from(extIdX.publicKey).toString('base64'),
    identityEd25519Pub: Buffer.from(extIdEd.publicKey).toString('base64'),
    sessionNonce: Buffer.from(extSessionNonce).toString('base64'),
  };

  let sessionKey: Uint8Array | null = null;
  let mcpId: string | null = null;
  let outboundSeq = 0;

  const ready = new Promise<void>((resolveReady) => {
    ws.on('message', async (data) => {
      try {
        const parsed = JSON.parse(data.toString());
        const frame = validateFrame(parsed);
        if (frame.type === 'hello' && frame.role === 'server') {
          const mcpPub = new Uint8Array(Buffer.from(frame.identityX25519Pub, 'base64'));
          const mcpNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));
          const ephemeral = await generateX25519();
          const shared = await ecdhX25519(ephemeral.privateKey, mcpPub);
          sessionKey = await hkdfSha256(
            shared,
            mcpNonce,
            enc.encode(HKDF_SESSION_INFO),
            32,
          );
          mcpId = frame.mcpId;
          const sig = await ed25519Sign(
            extIdEd.privateKey,
            concatBytes(mcpNonce, extSessionNonce),
          );
          const readyFrame: ReadyFrame = {
            type: 'ready',
            mcpId,
            extensionSessionPub: Buffer.from(ephemeral.publicKey).toString('base64'),
            sessionSig: Buffer.from(sig).toString('base64'),
          };
          ws.send(JSON.stringify(readyFrame));
          resolveReady();
        }
      } catch {
        // ignore
      }
    });
  });

  ws.send(JSON.stringify(extHello));
  await ready;

  return {
    ws,
    get sessionKey() { return sessionKey!; },
    get mcpId() { return mcpId!; },
    nextSeq() { return ++outboundSeq; },
  };
}

describe('extension reconnect (session-key renegotiation)', () => {
  let server: FetchproxyServer | null = null;

  afterEach(async () => {
    if (server) await server.close();
    server = null;
    await new Promise((r) => setTimeout(r, 50));
  });

  it('host accepts a new session key after extension disconnects and reconnects', async () => {
    const port = 41060;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-reconnect-'));

    server = new FetchproxyServer({
      port,
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      identityDir: idDir,
    });
    await server.listen();

    // First connection — complete handshake and verify a fetch round-trips.
    const ext1 = await connectMockExtension(port);

    // Wire up a responder on ext1 for fetch requests.
    const ext1Handler = (data: WebSocket.RawData) => {
      void (async () => {
        try {
          const parsed = JSON.parse(data.toString());
          const frame = validateFrame(parsed);
          if (frame.type !== 'frame' || frame.mcpId !== ext1.mcpId) return;
          const inner = await openEncryptedFrame(ext1.sessionKey, frame);
          if (inner.type === 'request' && inner.op === 'fetch') {
            const sealed = await sealInnerFrame(ext1.sessionKey, ext1.mcpId, ext1.nextSeq(), {
              type: 'response',
              id: inner.id,
              ok: true,
              op: 'fetch',
              status: 200,
              url: inner.init.url,
              body: 'first-session',
            });
            ext1.ws.send(JSON.stringify(sealed));
          }
        } catch { /* ignore */ }
      })();
    };
    ext1.ws.on('message', ext1Handler);

    const r1 = await server.fetch({
      url: 'https://example.com/test',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    expect(r1.ok).toBe(true);
    if (r1.ok) expect(r1.body).toBe('first-session');

    // Disconnect extension (simulates SW eviction / extension reload).
    const ext1Closed = new Promise<void>((r) => ext1.ws.on('close', () => r()));
    ext1.ws.close();
    await ext1Closed;
    await new Promise((r) => setTimeout(r, 50));

    // Reconnect with a fresh handshake — new ephemeral keys.
    const ext2 = await connectMockExtension(port);

    // Wire up a responder on ext2.
    ext2.ws.on('message', (data: WebSocket.RawData) => {
      void (async () => {
        try {
          const parsed = JSON.parse(data.toString());
          const frame = validateFrame(parsed);
          if (frame.type !== 'frame' || frame.mcpId !== ext2.mcpId) return;
          const inner = await openEncryptedFrame(ext2.sessionKey, frame);
          if (inner.type === 'request' && inner.op === 'fetch') {
            const sealed = await sealInnerFrame(ext2.sessionKey, ext2.mcpId, ext2.nextSeq(), {
              type: 'response',
              id: inner.id,
              ok: true,
              op: 'fetch',
              status: 200,
              url: inner.init.url,
              body: 'second-session',
            });
            ext2.ws.send(JSON.stringify(sealed));
          }
        } catch { /* ignore */ }
      })();
    });

    // Fetch through the new session — must use the new session key.
    const r2 = await server.fetch({
      url: 'https://example.com/test',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    expect(r2.ok).toBe(true);
    if (r2.ok) expect(r2.body).toBe('second-session');

    ext2.ws.close();
  }, 30_000);

  it('in-flight fetch rejects with "extension disconnected" when the extension drops', async () => {
    const port = 41061;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-reconnect-pending-'));

    server = new FetchproxyServer({
      port,
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      identityDir: idDir,
    });
    await server.listen();

    const ext = await connectMockExtension(port);

    // Start a fetch but don't answer it from the mock extension.
    const fetchPromise = server.fetch({
      url: 'https://example.com/slow',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });

    // Give the frame time to be sent.
    await new Promise((r) => setTimeout(r, 50));

    // Extension disconnects while request is in-flight.
    ext.ws.close();

    const result = await fetchPromise;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/extension disconnected/);
  }, 30_000);

  it('in-flight readLocalStorage rejects on extension disconnect', async () => {
    const port = 41062;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-reconnect-storage-'));

    server = new FetchproxyServer({
      port,
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      capabilities: ['fetch', 'read_local_storage'],
      localStorageKeys: ['token'],
      identityDir: idDir,
    });
    await server.listen();

    const ext = await connectMockExtension(port);

    const storagePromise = server.readLocalStorage({ keys: ['token'] });

    await new Promise((r) => setTimeout(r, 50));
    ext.ws.close();

    await expect(storagePromise).rejects.toThrow(/extension disconnected/);
  }, 30_000);

  it('sendOwnInner works again after reconnect (not permanently rejected)', async () => {
    const port = 41063;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-reconnect-promise-'));

    server = new FetchproxyServer({
      port,
      serverName: 'test-mcp',
      version: '0.0.1',
      domains: ['example.com'],
      identityDir: idDir,
    });
    await server.listen();

    const ext1 = await connectMockExtension(port);
    const ext1Closed = new Promise<void>((r) => ext1.ws.on('close', () => r()));
    ext1.ws.close();
    await ext1Closed;
    await new Promise((r) => setTimeout(r, 50));

    const ext2 = await connectMockExtension(port);

    // Wire up responder for the second session.
    ext2.ws.on('message', (data: WebSocket.RawData) => {
      void (async () => {
        try {
          const parsed = JSON.parse(data.toString());
          const frame = validateFrame(parsed);
          if (frame.type !== 'frame' || frame.mcpId !== ext2.mcpId) return;
          const inner = await openEncryptedFrame(ext2.sessionKey, frame);
          if (inner.type === 'request' && inner.op === 'fetch') {
            const sealed = await sealInnerFrame(ext2.sessionKey, ext2.mcpId, ext2.nextSeq(), {
              type: 'response',
              id: inner.id,
              ok: true,
              op: 'fetch',
              status: 200,
              url: inner.init.url,
              body: 'alive-after-reconnect',
            });
            ext2.ws.send(JSON.stringify(sealed));
          }
        } catch { /* ignore */ }
      })();
    });

    const result = await server.fetch({
      url: 'https://example.com/check',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.body).toBe('alive-after-reconnect');

    ext2.ws.close();
  }, 30_000);
});
