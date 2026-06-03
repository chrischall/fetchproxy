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
    await server.connect();

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
    await server.connect();

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
    await server.connect();

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
    await server.connect();

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

/**
 * Helper for the peer-reconnect describe block: completes the mutual-auth
 * handshake for ALL incoming `hello` frames on a single WS connection.
 * Unlike `connectMockExtension`, which is single-MCP, this returns a map
 * keyed by `mcpId` so the test can route encrypted frames to the right
 * session key after the host has multiplexed two server hellos in.
 */
async function connectMockExtensionMulti(port: number, expectedMcps: number) {
  const extIdX = await generateX25519();
  const extIdEd = await generateEd25519();
  const extSessionNonce = new Uint8Array(32);
  crypto.getRandomValues(extSessionNonce);

  const ws = new WebSocket(`ws://127.0.0.1:${port}`);
  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });

  interface McpSession {
    sessionKey: Uint8Array;
    outboundSeq: number;
  }
  const sessions = new Map<string, McpSession>();

  // Resolve once we've handshaked with `expectedMcps` distinct MCPs.
  let resolveReady!: () => void;
  const ready = new Promise<void>((r) => { resolveReady = r; });

  ws.on('message', (data) => {
    void (async () => {
      try {
        const parsed = JSON.parse(data.toString());
        const frame = validateFrame(parsed);
        if (frame.type === 'hello' && frame.role === 'server') {
          const mcpPub = new Uint8Array(Buffer.from(frame.identityX25519Pub, 'base64'));
          const mcpNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));
          const ephemeral = await generateX25519();
          const shared = await ecdhX25519(ephemeral.privateKey, mcpPub);
          const sessionKey = await hkdfSha256(
            shared,
            mcpNonce,
            enc.encode(HKDF_SESSION_INFO),
            32,
          );
          // Replace any prior session for this mcpId — simulates the
          // extension's auto-trust path on reconnect, which derives a
          // fresh ephemeral per WS connect.
          sessions.set(frame.mcpId, { sessionKey, outboundSeq: 0 });
          const sig = await ed25519Sign(
            extIdEd.privateKey,
            concatBytes(mcpNonce, extSessionNonce),
          );
          const readyFrame: ReadyFrame = {
            type: 'ready',
            mcpId: frame.mcpId,
            extensionSessionPub: Buffer.from(ephemeral.publicKey).toString('base64'),
            sessionSig: Buffer.from(sig).toString('base64'),
          };
          ws.send(JSON.stringify(readyFrame));
          if (sessions.size >= expectedMcps) resolveReady();
        }
      } catch {
        // ignore
      }
    })();
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
  ws.send(JSON.stringify(extHello));
  await ready;

  return { ws, sessions };
}

/**
 * Reproduces the multi-MCP bug we hit in production: with a host MCP plus
 * one or more peer MCPs sharing the bridge, the host renegotiates its
 * session correctly when the extension reconnects, but the peers stay
 * stuck on their first session key. After the extension reconnect, the
 * peer-side sealed frames are encrypted with the old key while the
 * extension is now using the renegotiated key — and the frame is
 * silently dropped by the extension's decrypt path. Tools on the peer
 * MCP just time out.
 */
describe('extension reconnect (peer MCPs)', () => {
  let host: FetchproxyServer | null = null;
  let peer: FetchproxyServer | null = null;

  afterEach(async () => {
    if (peer) await peer.close();
    if (host) await host.close();
    host = null;
    peer = null;
    await new Promise((r) => setTimeout(r, 50));
  });

  it('peer fetch still works after extension reconnects', async () => {
    const port = 41080;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-reconnect-'));

    host = new FetchproxyServer({
      port,
      serverName: 'host-mcp',
      version: '0.0.1',
      domains: ['host.example.com'],
      identityDir: idDir,
    });
    await host.listen();
    await host.connect();
    expect(host.role).toBe('host');

    peer = new FetchproxyServer({
      port,
      serverName: 'peer-mcp',
      version: '0.0.1',
      domains: ['peer.example.com'],
      identityDir: idDir,
    });
    await peer.listen();
    await peer.connect();
    expect(peer.role).toBe('peer');

    // Mock extension responder: echoes the request body back to the caller,
    // labeled with which session derived it. Re-attached for each WS.
    function wireResponder(
      ws: WebSocket,
      sessions: Map<string, { sessionKey: Uint8Array; outboundSeq: number }>,
      sessionLabel: string,
    ): void {
      ws.on('message', (data: WebSocket.RawData) => {
        void (async () => {
          try {
            const parsed = JSON.parse(data.toString());
            const frame = validateFrame(parsed);
            if (frame.type !== 'frame') return;
            const sess = sessions.get(frame.mcpId);
            if (!sess) return;
            const inner = await openEncryptedFrame(sess.sessionKey, frame);
            if (inner.type !== 'request' || inner.op !== 'fetch') return;
            sess.outboundSeq += 1;
            const sealed = await sealInnerFrame(
              sess.sessionKey,
              frame.mcpId,
              sess.outboundSeq,
              {
                type: 'response',
                id: inner.id,
                ok: true,
                op: 'fetch',
                status: 200,
                url: inner.init.url,
                body: `${sessionLabel}:${frame.mcpId}`,
              },
            );
            ws.send(JSON.stringify(sealed));
          } catch { /* ignore */ }
        })();
      });
    }

    // First extension connect — handshakes with both MCPs.
    const ext1 = await connectMockExtensionMulti(port, 2);
    wireResponder(ext1.ws, ext1.sessions, 'first');

    // Sanity check: peer fetch works on the first session.
    const r1 = await peer.fetch({
      url: 'https://peer.example.com/x',
      method: 'GET',
      tabUrl: 'https://peer.example.com/',
    });
    expect(r1.ok).toBe(true);
    if (r1.ok) expect(r1.body.startsWith('first:peer-mcp:')).toBe(true);

    // Extension reconnects (simulates MV3 service-worker eviction).
    const ext1Closed = new Promise<void>((r) => ext1.ws.on('close', () => r()));
    ext1.ws.close();
    await ext1Closed;
    await new Promise((r) => setTimeout(r, 50));

    // The new extension WS handshakes again with both MCPs — fresh
    // ephemeral keys, fresh session keys on both ends of each pair.
    const ext2 = await connectMockExtensionMulti(port, 2);
    wireResponder(ext2.ws, ext2.sessions, 'second');

    // The host MCP's fetch should keep working (covered by the host-side
    // reconnect test above; included here as a regression guard against
    // breaking the host path while fixing the peer path).
    const hostFetch = await host.fetch({
      url: 'https://host.example.com/y',
      method: 'GET',
      tabUrl: 'https://host.example.com/',
    });
    expect(hostFetch.ok).toBe(true);
    if (hostFetch.ok) expect(hostFetch.body.startsWith('second:host-mcp:')).toBe(true);

    // THE BUG: the peer MCP's fetch hangs until the test times out, because
    // the peer is still encrypting with its first session key while the
    // extension only knows the renegotiated key.
    const peerFetch = await peer.fetch({
      url: 'https://peer.example.com/z',
      method: 'GET',
      tabUrl: 'https://peer.example.com/',
    });
    expect(peerFetch.ok).toBe(true);
    if (peerFetch.ok) expect(peerFetch.body.startsWith('second:peer-mcp:')).toBe(true);

    ext2.ws.close();
  }, 30_000);

  it('in-flight peer fetch rejects on session renegotiation', async () => {
    const port = 41081;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-inflight-'));

    host = new FetchproxyServer({
      port,
      serverName: 'host-mcp',
      version: '0.0.1',
      domains: ['host.example.com'],
      identityDir: idDir,
    });
    await host.listen();
    await host.connect();

    peer = new FetchproxyServer({
      port,
      serverName: 'peer-mcp',
      version: '0.0.1',
      domains: ['peer.example.com'],
      identityDir: idDir,
    });
    await peer.listen();
    await peer.connect();

    // Connect extension but never answer the fetch — we want to observe
    // the in-flight rejection path, not an upstream response.
    const ext1 = await connectMockExtensionMulti(port, 2);

    const inflight = peer.fetch({
      url: 'https://peer.example.com/slow',
      method: 'GET',
      tabUrl: 'https://peer.example.com/',
    });
    // Give the request time to land in the pending map.
    await new Promise((r) => setTimeout(r, 50));

    // Reconnect — this should reject the in-flight request rather than
    // leave it hanging until the MCP-level timeout.
    const ext1Closed = new Promise<void>((r) => ext1.ws.on('close', () => r()));
    ext1.ws.close();
    await ext1Closed;
    const ext2 = await connectMockExtensionMulti(port, 2);

    const result = await inflight;
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toMatch(/extension disconnected/);

    // Symmetric cleanup with the first peer-reconnect test — the
    // FetchproxyServer.close() in afterEach drops the server-side socket
    // and the client closes implicitly, but closing here keeps the test
    // teardown easy to follow and matches the other test's pattern.
    ext2.ws.close();
  }, 30_000);
});

/**
 * 0.13.0+ peer re-host on host loss. The concentrator role is elected once;
 * before this, a peer whose host process died was stranded as a peer forever
 * (every verb call reused the dead handle and failed with "peer WS closed
 * before ready"), even though the port was now free and it could trivially
 * become the new host. The fix: on host-WS-close, tear down the peer handle
 * and let the next verb call re-elect.
 */
describe('peer re-host on host loss', () => {
  let host: FetchproxyServer | null = null;
  let peer: FetchproxyServer | null = null;

  afterEach(async () => {
    if (peer) await peer.close();
    if (host) await host.close();
    host = null;
    peer = null;
    await new Promise((r) => setTimeout(r, 50));
  });

  it('a stranded peer re-elects to host on the next call after its host dies', async () => {
    const port = 41090;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-rehost-'));

    host = new FetchproxyServer({
      port,
      serverName: 'host-mcp',
      version: '0.0.1',
      domains: ['host.example.com'],
      identityDir: idDir,
    });
    await host.listen();
    await host.connect();
    expect(host.role).toBe('host');

    peer = new FetchproxyServer({
      port,
      serverName: 'peer-mcp',
      version: '0.0.1',
      domains: ['peer.example.com'],
      identityDir: idDir,
    });
    await peer.listen();
    await peer.connect();
    expect(peer.role).toBe('peer');

    // Host dies — drops the peer's upstream WS.
    await host.close();
    host = null;

    // The peer observes the close and tears down its stranded handle
    // (lazy: role returns to null, awaiting the next verb call to re-elect).
    await new Promise((r) => setTimeout(r, 100));
    expect(peer.role).toBe(null);

    // Next call re-elects on the now-free port → becomes the new host.
    await peer.connect();
    expect(peer.role).toBe('host');
  }, 30_000);

  it('intentional peer.close() does not re-elect to host (closing guard)', async () => {
    const port = 41091;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-rehost-guard-'));

    host = new FetchproxyServer({
      port,
      serverName: 'host-mcp',
      version: '0.0.1',
      domains: ['host.example.com'],
      identityDir: idDir,
    });
    await host.listen();
    await host.connect();

    peer = new FetchproxyServer({
      port,
      serverName: 'peer-mcp',
      version: '0.0.1',
      domains: ['peer.example.com'],
      identityDir: idDir,
    });
    await peer.listen();
    await peer.connect();
    expect(peer.role).toBe('peer');

    // Intentional shutdown — the ensuing WS close must NOT be mistaken for
    // host death. Role stays null; the peer does not spontaneously re-elect.
    await peer.close();
    await new Promise((r) => setTimeout(r, 100));
    expect(peer.role).toBe(null);
    peer = null;
  }, 30_000);
});
