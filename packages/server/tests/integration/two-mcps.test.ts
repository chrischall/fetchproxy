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
  type HelloFrameFromExtension,
  type ReadyFrame,
} from '@fetchproxy/protocol';
import { FetchproxyServer } from '../../src/index.js';

describe('integration: two MCPs through one host', () => {
  let a: FetchproxyServer | null = null;
  let b: FetchproxyServer | null = null;
  let extWs: WebSocket | null = null;

  afterEach(async () => {
    if (extWs && extWs.readyState === extWs.OPEN) extWs.close();
    if (a) await a.close();
    if (b) await b.close();
    a = null;
    b = null;
    extWs = null;
    // Small grace period for sockets to settle so the next test gets a clean port.
    await new Promise((r) => setTimeout(r, 50));
  });

  it('routes fetches from host and peer through one extension WS, with distinct session keys', async () => {
    const port = 41010;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-int-'));

    // Stand up two MCPs on the same port. First wins host, second becomes peer.
    a = new FetchproxyServer({
      port,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      identityDir: idDir,
    });
    await a.listen();
    expect(a.role).toBe('host');

    b = new FetchproxyServer({
      port,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
      identityDir: idDir,
    });
    await b.listen();
    expect(b.role).toBe('peer');

    // Mock extension: dial the host's WS.
    extWs = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((resolve, reject) => {
      extWs!.once('open', () => resolve());
      extWs!.once('error', reject);
    });

    // Per-mcpId session state on the extension side.
    interface Track {
      sessionKey?: Uint8Array;
      mcpId: string;
      domains: string[];
    }
    const tracks = new Map<string, Track>();      // by mcpId
    const serverNameToMcpId = new Map<string, string>();

    // Track session keys as base64 strings for the distinct-keys assertion.
    const sessionKeysB64: string[] = [];

    // Outbound seq counters per mcpId
    const outboundSeq = new Map<string, number>();

    function nextSeq(mcpId: string): number {
      const n = (outboundSeq.get(mcpId) ?? 0) + 1;
      outboundSeq.set(mcpId, n);
      return n;
    }

    const enc = new TextEncoder();

    // 0.4.0: mock-extension identity used for ReadyFrame signatures.
    // Both MCPs (host + peer) get the same extension identity since
    // there's only one WS connection.
    const extIdX = await generateX25519();
    const extIdEd = await generateEd25519();
    const extSessionNonce = new Uint8Array(32);
    (globalThis.crypto as Crypto).getRandomValues(extSessionNonce);

    // Wait for both server hellos to arrive AND respond with ready frames.
    const bothReady = new Promise<void>((resolveBothReady) => {
      const needed = new Set(['opentable-mcp', 'resy-mcp']);

      extWs!.on('message', async (data) => {
        try {
          const parsed = JSON.parse(data.toString());
          const frame = validateFrame(parsed);

          if (frame.type === 'hello' && frame.role === 'server') {
            const identityX25519Pub = new Uint8Array(Buffer.from(frame.identityX25519Pub, 'base64'));
            const mcpSessionNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));

            // Auto-approve in this test (the pair-code gate is unit-tested elsewhere).
            const ephemeral = await generateX25519();
            const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
            const sessionKey = await hkdfSha256(
              shared,
              mcpSessionNonce,
              enc.encode('fetchproxy/0.1.0/session'),
              32,
            );

            tracks.set(frame.mcpId, {
              sessionKey,
              mcpId: frame.mcpId,
              domains: [...frame.domains],
            });
            serverNameToMcpId.set(frame.serverName, frame.mcpId);
            sessionKeysB64.push(Buffer.from(sessionKey).toString('base64'));

            const sig = await ed25519Sign(
              extIdEd.privateKey,
              concatBytes(mcpSessionNonce, extSessionNonce),
            );
            const ready: ReadyFrame = {
              type: 'ready',
              mcpId: frame.mcpId,
              extensionSessionPub: Buffer.from(ephemeral.publicKey).toString('base64'),
              sessionSig: Buffer.from(sig).toString('base64'),
            };
            extWs!.send(JSON.stringify(ready));

            needed.delete(frame.serverName);
            if (needed.size === 0) resolveBothReady();
            return;
          }

          if (frame.type === 'frame') {
            const track = tracks.get(frame.mcpId);
            if (!track?.sessionKey) return;
            const inner = await openEncryptedFrame(track.sessionKey, frame);
            if (inner.type === 'request') {
              // Echo a synthetic 200 response.
              const respInner = {
                type: 'response' as const,
                id: inner.id,
                ok: true as const,
                status: 200,
                url: inner.init.url,
                body: `echo from ${frame.mcpId}`,
              };
              const sealed = await sealInnerFrame(
                track.sessionKey,
                frame.mcpId,
                nextSeq(frame.mcpId),
                respInner,
              );
              extWs!.send(JSON.stringify(sealed));
            }
          }
        } catch (e) {
          console.error('mock extension error:', e);
        }
      });

      // Send the extension hello to trigger the host to forward server hellos.
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

    await bothReady;

    // Now both MCPs should be ready. Each issues a fetch — the host (A) on its
    // own path, the peer (B) through the host. Both should round-trip.
    const [ra, rb] = await Promise.all([
      a.fetch({ url: 'https://opentable.com/x', method: 'GET', tabUrl: 'https://opentable.com/' }),
      b.fetch({ url: 'https://resy.com/y', method: 'GET', tabUrl: 'https://resy.com/' }),
    ]);

    expect(ra.ok).toBe(true);
    if (ra.ok) {
      expect(ra.status).toBe(200);
      const opentableMcpId = serverNameToMcpId.get('opentable-mcp');
      expect(ra.body).toContain(opentableMcpId!);
    }
    expect(rb.ok).toBe(true);
    if (rb.ok) {
      expect(rb.status).toBe(200);
      const resyMcpId = serverNameToMcpId.get('resy-mcp');
      expect(rb.body).toContain(resyMcpId!);
    }

    // Distinct session keys — host can't decrypt peer's traffic.
    expect(sessionKeysB64).toHaveLength(2);
    expect(sessionKeysB64[0]).not.toBe(sessionKeysB64[1]);
  }, 30_000);
});
