import { describe, it, expect, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateFrame,
  generateX25519,
  ecdhX25519,
  hkdfSha256,
  sealInnerFrame,
  openEncryptedFrame,
  type HelloFrameFromExtension,
  type ReadyFrame,
} from '@fetchproxy/protocol';
import { FetchproxyServer } from '../../src/index.js';

/**
 * End-to-end exercise of the `read_cookies` verb through the real WS
 * concentrator. A mock extension dials the host, auto-approves the
 * pair, and replies to any `read_cookies` inner request with a canned
 * cookies string. The MCP's `readCookies()` should resolve to that
 * string.
 *
 * Mirrors `two-mcps.test.ts` for shape: that one is the gold-standard
 * fetch integration test on this codebase, this one shadows its
 * structure for the new verb.
 */
describe('integration: readCookies() round-trip', () => {
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

  it('routes a read_cookies request through the bridge and returns the cookies', async () => {
    const port = 41020;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-int-cookies-'));

    server = new FetchproxyServer({
      port,
      serverName: 'credit-karma-mcp',
      version: '0.0.1',
      domains: ['creditkarma.com'],
      capabilities: ['fetch', 'read_cookies'],
      identityDir: idDir,
    });
    await server.listen();
    expect(server.role).toBe('host');

    extWs = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((resolve, reject) => {
      extWs!.once('open', () => resolve());
      extWs!.once('error', reject);
    });

    let sessionKey: Uint8Array | null = null;
    let mcpId: string | null = null;
    let outboundSeq = 0;

    let helloCapabilities: string[] | undefined;

    const ready = new Promise<void>((resolveReady) => {
      extWs!.on('message', async (data) => {
        try {
          const parsed = JSON.parse(data.toString());
          const frame = validateFrame(parsed);

          if (frame.type === 'hello' && frame.role === 'server') {
            // Surface the capabilities the server actually sent on the
            // wire — this is half the point of the test.
            helloCapabilities = frame.capabilities;
            const identityX25519Pub = new Uint8Array(
              Buffer.from(frame.identityX25519Pub, 'base64'),
            );
            const sessionNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));
            const ephemeral = await generateX25519();
            const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
            sessionKey = await hkdfSha256(
              shared,
              sessionNonce,
              new TextEncoder().encode('fetchproxy/0.1.0/session'),
              32,
            );
            mcpId = frame.mcpId;
            const readyFrame: ReadyFrame = {
              type: 'ready',
              mcpId,
              extensionSessionPub: Buffer.from(ephemeral.publicKey).toString('base64'),
            };
            extWs!.send(JSON.stringify(readyFrame));
            resolveReady();
            return;
          }
          if (frame.type === 'frame') {
            if (!sessionKey || !mcpId || frame.mcpId !== mcpId) return;
            const inner = await openEncryptedFrame(sessionKey, frame);
            if (inner.type === 'request' && inner.op === 'read_cookies') {
              // Sanity-check the inner-request shape the server sent.
              expect(inner.init.tabUrl).toBe('https://creditkarma.com/');
              const respInner = {
                type: 'response' as const,
                id: inner.id,
                ok: true as const,
                op: 'read_cookies' as const,
                cookies: 'sid=secret; csrf=xyz',
              };
              outboundSeq += 1;
              const sealed = await sealInnerFrame(
                sessionKey,
                mcpId,
                outboundSeq,
                respInner,
              );
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
        protocolVersion: 1,
        role: 'extension',
        platform: 'chrome',
        extensionId: 'fetchproxy',
        version: '0.2.0',
      };
      extWs!.send(JSON.stringify(extHello));
    });

    await ready;

    // The cookies string we set in the mock above should arrive back at
    // the MCP unchanged.
    const cookies = await server.readCookies();
    expect(cookies).toBe('sid=secret; csrf=xyz');

    // And the wire-level hello must have surfaced the declared capabilities.
    expect(helloCapabilities).toEqual(['fetch', 'read_cookies']);
  }, 30_000);

  it("throws if readCookies() is called on an MCP that didn't declare the capability", async () => {
    const port = 41021;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-int-cookies-'));

    server = new FetchproxyServer({
      port,
      serverName: 'opentable-mcp',
      version: '0.0.1',
      domains: ['opentable.com'],
      // No capabilities -> defaults to ['fetch']
      identityDir: idDir,
    });
    await server.listen();

    // listen() succeeded; the developer-facing guard should bite without
    // any extension being connected, because it predates the wire send.
    await expect(server.readCookies()).rejects.toThrow(/read_cookies/);
  });
});
