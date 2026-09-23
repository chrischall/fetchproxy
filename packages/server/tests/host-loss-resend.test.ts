import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  openEncryptedFrame,
  sealInnerFrame,
  type EncryptedFrame,
  type InnerRequest,
} from '@fetchproxy/protocol';
import { FetchproxyServer } from '../src/index.js';
import { startFakeConcentrator, newFakeExtension } from './helpers/concentrator.js';
import { connectMockExtension, type MockExtension } from './helpers/mock-extension.js';

// B-BUG-6: short-lived processes (a bootstrap lift, an `fpx` call) can win the
// port election, and their close() used to fail every other MCP's in-flight
// calls with "extension disconnected". A peer that loses its host now
// re-elects and re-sends the requests that are safe to repeat; only the ones
// that may already have run (a POST, a cookie write, a download) fail.

let server: FetchproxyServer | null = null;
let ext: MockExtension | null = null;
afterEach(async () => {
  ext?.close();
  ext = null;
  if (server) await server.close();
  server = null;
});

describe('B-BUG-6: a peer survives its host exiting', () => {
  it('re-sends an in-flight GET through the re-elected bridge and fails the POST', async () => {
    const rig = await startFakeConcentrator();
    const dir = mkdtempSync(join(tmpdir(), 'fp-hostloss-'));
    server = new FetchproxyServer({
      serverName: 'resy-mcp',
      version: '0.9.1',
      domains: ['resy.com'],
      host: '127.0.0.1',
      port: rig.port,
      identityDir: dir,
      trustDir: dir,
      allowNewExtensionIdentity: true,
      fetchTimeoutMs: 15_000,
      bridgeReviveDelayMs: 0,
      keepAliveIntervalMs: 0,
    });
    await server.listen();
    const mcpId = (server as unknown as { mcpId: string }).mcpId;

    const get = server.fetch({
      url: 'https://resy.com/a',
      method: 'GET',
      tabUrl: 'https://resy.com/',
    });
    // The peer handshake with the short-lived "host".
    await rig.waitForHello();
    const ext1 = await newFakeExtension();
    await rig.relayExtensionHello(ext1);
    await rig.answerReady(ext1, await rig.waitForHello(1));
    await rig.waitForFrames(1);
    const post = server.fetch({
      url: 'https://resy.com/book',
      method: 'POST',
      tabUrl: 'https://resy.com/',
    });
    await rig.waitForFrames(2);

    // The short-lived host exits, releasing the port.
    (await rig.socket()).terminate();
    await rig.close();

    const postResult = await post;
    expect(postResult.ok).toBe(false);
    if (!postResult.ok) expect(postResult.error).toMatch(/may already have run/);

    // This process re-elects (the port is free, so it becomes the host); the
    // extension reconnects to it and the GET is re-sent there.
    await vi.waitFor(() => expect(server!.bridgeHealth().role).toBe('host'));
    ext = await connectMockExtension(rig.port);
    const key = await ext.completeHandshake(mcpId);
    await vi.waitFor(() =>
      expect(ext!.framesFor(mcpId).some((f) => f.type === 'frame')).toBe(true),
    );
    const sealed = ext
      .framesFor(mcpId)
      .find((f) => f.type === 'frame') as unknown as EncryptedFrame;
    const req = (await openEncryptedFrame(key, sealed, 's2e')) as InnerRequest;
    expect(req.op).toBe('fetch');
    if (req.op === 'fetch') expect(req.init.method).toBe('GET');
    ext.ws.send(
      JSON.stringify(
        await sealInnerFrame(
          key,
          mcpId,
          1,
          {
            type: 'response',
            id: req.id,
            ok: true,
            op: 'fetch',
            status: 200,
            url: 'https://resy.com/a',
            body: 'ok',
          },
          'e2s',
        ),
      ),
    );
    const getResult = await get;
    expect(getResult.ok).toBe(true);
    if (getResult.ok) expect(getResult.body).toBe('ok');
  }, 20_000);
});
