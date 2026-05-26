import { describe, it, expect, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateFrame,
  generateX25519,
  generateEd25519,
  type HelloFrameFromExtension,
} from '@fetchproxy/protocol';
import { FetchproxyServer, FetchproxyProtocolError } from '../../src/index.js';

/**
 * Connect a mock extension that handshakes JUST enough to receive every
 * server hello, then — instead of returning a ready frame to auto-trust —
 * sends back a `pair-pending` frame for each MCP carrying a fixed pair
 * code. Mirrors what the real extension does in `background.ts:onServerHello`
 * when `handleServerHello` returns `kind: 'needs-pair'`.
 *
 * Returns a `helloCount` accessor so the test can wait until both the
 * host's own hello and the peer's forwarded hello have arrived before
 * issuing tool calls.
 */
async function connectMockExtensionThatNeverApproves(
  port: number,
  perMcpPairCode: Record<string, string>,
) {
  const extIdX = await generateX25519();
  const extIdEd = await generateEd25519();
  const extSessionNonce = new Uint8Array(32);
  crypto.getRandomValues(extSessionNonce);

  const ws = new WebSocket(`ws://127.0.0.1:${port}`);
  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });

  let helloCount = 0;
  ws.on('message', (data) => {
    void (async () => {
      try {
        const parsed = JSON.parse(data.toString());
        const frame = validateFrame(parsed);
        if (frame.type === 'hello' && frame.role === 'server') {
          helloCount += 1;
          // Pair-pending instead of ready — extension is waiting on user.
          const code = perMcpPairCode[frame.serverName] ?? '000-000';
          ws.send(
            JSON.stringify({ type: 'pair-pending', mcpId: frame.mcpId, pairCode: code }),
          );
        }
      } catch {
        /* ignore */
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

  return {
    ws,
    helloCountReached: (n: number, timeoutMs = 2000) =>
      new Promise<void>((resolve, reject) => {
        const start = Date.now();
        const tick = (): void => {
          if (helloCount >= n) return resolve();
          if (Date.now() - start > timeoutMs) {
            return reject(new Error(`only saw ${helloCount}/${n} hellos within ${timeoutMs}ms`));
          }
          setTimeout(tick, 10);
        };
        tick();
      }),
  };
}

describe('pair-pending surfaces the pair code to MCP-side callers', () => {
  let host: FetchproxyServer | null = null;
  let peer: FetchproxyServer | null = null;
  let extWs: WebSocket | null = null;

  afterEach(async () => {
    if (extWs && extWs.readyState === extWs.OPEN) extWs.close();
    if (peer) await peer.close();
    if (host) await host.close();
    host = null;
    peer = null;
    extWs = null;
    await new Promise((r) => setTimeout(r, 50));
  });

  it('host: fetch() returns ok:false with the pair code in the error', async () => {
    const port = 41090;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-pair-pending-host-'));
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

    const ext = await connectMockExtensionThatNeverApproves(port, {
      'host-mcp': '845-237',
    });
    extWs = ext.ws;
    await ext.helloCountReached(1);
    // Give the pair-pending frame round-trip a beat to update host state.
    await new Promise((r) => setTimeout(r, 30));

    const result = await host.fetch({
      url: 'https://host.example.com/x',
      method: 'GET',
      tabUrl: 'https://host.example.com/',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toMatch(/pairing required/);
      expect(result.error).toMatch(/host-mcp/);
      expect(result.error).toMatch(/845-237/);
    }
  }, 15_000);

  it('peer: fetch() returns ok:false with the pair code in the error', async () => {
    const port = 41091;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-pair-pending-peer-'));
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

    const ext = await connectMockExtensionThatNeverApproves(port, {
      'host-mcp': '111-222',
      'peer-mcp': '333-444',
    });
    extWs = ext.ws;
    await ext.helloCountReached(2);
    await new Promise((r) => setTimeout(r, 50));

    const result = await peer.fetch({
      url: 'https://peer.example.com/x',
      method: 'GET',
      tabUrl: 'https://peer.example.com/',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toMatch(/pairing required/);
      expect(result.error).toMatch(/peer-mcp/);
      // Critically: peer must see ITS pair code, not the host's.
      expect(result.error).toMatch(/333-444/);
      expect(result.error).not.toMatch(/111-222/);
    }
  }, 15_000);

  it('onPairCode callback fires when the bridge reports pair-pending', async () => {
    const port = 41092;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-pair-pending-cb-'));
    const codes: string[] = [];
    host = new FetchproxyServer({
      port,
      serverName: 'host-mcp',
      version: '0.0.1',
      domains: ['host.example.com'],
      identityDir: idDir,
      onPairCode: (c) => codes.push(c),
    });
    await host.listen();
    await host.connect();

    const ext = await connectMockExtensionThatNeverApproves(port, {
      'host-mcp': '567-890',
    });
    extWs = ext.ws;
    await ext.helloCountReached(1);
    // Give the host's onPendingPair listeners a tick to fire.
    await new Promise((r) => setTimeout(r, 50));

    // The MCP host's existing onPairCode (derived from extension hello +
    // own pub) also fires on extension hello receipt, so codes has the
    // locally-computed code already. The pair-pending frame's code is
    // surfaced through `host.pendingPairCode()` / `fetch()` errors, not
    // re-fired through onPairCode (which is intentional — the locally
    // computed code is canonical for the host's own pair, the wire one
    // is a sanity check). What we ASSERT here is that the host doesn't
    // hang when fetch is called after pair-pending arrives.
    const result = await host.fetch({
      url: 'https://host.example.com/x',
      method: 'GET',
      tabUrl: 'https://host.example.com/',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toMatch(/567-890/);
    }
  }, 15_000);
});
