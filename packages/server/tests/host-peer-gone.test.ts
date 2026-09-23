import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { HelloFrameFromExtension } from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { buildTestPeerHello } from './helpers/peer-hello.js';

// B-BUG-9: when a peer's socket closes, the host tells the extension (if its
// hello accepts 'peer-gone') so the extension can drop that mcpId's session.

let host: HostHandle | null = null;
afterEach(async () => {
  if (host) await host.close();
  host = null;
});

const open = (ws: WebSocket) => new Promise<void>((r) => ws.once('open', () => r()));
const recorder = (ws: WebSocket): Record<string, unknown>[] => {
  const seen: Record<string, unknown>[] = [];
  ws.on('message', (data: Buffer) => seen.push(JSON.parse(data.toString())));
  return seen;
};

async function setup(extAccepts: string[] | undefined) {
  const el = await electRole({ host: '127.0.0.1', port: 0 });
  if (el.role !== 'host') throw new Error('expected host');
  const port = (el.server.address() as AddressInfo).port;
  const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-gone-'));
  host = await startHost({
    httpServer: el.server,
    ownIdentity: await loadOrCreateIdentity('opentable-mcp', idDir),
    ownMcpId: 'opentable-mcp:0.9.1:abc1234567890de1',
    ownServerName: 'opentable-mcp',
    ownVersion: '0.9.1',
    ownDomains: ['opentable.com'],
    extensionTrust: { allowNew: false, read: async () => null, write: async () => {} },
  });
  const ext = new WebSocket(`ws://127.0.0.1:${port}`);
  await open(ext);
  const extSeen = recorder(ext);
  ext.send(
    JSON.stringify({
      type: 'hello',
      protocolVersion: 4,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '3.2.0',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
      ...(extAccepts ? { accepts: extAccepts } : {}),
    } satisfies HelloFrameFromExtension),
  );
  await vi.waitFor(() => expect(host!.extensionConnected()).toBe(true));

  const peerMcpId = 'resy-mcp:0.0.1:abc1234567890de2';
  const peer = new WebSocket(`ws://127.0.0.1:${port}`);
  await open(peer);
  const peerSeen = recorder(peer);
  peer.send(
    JSON.stringify(
      await buildTestPeerHello({
        identity: await loadOrCreateIdentity('resy-mcp', idDir),
        mcpId: peerMcpId,
        serverName: 'resy-mcp',
        version: '0.0.1',
        domains: ['resy.com'],
      }),
    ),
  );
  // Registered once the host has relayed the extension hello to it.
  await vi.waitFor(() => expect(peerSeen.some((f) => f.type === 'hello')).toBe(true));
  return { ext, extSeen, peer, peerMcpId };
}

describe('B-BUG-9: host → extension peer-gone', () => {
  it('tells an extension that accepts it when a peer disconnects', async () => {
    const { ext, extSeen, peer, peerMcpId } = await setup(['peer-gone']);
    peer.close();
    await vi.waitFor(() => expect(extSeen).toContainEqual({ type: 'peer-gone', mcpId: peerMcpId }));
    ext.close();
  });

  it('sends nothing to an extension that did not advertise it', async () => {
    const { ext, extSeen, peer } = await setup(undefined);
    peer.close();
    await new Promise((r) => setTimeout(r, 100));
    expect(extSeen.some((f) => f.type === 'peer-gone')).toBe(false);
    ext.close();
  });
});
