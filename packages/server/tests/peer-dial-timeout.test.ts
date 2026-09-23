import { describe, it, expect, afterEach } from 'vitest';
import { createServer, type Server, type Socket } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startPeer } from '../src/peer.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { memoryTrust } from './helpers/concentrator.js';

// B-BUG-8: a listener that accepts TCP but never answers the WebSocket
// upgrade (a wedged / SIGSTOPped host, or a non-fetchproxy process on the
// port) left the peer dial pending forever — and with it every verb, since
// ensureConnected shares one connecting promise.

let server: Server | null = null;
const sockets: Socket[] = [];
afterEach(async () => {
  for (const s of sockets.splice(0)) s.destroy();
  await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
  server = null;
});

async function blackHole(): Promise<number> {
  server = createServer((sock) => {
    sockets.push(sock); // accept, never reply
  });
  await new Promise<void>((r) => server!.listen(0, '127.0.0.1', () => r()));
  return (server!.address() as { port: number }).port;
}

describe('B-BUG-8: peer dial handshake timeout', () => {
  it('rejects with a clear error when the host never answers the upgrade', async () => {
    const port = await blackHole();
    const identity = await loadOrCreateIdentity('t', mkdtempSync(join(tmpdir(), 'fp-dial-')));
    const started = Date.now();
    await expect(
      startPeer({
        host: '127.0.0.1',
        port,
        identity,
        mcpId: 't:abc',
        serverName: 't',
        version: '0.0.1',
        domains: ['example.com'],
        extensionTrust: memoryTrust(),
        dialTimeoutMs: 100,
      }),
    ).rejects.toThrow(/did not answer.*100ms/i);
    expect(Date.now() - started).toBeLessThan(2_000);
  });
});
