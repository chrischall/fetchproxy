import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { sealInnerFrame, type InnerFrame } from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { connectMockExtension, type MockExtension } from './helpers/mock-extension.js';

// B-BUG-4: on the host role, one frame addressed to the host's OWN session
// that failed GCM or failed validation was rethrown into the socket handler,
// which closed the EXTENSION socket with 1011 — disconnecting the extension
// from every MCP on the concentrator. The peer path already handled both
// cases per frame; the host must too.

const MCP_ID = 'opentable-mcp:0.9.1:abc1234567890def';

let host: HostHandle | null = null;
let ext: MockExtension | null = null;
afterEach(async () => {
  vi.restoreAllMocks();
  ext?.close();
  ext = null;
  if (host) await host.close();
  host = null;
});

async function linkedHost(): Promise<{ key: Uint8Array; received: InnerFrame[] }> {
  const el = await electRole({ host: '127.0.0.1', port: 0 });
  if (el.role !== 'host') throw new Error('expected host');
  const port = (el.server.address() as AddressInfo).port;
  host = await startHost({
    httpServer: el.server,
    ownIdentity: await loadOrCreateIdentity('opentable-mcp', mkdtempSync(join(tmpdir(), 'fp-badframe-'))),
    ownMcpId: MCP_ID,
    ownServerName: 'opentable-mcp',
    ownVersion: '0.9.1',
    ownDomains: ['opentable.com'],
    extensionTrust: { allowNew: false, read: async () => null, write: async () => {} },
  });
  ext = await connectMockExtension(port);
  const key = await ext.completeHandshake(MCP_ID);
  await vi.waitFor(() => expect(host!.sessionLinked()).toBe(true));
  const received: InnerFrame[] = [];
  host.onOwnInner((inner) => received.push(inner));
  return { key, received };
}

describe('B-BUG-4: host survives one bad frame on its own session', () => {
  it('drops an undecryptable frame and keeps the extension connected', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const { key, received } = await linkedHost();
    const wrongKey = new Uint8Array(32).fill(7);
    ext!.ws.send(JSON.stringify(await sealInnerFrame(wrongKey, MCP_ID, 1, { type: 'pong' }, 'e2s')));
    // The genuine frame behind it (same seq — the forged one must not spend it).
    ext!.ws.send(JSON.stringify(await sealInnerFrame(key, MCP_ID, 1, { type: 'pong' }, 'e2s')));
    await vi.waitFor(() => expect(received).toHaveLength(1));
    expect(host!.extensionConnected()).toBe(true);
    expect(ext!.ws.readyState).toBe(ext!.ws.OPEN);
  });

  it('fails only the affected request when a frame decrypts but fails validation', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const { key, received } = await linkedHost();
    const bad = new TextEncoder().encode(
      JSON.stringify({ type: 'response', id: 42, op: 'fetch', ok: 'not-a-boolean' }),
    );
    ext!.ws.send(JSON.stringify(await sealInnerFrame(key, MCP_ID, 1, bad, 'e2s')));
    await vi.waitFor(() => expect(received).toHaveLength(1));
    expect(received[0]).toMatchObject({ type: 'response', id: 42, ok: false });
    expect(errors).toHaveBeenCalled();
    // The link is intact: the next genuine frame is delivered.
    ext!.ws.send(JSON.stringify(await sealInnerFrame(key, MCP_ID, 2, { type: 'pong' }, 'e2s')));
    await vi.waitFor(() => expect(received).toHaveLength(2));
    expect(ext!.ws.readyState).toBe(ext!.ws.OPEN);
  });
});
