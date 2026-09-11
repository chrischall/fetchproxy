import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { connectMockExtension } from './helpers/mock-extension.js';

/**
 * `MockExtension.closed()` must answer a close that has ALREADY landed.
 *
 * It used to attach its `'close'` listener at the moment it was called, which
 * is a race the caller cannot see and cannot win: the host answers a forged
 * `ready` by closing 1008 within a few milliseconds, and every caller reaches
 * `closed()` some awaits later. It held together only because those awaits
 * were fast — until `completeHandshake` grew an ECDH and an HKDF after the
 * send, and `extension-pin-host.test.ts` started timing out under a loaded
 * full-suite run. A latched close makes the helper's answer independent of
 * when it is asked.
 */

const MCP_ID = 'opentable-mcp:0.9.1:abc1234567890def';

let host: HostHandle | null = null;
afterEach(async () => {
  if (host) await host.close();
  host = null;
});

describe('the mock extension latches its close', () => {
  it('reports a refusal the caller only asks about later', async () => {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-mock-closed-'));
    host = await startHost({
      httpServer: el.server,
      ownIdentity: await loadOrCreateIdentity('opentable-mcp', idDir),
      ownMcpId: MCP_ID,
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: { allowNew: false, read: async () => null, write: async () => {} },
    });

    const ext = await connectMockExtension(port);
    await ext.completeHandshake(MCP_ID, { forgeSignature: true });

    // Stand in for the awaits a real caller happens to have between the
    // forged ready and its question: by here the 1008 is long gone.
    await new Promise((resolve) => setTimeout(resolve, 250));

    const { code } = await ext.closed();
    expect(code).toBe(1008);
    // Asking twice is still an answer, not a second wait.
    expect((await ext.closed()).code).toBe(1008);
  });
});
