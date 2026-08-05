import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import type { ExtensionPin, ExtensionTrustPort } from '../src/extension-trust.js';
import { connectMockExtension, newExtensionIdentity } from './helpers/mock-extension.js';

/**
 * #208, host path: the MCP pins the extension's identity.
 *
 * Before this, `host.ts` verified `ready.sessionSig` against the identity in
 * the hello it had just received — proof that the connecting party holds the
 * key it showed us, and no evidence at all that it is the party we paired
 * with. These tests are about the second half.
 */

const MCP_ID = 'opentable-mcp:0.9.1:abc1234567890def';

interface MemoryTrust extends ExtensionTrustPort {
  writes: ExtensionPin[];
}

function memoryTrust(initial: ExtensionPin | null = null, allowNew = false): MemoryTrust {
  let pin = initial;
  const writes: ExtensionPin[] = [];
  return {
    allowNew,
    writes,
    read: async () => pin,
    write: async (next) => {
      pin = next;
      writes.push(next);
    },
  };
}

let host: HostHandle | null = null;
afterEach(async () => {
  if (host) await host.close();
  host = null;
});

async function startTestHost(trust: ExtensionTrustPort): Promise<number> {
  const el = await electRole({ host: '127.0.0.1', port: 0 });
  if (el.role !== 'host') throw new Error('expected host');
  const port = (el.server.address() as AddressInfo).port;
  const idDir = mkdtempSync(join(tmpdir(), 'fp-pin-'));
  host = await startHost({
    httpServer: el.server,
    ownIdentity: await loadOrCreateIdentity('opentable-mcp', idDir),
    ownMcpId: MCP_ID,
    ownServerName: 'opentable-mcp',
    ownVersion: '0.9.1',
    ownDomains: ['opentable.com'],
    extensionTrust: trust,
  });
  return port;
}

describe('the host pins the extension it paired with', () => {
  it('trusts the first extension and records it once the signature proves the key', async () => {
    const trust = memoryTrust();
    const port = await startTestHost(trust);

    const ext = await connectMockExtension(port);
    await ext.completeHandshake(MCP_ID);
    await host!.sendOwnInner({ type: 'ping' });

    expect(trust.writes).toHaveLength(1);
    expect(trust.writes[0]).toMatchObject({
      identityX25519Pub: ext.hello.identityX25519Pub,
      identityEd25519Pub: ext.hello.identityEd25519Pub,
    });
    ext.close();
  });

  it('does NOT pin an identity that failed to prove itself', async () => {
    // The ordering is the point: a claimant that cannot sign must not be able
    // to install itself as the pinned extension and lock the real one out.
    const trust = memoryTrust();
    const port = await startTestHost(trust);

    const ext = await connectMockExtension(port);
    await ext.completeHandshake(MCP_ID, { forgeSignature: true });
    const { code } = await ext.closed();

    expect(code).toBe(1008);
    expect(trust.writes).toEqual([]);
  });

  it('recognises the same extension on a later connection', async () => {
    const identity = await newExtensionIdentity();
    const first = await connectMockExtension(await startTestHost(memoryTrust()), identity);
    // Re-pin from that first pairing, then reconnect as the same browser.
    const trust = memoryTrust(first.pin());
    first.close();
    await host!.close();
    host = null;

    const port = await startTestHost(trust);
    const again = await connectMockExtension(port, identity);
    await again.completeHandshake(MCP_ID);
    // The session deriving at all is the proof it was accepted.
    await expect(host!.sendOwnInner({ type: 'ping' })).resolves.toBeUndefined();
    // Nothing to rewrite — the pin already says this.
    expect(trust.writes).toEqual([]);
    again.close();
  });

  it('refuses a different extension identity, before any session exists', async () => {
    const other = await newExtensionIdentity();
    const strangerPin: ExtensionPin = {
      identityX25519Pub: Buffer.from(other.x25519.publicKey).toString('base64'),
      identityEd25519Pub: Buffer.from(other.ed25519.publicKey).toString('base64'),
      pinnedAt: 1_700_000_000_000,
    };
    const trust = memoryTrust(strangerPin);
    const port = await startTestHost(trust);

    const ext = await connectMockExtension(port);
    const { code, reason } = await ext.closed();

    expect(code).toBe(1008);
    expect(reason).toMatch(/identity/i);
    expect(trust.writes).toEqual([]);
  });

  it('replaces the pin when the operator allowed a new identity', async () => {
    const other = await newExtensionIdentity();
    const trust = memoryTrust(
      {
        identityX25519Pub: Buffer.from(other.x25519.publicKey).toString('base64'),
        identityEd25519Pub: Buffer.from(other.ed25519.publicKey).toString('base64'),
        pinnedAt: 1_700_000_000_000,
      },
      true,
    );
    const port = await startTestHost(trust);

    const ext = await connectMockExtension(port);
    await ext.completeHandshake(MCP_ID);
    await host!.sendOwnInner({ type: 'ping' });

    expect(trust.writes).toHaveLength(1);
    expect(trust.writes[0]?.identityX25519Pub).toBe(ext.hello.identityX25519Pub);
    ext.close();
  });

  it('refuses rather than serving when the pin cannot be read', async () => {
    // Fail closed: an unreadable pin file is the one state in which "carry on"
    // would silently mean "trust anyone".
    const trust: ExtensionTrustPort = {
      allowNew: false,
      read: async () => {
        throw new Error('unreadable extension pin at /tmp/x — delete it to re-pair');
      },
      write: async () => {},
    };
    const port = await startTestHost(trust);

    const ext = await connectMockExtension(port);
    const { code } = await ext.closed();
    expect(code).toBe(1008);
  });
});
