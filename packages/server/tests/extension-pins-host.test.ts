import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { fileExtensionTrust, type ExtensionTrustPort } from '../src/extension-trust.js';
import { extensionPinsPath } from '../src/extension-pins.js';
import {
  connectMockExtension,
  newExtensionIdentity,
  type CryptoKeyPairRaw,
} from './helpers/mock-extension.js';

/**
 * A3, host path: an MCP that holds the bridge port accepts only the
 * extensions the hosting provider listed, read from the managed pin-set file
 * on every handshake. See `extension-pins.test.ts` for the invariants.
 */

const MCP_ID = 'opentable-mcp:0.9.1:abc1234567890def';
const SERVER = 'opentable-mcp';
const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');

type Identity = { x25519: CryptoKeyPairRaw; ed25519: CryptoKeyPairRaw };

function entry(id: Identity, label?: string) {
  return {
    x25519Pub: b64(id.x25519.publicKey),
    ed25519Pub: b64(id.ed25519.publicKey),
    ...(label ? { label } : {}),
  };
}

function writeSet(dir: string, ...ids: Identity[]): void {
  writeFileSync(
    extensionPinsPath(SERVER, dir),
    JSON.stringify({ v: 1, managed: true, extensions: ids.map((id) => entry(id)) }),
  );
}

let host: HostHandle | null = null;
afterEach(async () => {
  if (host) await host.close();
  host = null;
  vi.restoreAllMocks();
});

function managedPort(trustDir: string): ExtensionTrustPort {
  return fileExtensionTrust({
    serverName: SERVER,
    trustDir,
    allowNew: false,
    extensionPins: 'managed',
  });
}

async function startTestHost(trust: ExtensionTrustPort): Promise<number> {
  const el = await electRole({ host: '127.0.0.1', port: 0 });
  if (el.role !== 'host') throw new Error('expected host');
  const port = (el.server.address() as AddressInfo).port;
  const idDir = mkdtempSync(join(tmpdir(), 'fp-mpin-id-'));
  host = await startHost({
    httpServer: el.server,
    ownIdentity: await loadOrCreateIdentity(SERVER, idDir),
    ownMcpId: MCP_ID,
    ownServerName: SERVER,
    ownVersion: '0.9.1',
    ownDomains: ['opentable.com'],
    extensionTrust: trust,
  });
  return port;
}

async function accepted(port: number, id: Identity): Promise<boolean> {
  const ext = await connectMockExtension(port, id);
  const outcome = await Promise.race([
    ext.completeHandshake(MCP_ID).then(async () => {
      await host!.sendOwnInner({ type: 'ping' });
      return true;
    }),
    ext.closed().then(() => false),
  ]);
  ext.close();
  await ext.closed();
  // Let the host process the close before the next connection claims the slot.
  await new Promise((r) => setTimeout(r, 20));
  return outcome;
}

async function refusal(port: number, id: Identity): Promise<{ code: number; reason: string }> {
  const ext = await connectMockExtension(port, id);
  const closed = await ext.closed();
  await new Promise((r) => setTimeout(r, 20));
  return closed;
}

describe('host: a host-managed extension pin set', () => {
  it('accepts every listed extension: E1 and E2', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpin-'));
    const e1 = await newExtensionIdentity();
    const e2 = await newExtensionIdentity();
    writeSet(trustDir, e1, e2);
    const port = await startTestHost(managedPort(trustDir));

    expect(await accepted(port, e1)).toBe(true);
    expect(await accepted(port, e2)).toBe(true);
  });

  it('refuses an unlisted extension, E3, with 1008', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpin-'));
    const e1 = await newExtensionIdentity();
    const e2 = await newExtensionIdentity();
    writeSet(trustDir, e1, e2);
    const port = await startTestHost(managedPort(trustDir));
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const { code, reason } = await refusal(port, await newExtensionIdentity());
    expect(code).toBe(1008);
    expect(reason).toBe('extension identity is not in the managed pin set');
    expect(warn).toHaveBeenCalled();
  });

  it("refuses E1's X25519 with E2's Ed25519, and the reverse — both keys or neither", async () => {
    // The mixed browser holds E2's (resp. E1's) signing key, so its `ready`
    // signature VERIFIES against the Ed25519 key its hello presents. The only
    // thing that can refuse it is requiring both keys to come from one entry.
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpin-'));
    const e1 = await newExtensionIdentity();
    const e2 = await newExtensionIdentity();
    writeSet(trustDir, e1, e2);
    const port = await startTestHost(managedPort(trustDir));
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    expect((await refusal(port, { x25519: e1.x25519, ed25519: e2.ed25519 })).code).toBe(1008);
    expect((await refusal(port, { x25519: e2.x25519, ed25519: e1.ed25519 })).code).toBe(1008);
    // The genuine pairs still work afterwards.
    expect(await accepted(port, e1)).toBe(true);
  });

  it('refuses every extension when the file is missing, logging EXTENSION_PINS_MISSING', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpin-'));
    const port = await startTestHost(managedPort(trustDir));
    const logs: string[] = [];
    vi.spyOn(console, 'warn').mockImplementation((m: unknown) => void logs.push(String(m)));
    vi.spyOn(console, 'error').mockImplementation((m: unknown) => void logs.push(String(m)));

    const id = await newExtensionIdentity();
    expect(await refusal(port, id)).toEqual({ code: 1008, reason: 'extension pin set unavailable' });
    const joined = logs.join('\n');
    expect(joined).toContain('EXTENSION_PINS_MISSING');
    expect(joined).toContain(extensionPinsPath(SERVER, trustDir));
    // Named the path, never a key.
    expect(joined).not.toContain(b64(id.x25519.publicKey));
    expect(joined).not.toContain(b64(id.ed25519.publicKey));
    // Once per handshake, not once per process.
    expect(logs.filter((l) => l.includes('EXTENSION_PINS_MISSING'))).toHaveLength(1);
    await refusal(port, id);
    expect(logs.filter((l) => l.includes('EXTENSION_PINS_MISSING'))).toHaveLength(2);
    // Fail closed means nothing got written in the file's place.
    expect(readdirSync(trustDir)).toEqual([]);
  });

  it('refuses every extension when the file is malformed, logging EXTENSION_PINS_MALFORMED', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpin-'));
    const e1 = await newExtensionIdentity();
    // E1 is in there — but a v2 file is not one this build can read, and a
    // file it cannot read admits nobody.
    writeFileSync(
      extensionPinsPath(SERVER, trustDir),
      JSON.stringify({ v: 2, managed: true, extensions: [entry(e1)] }),
    );
    const port = await startTestHost(managedPort(trustDir));
    const logs: string[] = [];
    vi.spyOn(console, 'warn').mockImplementation((m: unknown) => void logs.push(String(m)));
    vi.spyOn(console, 'error').mockImplementation((m: unknown) => void logs.push(String(m)));

    expect(await refusal(port, e1)).toEqual({ code: 1008, reason: 'extension pin set unavailable' });
    expect(logs.join('\n')).toContain('EXTENSION_PINS_MALFORMED');
    expect(logs.join('\n')).not.toContain(b64(e1.x25519.publicKey));
  });

  it('takes a changed file on the next handshake, with no restart (the read is never cached)', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpin-'));
    const e1 = await newExtensionIdentity();
    const e2 = await newExtensionIdentity();
    writeSet(trustDir, e1);
    const port = await startTestHost(managedPort(trustDir));
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    expect(await accepted(port, e1)).toBe(true);
    expect((await refusal(port, e2)).code).toBe(1008);

    // The host confirms E2 and revokes E1.
    writeSet(trustDir, e2);
    expect(await accepted(port, e2)).toBe(true);
    expect((await refusal(port, e1)).code).toBe(1008);
  });

  it('never writes a trust file — the directory listing is exactly what the host wrote', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpin-'));
    const e1 = await newExtensionIdentity();
    writeSet(trustDir, e1);
    const port = await startTestHost(managedPort(trustDir));
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    expect(await accepted(port, e1)).toBe(true);
    await refusal(port, await newExtensionIdentity());

    expect(readdirSync(trustDir)).toEqual([`${SERVER}.extension-pins.json`]);
  });

  it('never consults a first-use pin on disk, even one naming a stranger', async () => {
    // Managed mode replaces the first-use pin rather than layering on it: a
    // leftover `extension-trust.json` must neither admit nor block anybody.
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpin-'));
    const e1 = await newExtensionIdentity();
    const stranger = await newExtensionIdentity();
    writeSet(trustDir, e1);
    writeFileSync(
      join(trustDir, `${SERVER}.extension-trust.json`),
      JSON.stringify({
        identityX25519Pub: b64(stranger.x25519.publicKey),
        identityEd25519Pub: b64(stranger.ed25519.publicKey),
        pinnedAt: 1,
      }),
    );
    const port = await startTestHost(managedPort(trustDir));
    vi.spyOn(console, 'warn').mockImplementation(() => {});

    expect(await accepted(port, e1)).toBe(true);
    expect((await refusal(port, stranger)).code).toBe(1008);
  });

  it('ignores FETCHPROXY_TRUST_NEW_EXTENSION', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpin-'));
    writeSet(trustDir, await newExtensionIdentity());
    process.env.FETCHPROXY_TRUST_NEW_EXTENSION = '1';
    try {
      const trust = fileExtensionTrust({
        serverName: SERVER,
        trustDir,
        // What `FetchproxyServer` would compute from that variable.
        allowNew: true,
        extensionPins: 'managed',
      });
      const port = await startTestHost(trust);
      vi.spyOn(console, 'warn').mockImplementation(() => {});

      expect((await refusal(port, await newExtensionIdentity())).code).toBe(1008);
      expect(readdirSync(trustDir)).toEqual([`${SERVER}.extension-pins.json`]);
    } finally {
      delete process.env.FETCHPROXY_TRUST_NEW_EXTENSION;
    }
  });
});
