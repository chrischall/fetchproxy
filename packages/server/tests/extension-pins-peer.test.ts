import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { fileExtensionTrust } from '../src/extension-trust.js';
import { extensionPinsPath } from '../src/extension-pins.js';
import {
  newFakeExtension,
  startFakeConcentrator,
  type FakeConcentrator,
  type FakeExtension,
} from './helpers/concentrator.js';

/**
 * A3, peer path: an MCP behind the concentrator checks the RELAYED extension
 * hello against the managed pin set, fresh on every `ready` it authenticates.
 *
 * The first-use peer path reads its pin once per process (an MV3 eviction
 * renegotiates often, and a disk read there widens a race). Managed mode
 * cannot keep that cache: the set is how a host revokes a browser, and a
 * cached set would keep admitting a revoked one until the child restarts.
 */

const MCP_ID = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';
const SERVER = 'opentable-mcp';

function entry(e: FakeExtension) {
  return { x25519Pub: e.hello.identityX25519Pub, ed25519Pub: e.hello.identityEd25519Pub };
}

function writeSet(dir: string, ...exts: FakeExtension[]): void {
  writeFileSync(
    extensionPinsPath(SERVER, dir),
    JSON.stringify({ v: 1, managed: true, extensions: exts.map(entry) }),
  );
}

/** A browser holding `signer`'s Ed25519 key while presenting `x`'s X25519 key. */
async function mixed(x: FakeExtension, signer: FakeExtension): Promise<FakeExtension> {
  const fresh = await newFakeExtension(signer);
  return {
    ...fresh,
    hello: { ...fresh.hello, identityX25519Pub: x.hello.identityX25519Pub },
  };
}

let peer: InternalPeerHandle | null = null;
let rig: FakeConcentrator | null = null;
afterEach(async () => {
  if (peer) peer.close();
  peer = null;
  if (rig) await rig.close();
  rig = null;
  vi.restoreAllMocks();
});

async function startManagedPeer(
  trustDir: string,
  allowNew = false,
): Promise<{ rig: FakeConcentrator; closed: Promise<number> }> {
  rig = await startFakeConcentrator();
  const idDir = mkdtempSync(join(tmpdir(), 'fp-mpeer-id-'));
  peer = await startPeer({
    host: '127.0.0.1',
    port: rig.port,
    identity: await loadOrCreateIdentity(SERVER, idDir),
    mcpId: MCP_ID,
    serverName: SERVER,
    version: '0.9.1',
    domains: ['opentable.com'],
    extensionTrust: fileExtensionTrust({
      serverName: SERVER,
      trustDir,
      allowNew,
      extensionPins: 'managed',
    }),
  });
  // Unhandled, the first-ready rejection a refusal causes fails the run.
  peer.session.catch(() => {});
  const socket = await rig.socket();
  const closed = new Promise<number>((resolve) => socket.once('close', (code) => resolve(code)));
  await rig.waitForHello(0);
  return { rig, closed };
}

/** Relay `ext`, answer the hello it triggers, and report the outcome. */
async function handshake(
  r: FakeConcentrator,
  ext: FakeExtension,
  nth: number,
  closed: Promise<number>,
): Promise<'linked' | number> {
  await r.relayExtensionHello(ext);
  const hello = await r.waitForHello(nth);
  await r.answerReady(ext, hello);
  const deadline = Date.now() + 2_000;
  for (;;) {
    const code = await Promise.race([
      closed,
      new Promise<null>((res) => setTimeout(() => res(null), 10)),
    ]);
    if (code !== null) return code;
    if (peer!.sessionLinked()) return 'linked';
    if (Date.now() > deadline) throw new Error('neither linked nor refused');
  }
}

describe('peer: a host-managed extension pin set', () => {
  it('accepts a listed extension (E1) and a listed second browser (E2)', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpeer-'));
    const e1 = await newFakeExtension();
    const e2 = await newFakeExtension();
    writeSet(trustDir, e1, e2);
    const { rig: r, closed } = await startManagedPeer(trustDir);

    expect(await handshake(r, e1, 1, closed)).toBe('linked');
    await r.relayExtensionDisconnected();
    expect(await handshake(r, e2, 2, closed)).toBe('linked');
  });

  it('refuses an unlisted extension (E3) with 1008', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpeer-'));
    writeSet(trustDir, await newFakeExtension(), await newFakeExtension());
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { rig: r, closed } = await startManagedPeer(trustDir);

    expect(await handshake(r, await newFakeExtension(), 1, closed)).toBe(1008);
  });

  it("refuses E1's X25519 with E2's Ed25519", async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpeer-'));
    const e1 = await newFakeExtension();
    const e2 = await newFakeExtension();
    writeSet(trustDir, e1, e2);
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { rig: r, closed } = await startManagedPeer(trustDir);

    // The signature verifies — the mix holds E2's signing key — so only the
    // both-keys rule can refuse it.
    expect(await handshake(r, await mixed(e1, e2), 1, closed)).toBe(1008);
  });

  it("refuses E2's X25519 with E1's Ed25519", async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpeer-'));
    const e1 = await newFakeExtension();
    const e2 = await newFakeExtension();
    writeSet(trustDir, e1, e2);
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { rig: r, closed } = await startManagedPeer(trustDir);

    expect(await handshake(r, await mixed(e2, e1), 1, closed)).toBe(1008);
  });

  it('refuses everything when the file is missing, and names the code', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpeer-'));
    const logs: string[] = [];
    vi.spyOn(console, 'warn').mockImplementation((m: unknown) => void logs.push(String(m)));
    vi.spyOn(console, 'error').mockImplementation((m: unknown) => void logs.push(String(m)));
    const { rig: r, closed } = await startManagedPeer(trustDir);
    const e1 = await newFakeExtension();

    expect(await handshake(r, e1, 1, closed)).toBe(1008);
    expect(logs.join('\n')).toContain('EXTENSION_PINS_MISSING');
    expect(logs.join('\n')).not.toContain(e1.hello.identityX25519Pub);
    expect(readdirSync(trustDir)).toEqual([]);
  });

  it('refuses everything when the file is malformed', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpeer-'));
    writeFileSync(extensionPinsPath(SERVER, trustDir), '{"v":1,"managed":true,"extensions":[{}]}');
    const logs: string[] = [];
    vi.spyOn(console, 'warn').mockImplementation((m: unknown) => void logs.push(String(m)));
    vi.spyOn(console, 'error').mockImplementation((m: unknown) => void logs.push(String(m)));
    const { rig: r, closed } = await startManagedPeer(trustDir);

    expect(await handshake(r, await newFakeExtension(), 1, closed)).toBe(1008);
    expect(logs.join('\n')).toContain('EXTENSION_PINS_MALFORMED');
  });

  it('reads the set afresh on every handshake — a change needs no restart', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpeer-'));
    const e1 = await newFakeExtension();
    const e2 = await newFakeExtension();
    writeSet(trustDir, e1);
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { rig: r, closed } = await startManagedPeer(trustDir);

    expect(await handshake(r, e1, 1, closed)).toBe('linked');

    // The host confirms a second browser: admitted with no restart.
    writeSet(trustDir, e1, e2);
    await r.relayExtensionDisconnected();
    expect(await handshake(r, e2, 2, closed)).toBe('linked');

    // …and revokes the first: refused on its very next handshake.
    writeSet(trustDir, e2);
    await r.relayExtensionDisconnected();
    expect(await handshake(r, await newFakeExtension(e1), 3, closed)).toBe(1008);
  });

  it('never writes a trust file, and ignores an allow-new-identity request', async () => {
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-mpeer-'));
    const e1 = await newFakeExtension();
    writeSet(trustDir, e1);
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { rig: r, closed } = await startManagedPeer(trustDir, true);

    expect(await handshake(r, e1, 1, closed)).toBe('linked');
    await r.relayExtensionDisconnected();
    expect(await handshake(r, await newFakeExtension(), 2, closed)).toBe(1008);
    expect(readdirSync(trustDir)).toEqual([`${SERVER}.extension-pins.json`]);
  });
});
