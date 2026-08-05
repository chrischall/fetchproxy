import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm, readFile, writeFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  decideExtensionTrust,
  readExtensionPin,
  writeExtensionPin,
  clearExtensionPin,
  extensionTrustPath,
  type ExtensionPin,
} from '../src/extension-trust.js';

/**
 * #208 — the MCP side pins the extension's identity.
 *
 * The extension has always pinned the MCP (`trustedMcps`, keyed by the SHA-256
 * of its X25519 pub). The MCP has never pinned the extension: `host.ts`
 * verifies `ready.sessionSig` against the identity presented in the SAME
 * connection, which proves freshness and says nothing about continuity, and
 * `peer.ts` verifies nothing at all. On loopback that's deliberate. Over a
 * network it means whoever reaches the endpoint is the browser.
 */

const HELLO_A = { identityX25519Pub: 'QUFB', identityEd25519Pub: 'QkJC' };
const HELLO_B = { identityX25519Pub: 'Q0ND', identityEd25519Pub: 'RERE' };

function pinOf(hello: typeof HELLO_A, pinnedAt = 1_700_000_000_000): ExtensionPin {
  return { ...hello, pinnedAt };
}

describe('decideExtensionTrust', () => {
  it('trusts the first extension it ever sees', () => {
    expect(
      decideExtensionTrust({ pin: null, hello: HELLO_A, allowNew: false, serverName: 'x-mcp' }),
    ).toEqual({ decision: 'first-use' });
  });

  it('recognises the pinned extension on every later connection', () => {
    expect(
      decideExtensionTrust({
        pin: pinOf(HELLO_A),
        hello: HELLO_A,
        allowNew: false,
        serverName: 'x-mcp',
      }),
    ).toEqual({ decision: 'pinned' });
  });

  it('refuses a different extension identity', () => {
    const out = decideExtensionTrust({
      pin: pinOf(HELLO_A),
      hello: HELLO_B,
      allowNew: false,
      serverName: 'x-mcp',
    });
    expect(out.decision).toBe('refused');
    // The refusal has to be actionable: an extension re-install legitimately
    // mints a new identity, and a user who is only told "refused" is stuck.
    if (out.decision !== 'refused') throw new Error('unreachable');
    expect(out.message).toContain('x-mcp');
    expect(out.message).toMatch(/FETCHPROXY_TRUST_NEW_EXTENSION/);
  });

  it('refuses a half-match — one key rotated is not the same extension', () => {
    for (const hello of [
      { identityX25519Pub: HELLO_A.identityX25519Pub, identityEd25519Pub: HELLO_B.identityEd25519Pub },
      { identityX25519Pub: HELLO_B.identityX25519Pub, identityEd25519Pub: HELLO_A.identityEd25519Pub },
    ]) {
      expect(
        decideExtensionTrust({ pin: pinOf(HELLO_A), hello, allowNew: false, serverName: 'x-mcp' })
          .decision,
      ).toBe('refused');
    }
  });

  it('replaces the pin when the operator has explicitly allowed a new identity', () => {
    const out = decideExtensionTrust({
      pin: pinOf(HELLO_A),
      hello: HELLO_B,
      allowNew: true,
      serverName: 'x-mcp',
    });
    expect(out.decision).toBe('replace');
  });

  it('does not treat allowNew as a reason to skip pinning a first contact', () => {
    expect(
      decideExtensionTrust({ pin: null, hello: HELLO_A, allowNew: true, serverName: 'x-mcp' }),
    ).toEqual({ decision: 'first-use' });
  });
});

describe('the pin on disk', () => {
  let dir: string;

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'fp-trust-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('is absent until something pins, and reads back what was pinned', async () => {
    expect(await readExtensionPin('opentable-mcp', dir)).toBeNull();
    await writeExtensionPin('opentable-mcp', pinOf(HELLO_A), dir);
    expect(await readExtensionPin('opentable-mcp', dir)).toEqual(pinOf(HELLO_A));
  });

  it('is per MCP, like the identity beside it', async () => {
    await writeExtensionPin('opentable-mcp', pinOf(HELLO_A), dir);
    expect(await readExtensionPin('resy-mcp', dir)).toBeNull();
    expect(extensionTrustPath('opentable-mcp', dir)).not.toBe(extensionTrustPath('resy-mcp', dir));
  });

  it('is written 0600 — it sits next to a private key', async () => {
    await writeExtensionPin('opentable-mcp', pinOf(HELLO_A), dir);
    const st = await stat(extensionTrustPath('opentable-mcp', dir));
    expect(st.mode & 0o777).toBe(0o600);
  });

  it('keeps a scoped package name inside its own directory', async () => {
    await writeExtensionPin('@fetchproxy/example-mcp', pinOf(HELLO_A), dir);
    const path = extensionTrustPath('@fetchproxy/example-mcp', dir);
    expect(path.startsWith(dir)).toBe(true);
    expect(path).not.toContain('/example-mcp.');
    expect(await readExtensionPin('@fetchproxy/example-mcp', dir)).toEqual(pinOf(HELLO_A));
  });

  it('refuses a serverName that would escape the directory', async () => {
    for (const evil of ['../escape', 'a/b', '..', '']) {
      await expect(readExtensionPin(evil, dir), evil).rejects.toThrow(/unsafe/);
    }
  });

  it('refuses to read a corrupt pin rather than silently starting over', async () => {
    // Fail-closed: treating an unreadable pin as "no pin" would turn any
    // scribble on the file into a fresh trust-on-first-use.
    await writeFile(extensionTrustPath('opentable-mcp', dir), '{ not json', 'utf8');
    await expect(readExtensionPin('opentable-mcp', dir)).rejects.toThrow(/pin/i);
  });

  it('clears a pin, and says whether there was one', async () => {
    expect(await clearExtensionPin('opentable-mcp', dir)).toBe(false);
    await writeExtensionPin('opentable-mcp', pinOf(HELLO_A), dir);
    expect(await clearExtensionPin('opentable-mcp', dir)).toBe(true);
    expect(await readExtensionPin('opentable-mcp', dir)).toBeNull();
  });

  it('replaces a pin whole, leaving no half-written file behind', async () => {
    await writeExtensionPin('opentable-mcp', pinOf(HELLO_A), dir);
    await writeExtensionPin('opentable-mcp', pinOf(HELLO_B, 1_800_000_000_000), dir);
    const raw = await readFile(extensionTrustPath('opentable-mcp', dir), 'utf8');
    expect(JSON.parse(raw)).toEqual(pinOf(HELLO_B, 1_800_000_000_000));
  });
});
