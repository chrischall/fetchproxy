import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  generateIdentity,
  identityFilePath,
  loadOrCreateIdentity,
  parseIdentity,
  serializeIdentity,
  writeIdentityFile,
  type Identity,
} from '../src/identity.js';

/**
 * THE ON-DISK IDENTITY FORMAT IS A CONTRACT (#319).
 *
 * It used to be an implementation detail of `loadOrCreateIdentity`, which was
 * fine while this package was the only thing that read or wrote it. It is not
 * any more: a host that runs one child per caller has to PROVISION the identity
 * so every child of one registration presents the same one (#316), and that
 * means writing these exact bytes from another repo.
 *
 * The vector is what makes that safe. Without it the failure is silent — this
 * package renames a field, the host keeps writing the old one, every hosted MCP
 * mints a fresh identity and asks to pair again. Which is the original bug,
 * arriving through its own fix.
 *
 * `fixtures/identity-format.json` is committed and meant to be VENDORED by a
 * consumer, the way mcp-host vendors `seal-vectors.json` to hold four
 * implementations of a sealed-secret format to one wire shape.
 */
const FIXTURE = JSON.parse(
  readFileSync(join(fileURLToPath(new URL('../fixtures/identity-format.json', import.meta.url))), 'utf8'),
) as { identity: Record<string, string | number> };

const fromFixture = (): Identity =>
  parseIdentity(JSON.stringify(FIXTURE.identity));

describe('the identity file format', () => {
  /**
   * The bytes, exactly. Two-space JSON in a fixed key order — asserted as a
   * STRING rather than by deep-equal, because a consumer writing this file
   * writes bytes, and "same object once parsed" would let the shape drift in
   * ways that still break a byte comparison downstream.
   */
  it('serialises to the committed vector, byte for byte', () => {
    expect(serializeIdentity(fromFixture())).toBe(JSON.stringify(FIXTURE.identity, null, 2));
  });

  it('round-trips through parse', () => {
    const id = fromFixture();
    expect(parseIdentity(serializeIdentity(id))).toEqual(id);
  });

  /** Every field survives, and none is quietly dropped or renamed. */
  it('carries exactly the five documented fields', () => {
    const parsed = JSON.parse(serializeIdentity(fromFixture()));
    expect(Object.keys(parsed)).toEqual([
      'x25519Priv',
      'x25519Pub',
      'ed25519Priv',
      'ed25519Pub',
      'createdAt',
    ]);
  });

  /**
   * The point of the whole exercise: an identity written by SOMEBODY ELSE is
   * read back by this package as its own. That is what a host provisioning one
   * is relying on.
   */
  it('is read back by loadOrCreateIdentity when a host wrote it', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fp-fmt-'));
    const provisioned = fromFixture();
    const path = await writeIdentityFile(dir, 'opentable-mcp', provisioned);
    expect(path).toBe(identityFilePath(dir, 'opentable-mcp'));

    const loaded = await loadOrCreateIdentity('opentable-mcp', dir);
    expect(Buffer.from(loaded.x25519Pub)).toEqual(Buffer.from(provisioned.x25519Pub));
    expect(Buffer.from(loaded.ed25519Priv)).toEqual(Buffer.from(provisioned.ed25519Priv));
    expect(loaded.createdAt).toBe(provisioned.createdAt);
    // It did NOT mint a replacement — the file on disk is still the one written.
    expect(await readFile(path, 'utf8')).toBe(serializeIdentity(provisioned));
  });

  /** A provisioned file is as private as a minted one. */
  it('writes 0600, whatever the umask', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fp-fmt-mode-'));
    const path = await writeIdentityFile(dir, 'opentable-mcp', fromFixture());
    expect(statSync(path).mode & 0o777).toBe(0o600);
    expect(statSync(dir).mode & 0o777).toBe(0o700);
  });

  /**
   * The path is derived through `safeIdentityFileBase`, so a scoped name is
   * translated the same way for a provisioner as for this package — a host
   * that string-joined `${serverName}.json` would write `@scope/name.json`
   * into a directory that does not exist.
   */
  it('translates a scoped server name the same way for both sides', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fp-fmt-scoped-'));
    const id = await generateIdentity();
    const path = await writeIdentityFile(dir, '@fetchproxy/example-mcp', id);
    expect(path).toBe(join(dir, '@fetchproxy_example-mcp.json'));
    const loaded = await loadOrCreateIdentity('@fetchproxy/example-mcp', dir);
    expect(Buffer.from(loaded.x25519Pub)).toEqual(Buffer.from(id.x25519Pub));
  });

  /** Keygen is keygen: no I/O, and two calls are two identities. */
  it('generateIdentity writes nothing and repeats nothing', async () => {
    const a = await generateIdentity();
    const b = await generateIdentity();
    expect(Buffer.from(a.x25519Pub)).not.toEqual(Buffer.from(b.x25519Pub));
    expect(a.x25519Priv.length).toBe(32);
    expect(a.ed25519Pub.length).toBe(32);
  });
});
