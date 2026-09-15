import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * The identity is the one file whose loss re-keys the server and orphans every
 * trust record the extension holds for it, so a failure between "bytes staged"
 * and "bytes published" must leave the previous identity exactly as it was.
 * `rename` is the publish step; failing it is the sharpest way to prove the
 * target was never the file being written.
 */
const fsState = vi.hoisted(() => ({
  failRename: false,
  /** A directory whose mode this process cannot change (read-only mount). */
  lockedDir: undefined as string | undefined,
}));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return {
    ...actual,
    chmod: (async (path: never, mode: never) => {
      if (fsState.lockedDir !== undefined && String(path) === fsState.lockedDir) {
        throw Object.assign(new Error('EROFS: read-only file system'), { code: 'EROFS' });
      }
      return actual.chmod(path, mode);
    }) as typeof actual.chmod,
    rename: (async (from: never, to: never) => {
      if (fsState.failRename) {
        throw Object.assign(new Error('EXDEV: rename failed'), { code: 'EXDEV' });
      }
      return actual.rename(from, to);
    }) as typeof actual.rename,
  };
});

const { generateIdentity, loadOrCreateIdentity, writeIdentityFile } = await import(
  '../src/identity.js'
);

let root: string;
beforeEach(() => {
  fsState.failRename = false;
  root = mkdtempSync(join(tmpdir(), 'fp-id-atomic-'));
});
afterEach(() => {
  fsState.failRename = false;
  rmSync(root, { recursive: true, force: true });
});

describe('writeIdentityFile is atomic', () => {
  it('leaves the previous identity intact when the rename fails', async () => {
    const path = await writeIdentityFile(root, 'opentable-mcp', await generateIdentity());
    const before = readFileSync(path, 'utf8');

    fsState.failRename = true;
    await expect(
      writeIdentityFile(root, 'opentable-mcp', await generateIdentity()),
    ).rejects.toThrow(/EXDEV/);

    expect(readFileSync(path, 'utf8')).toBe(before);
  });

  it('leaves no staging file behind when the rename fails', async () => {
    await writeIdentityFile(root, 'opentable-mcp', await generateIdentity());
    fsState.failRename = true;
    await expect(
      writeIdentityFile(root, 'opentable-mcp', await generateIdentity()),
    ).rejects.toThrow();
    expect(readdirSync(root)).toEqual(['opentable-mcp.json']);
  });

  it('publishes only the target when nothing fails (control)', async () => {
    await writeIdentityFile(root, 'opentable-mcp', await generateIdentity());
    const second = await generateIdentity();
    const path = await writeIdentityFile(root, 'opentable-mcp', second);
    expect(readdirSync(root)).toEqual(['opentable-mcp.json']);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const again = await loadOrCreateIdentity('opentable-mcp', root);
    expect(Buffer.from(again.x25519Pub).equals(Buffer.from(second.x25519Pub))).toBe(true);
  });
});

describe('the identity directory is 0700 on every open', () => {
  it('tightens an existing 0755 directory when an identity is loaded from it', async () => {
    const dir = join(root, 'identity');
    await writeIdentityFile(dir, 'opentable-mcp', await generateIdentity());
    chmodSync(dir, 0o755);

    await loadOrCreateIdentity('opentable-mcp', dir);

    expect(statSync(dir).mode & 0o777).toBe(0o700);
  });

  it('tightens an existing 0755 directory when an identity is written into it', async () => {
    const dir = join(root, 'provisioned');
    mkdirSync(dir, { mode: 0o755 });
    chmodSync(dir, 0o755);

    await writeIdentityFile(dir, 'opentable-mcp', await generateIdentity());

    expect(statSync(dir).mode & 0o777).toBe(0o700);
  });

  /**
   * A host that PROVISIONS the identity mounts its directory read-only. The
   * mode there belongs to the provisioner; failing to tighten it must not stop
   * the server from reading the identity it was handed.
   */
  it('still loads an identity from a directory whose mode cannot be changed', async () => {
    const dir = join(root, 'mounted');
    const id = await generateIdentity();
    await writeIdentityFile(dir, 'opentable-mcp', id);

    fsState.lockedDir = dir;
    try {
      const loaded = await loadOrCreateIdentity('opentable-mcp', dir);
      expect(Buffer.from(loaded.x25519Pub).equals(Buffer.from(id.x25519Pub))).toBe(true);
    } finally {
      fsState.lockedDir = undefined;
    }
  });
});
