import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
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
  /** The errno a `chmod` of `lockedDir` fails with. */
  lockedCode: 'EROFS',
}));

vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs/promises')>();
  return {
    ...actual,
    chmod: (async (path: never, mode: never) => {
      if (fsState.lockedDir !== undefined && String(path) === fsState.lockedDir) {
        const code = fsState.lockedCode;
        throw Object.assign(new Error(`${code}: chmod refused`), { code });
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
  fsState.lockedDir = undefined;
  fsState.lockedCode = 'EROFS';
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

/**
 * The staging name is random so two writers never share one, which means a
 * SIGKILL between "staged" and "renamed" leaves a 0600 file holding a whole
 * private identity under a name no later write would ever reuse. The next
 * write is the one place that can find it, so it must.
 */
describe('a staging file left by a crashed write', () => {
  const LEFTOVER = 'opentable-mcp.json.0123456789ab.tmp';

  it('does not block the next write and does not survive it', async () => {
    writeFileSync(join(root, LEFTOVER), 'half a private key', { mode: 0o600 });

    const id = await generateIdentity();
    const path = await writeIdentityFile(root, 'opentable-mcp', id);

    expect(readdirSync(root)).toEqual(['opentable-mcp.json']);
    const loaded = await loadOrCreateIdentity('opentable-mcp', root);
    expect(Buffer.from(loaded.x25519Pub).equals(Buffer.from(id.x25519Pub))).toBe(true);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it('is swept even when the write that finds it fails, and the old identity stands', async () => {
    const path = await writeIdentityFile(root, 'opentable-mcp', await generateIdentity());
    const before = readFileSync(path, 'utf8');
    writeFileSync(join(root, LEFTOVER), 'half a private key', { mode: 0o600 });

    fsState.failRename = true;
    await expect(
      writeIdentityFile(root, 'opentable-mcp', await generateIdentity()),
    ).rejects.toThrow(/EXDEV/);

    expect(readFileSync(path, 'utf8')).toBe(before);
    expect(readdirSync(root)).toEqual(['opentable-mcp.json']);
  });

  it('is removed, not followed, when it is a symlink', async () => {
    const outside = join(root, 'outside');
    mkdirSync(outside);
    const victim = join(outside, 'victim');
    writeFileSync(victim, 'not yours');
    const dir = join(root, 'identity');
    mkdirSync(dir);
    symlinkSync(victim, join(dir, LEFTOVER));

    await writeIdentityFile(dir, 'opentable-mcp', await generateIdentity());

    expect(readdirSync(dir)).toEqual(['opentable-mcp.json']);
    expect(readFileSync(victim, 'utf8')).toBe('not yours');
  });

  it('leaves files that are not this identity\'s staging files alone', async () => {
    const others = [
      // Another server's in-flight write — it may be running right now.
      'resy-mcp.json.0123456789ab.tmp',
      // The extension pin's own fixed staging name.
      'opentable-mcp.extension-trust.json.tmp',
      // Not the shape `writeIdentityFile` stages to.
      'opentable-mcp.json.notrandom.tmp',
      'opentable-mcp.json.tmp',
    ];
    for (const name of others) writeFileSync(join(root, name), 'x');

    await writeIdentityFile(root, 'opentable-mcp', await generateIdentity());

    expect(readdirSync(root).sort()).toEqual([...others, 'opentable-mcp.json'].sort());
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

  /**
   * A directory can be writable without being ours: a root-created 0777 volume
   * mounted into a non-root container. `chmod` there fails EPERM, but the
   * identity can still be written — and on first boot it MUST be, or the
   * server never starts.
   */
  it.each(['EPERM', 'EROFS'])(
    'still writes an identity into a directory whose chmod fails %s',
    async (code) => {
      const dir = join(root, 'volume');
      mkdirSync(dir, { mode: 0o777 });
      fsState.lockedDir = dir;
      fsState.lockedCode = code;

      const id = await generateIdentity();
      const path = await writeIdentityFile(dir, 'opentable-mcp', id);

      fsState.lockedDir = undefined;
      expect(statSync(path).mode & 0o777).toBe(0o600);
      const loaded = await loadOrCreateIdentity('opentable-mcp', dir);
      expect(Buffer.from(loaded.x25519Pub).equals(Buffer.from(id.x25519Pub))).toBe(true);
    },
  );

  it('first boot creates an identity in a writable directory it does not own', async () => {
    const dir = join(root, 'volume');
    mkdirSync(dir, { mode: 0o777 });
    fsState.lockedDir = dir;
    fsState.lockedCode = 'EPERM';

    const id = await loadOrCreateIdentity('opentable-mcp', dir);

    expect(readdirSync(dir)).toEqual(['opentable-mcp.json']);
    fsState.lockedDir = undefined;
    const again = await loadOrCreateIdentity('opentable-mcp', dir);
    expect(Buffer.from(again.x25519Pub).equals(Buffer.from(id.x25519Pub))).toBe(true);
  });

  it('still fails a write when the directory chmod fails for any other reason', async () => {
    const dir = join(root, 'broken');
    mkdirSync(dir, { mode: 0o755 });
    fsState.lockedDir = dir;
    fsState.lockedCode = 'EIO';

    await expect(
      writeIdentityFile(dir, 'opentable-mcp', await generateIdentity()),
    ).rejects.toThrow(/EIO/);
    expect(readdirSync(dir)).toEqual([]);
  });

  it('still fails a load when the directory chmod fails for any other reason', async () => {
    const dir = join(root, 'broken');
    mkdirSync(dir, { mode: 0o755 });
    fsState.lockedDir = dir;
    fsState.lockedCode = 'EIO';

    await expect(loadOrCreateIdentity('opentable-mcp', dir)).rejects.toThrow(/EIO/);
  });
});
