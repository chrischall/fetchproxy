import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// B-BUG-11 follow-up: first-run identity creation publishes with `link()` so
// racing first runs cannot overwrite each other. Some filesystems have no hard
// links (FAT/exFAT volumes, some network and FUSE mounts, Windows without
// NTFS) and `link()` fails EPERM / ENOTSUP / ENOSYS there. That must not make
// an identity impossible to create: fall back to an exclusive create.

const linkError = vi.hoisted(() => ({ code: null as string | null }));

vi.mock('node:fs/promises', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs/promises')>();
  return {
    ...real,
    link: async (existing: string, target: string) => {
      if (linkError.code !== null) {
        throw Object.assign(new Error(`${linkError.code}: link not supported`), {
          code: linkError.code,
        });
      }
      return real.link(existing, target);
    },
  };
});

const {
  loadOrCreateIdentity,
  identityFilePath,
  parseIdentity,
  serializeIdentity,
  generateIdentity,
} = await import('../src/identity.js');

describe('first-run identity creation without hard links', () => {
  beforeEach(() => {
    linkError.code = null;
  });

  for (const code of ['EPERM', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS']) {
    it(`creates the identity when link() fails ${code}`, async () => {
      linkError.code = code;
      const dir = mkdtempSync(join(tmpdir(), 'fp-nolink-'));
      const id = await loadOrCreateIdentity('nolink-mcp', dir);
      const onDisk = parseIdentity(readFileSync(identityFilePath(dir, 'nolink-mcp'), 'utf8'));
      expect(serializeIdentity(onDisk)).toBe(serializeIdentity(id));
      // A restart reads the same identity back.
      const again = await loadOrCreateIdentity('nolink-mcp', dir);
      expect(serializeIdentity(again)).toBe(serializeIdentity(id));
      expect(readdirSync(dir).filter((n) => n.endsWith('.tmp'))).toEqual([]);
    });
  }

  it('racing first runs still agree on one identity through the fallback', async () => {
    linkError.code = 'EPERM';
    const dir = mkdtempSync(join(tmpdir(), 'fp-nolink-race-'));
    const ids = await Promise.all(
      Array.from({ length: 8 }, () => loadOrCreateIdentity('racer-mcp', dir)),
    );
    const onDisk = parseIdentity(readFileSync(identityFilePath(dir, 'racer-mcp'), 'utf8'));
    for (const id of ids) expect(serializeIdentity(id)).toBe(serializeIdentity(onDisk));
    expect(readdirSync(dir).filter((n) => n.endsWith('.tmp'))).toEqual([]);
  });

  it('still surfaces an unrelated link() failure', async () => {
    linkError.code = 'EACCES';
    const dir = mkdtempSync(join(tmpdir(), 'fp-nolink-eacces-'));
    await expect(loadOrCreateIdentity('nolink-mcp', dir)).rejects.toMatchObject({
      code: 'EACCES',
    });
  });

  // Without link() the winner creates the file and THEN writes it, so a loser
  // can find it empty. It must wait for the bytes, not fail its first run.
  it('waits out a racing winner whose file is created but not yet written', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fp-nolink-partial-'));
    const path = identityFilePath(dir, 'partial-mcp');
    writeFileSync(path, '', { mode: 0o600 });
    const winner = await generateIdentity();
    setTimeout(() => writeFileSync(path, serializeIdentity(winner)), 30);
    const got = await loadOrCreateIdentity('partial-mcp', dir);
    expect(serializeIdentity(got)).toBe(serializeIdentity(winner));
  });

  it('still reports a genuinely corrupt identity file', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fp-nolink-corrupt-'));
    writeFileSync(identityFilePath(dir, 'corrupt-mcp'), '{"x25519Priv":', { mode: 0o600 });
    await expect(loadOrCreateIdentity('corrupt-mcp', dir)).rejects.toBeInstanceOf(SyntaxError);
    // And it was not replaced.
    expect(readFileSync(identityFilePath(dir, 'corrupt-mcp'), 'utf8')).toBe('{"x25519Priv":');
  });
});
