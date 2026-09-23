import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  statSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// fleet-audit#311: without hard links the first run publishes by exclusive
// create and THEN writes. A crash between the two leaves a zero-length (or,
// mid-write, truncated) identity file, and every later start used to throw a
// SyntaxError until someone deleted it by hand. An abandoned file — one too old
// to be a racing first run still writing — is replaced through the same
// exclusive-create path; a fresh one is still waited on; a valid one is never
// touched.

const linkError = vi.hoisted(() => ({ code: 'EPERM' as string | null }));

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

/** Backdate `path` so it reads as a crashed writer's, not a live racer's. */
function age(path: string, ms = 60_000): void {
  const t = (Date.now() - ms) / 1000;
  utimesSync(path, t, t);
}

function scratch(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

describe('abandoned first-run identity file (fleet-audit#311)', () => {
  beforeEach(() => {
    linkError.code = 'EPERM';
  });

  it('recovers an abandoned zero-length identity file', async () => {
    const dir = scratch('fp-abandoned-empty-');
    const path = identityFilePath(dir, 'crashed-mcp');
    writeFileSync(path, '', { mode: 0o600 });
    age(path);

    const id = await loadOrCreateIdentity('crashed-mcp', dir);
    const onDisk = parseIdentity(readFileSync(path, 'utf8'));
    expect(serializeIdentity(onDisk)).toBe(serializeIdentity(id));
    expect(statSync(path).mode & 0o777).toBe(0o600);
    // A restart reads the same identity back.
    const again = await loadOrCreateIdentity('crashed-mcp', dir);
    expect(serializeIdentity(again)).toBe(serializeIdentity(id));
    // Nothing of the recovery is left behind.
    expect(readdirSync(dir).sort()).toEqual(['crashed-mcp.json']);
  });

  it('recovers an abandoned identity file truncated mid-write', async () => {
    const dir = scratch('fp-abandoned-trunc-');
    const path = identityFilePath(dir, 'crashed-mcp');
    const full = serializeIdentity(await generateIdentity());
    writeFileSync(path, full.slice(0, 40), { mode: 0o600 });
    age(path);

    const id = await loadOrCreateIdentity('crashed-mcp', dir);
    expect(readFileSync(path, 'utf8')).toBe(serializeIdentity(id));
  });

  it('recovers on a filesystem with hard links too', async () => {
    linkError.code = null;
    const dir = scratch('fp-abandoned-link-');
    const path = identityFilePath(dir, 'crashed-mcp');
    writeFileSync(path, '', { mode: 0o600 });
    age(path);
    const id = await loadOrCreateIdentity('crashed-mcp', dir);
    expect(readFileSync(path, 'utf8')).toBe(serializeIdentity(id));
  });

  it('racing starts over one abandoned file all adopt a single identity', async () => {
    const dir = scratch('fp-abandoned-race-');
    const path = identityFilePath(dir, 'racer-mcp');
    writeFileSync(path, '', { mode: 0o600 });
    age(path);

    const ids = await Promise.all(
      Array.from({ length: 8 }, () => loadOrCreateIdentity('racer-mcp', dir)),
    );
    const onDisk = serializeIdentity(parseIdentity(readFileSync(path, 'utf8')));
    for (const id of ids) expect(serializeIdentity(id)).toBe(onDisk);
    expect(readdirSync(dir).sort()).toEqual(['racer-mcp.json']);
  });

  it('still waits on a FRESH empty file — a racer mid-write — rather than replacing it', async () => {
    const dir = scratch('fp-fresh-empty-');
    const path = identityFilePath(dir, 'partial-mcp');
    writeFileSync(path, '', { mode: 0o600 });
    const winner = await generateIdentity();
    setTimeout(() => writeFileSync(path, serializeIdentity(winner)), 30);
    const got = await loadOrCreateIdentity('partial-mcp', dir);
    expect(serializeIdentity(got)).toBe(serializeIdentity(winner));
  });

  it('never replaces a fresh empty file even when its writer is slow', async () => {
    const dir = scratch('fp-fresh-slow-');
    const path = identityFilePath(dir, 'slow-mcp');
    writeFileSync(path, '', { mode: 0o600 });
    await expect(loadOrCreateIdentity('slow-mcp', dir)).rejects.toBeInstanceOf(SyntaxError);
    expect(readFileSync(path, 'utf8')).toBe('');
  });

  it('never replaces a valid identity, however old', async () => {
    const dir = scratch('fp-old-valid-');
    const path = identityFilePath(dir, 'old-mcp');
    const bytes = serializeIdentity(await generateIdentity());
    writeFileSync(path, bytes, { mode: 0o600 });
    age(path, 365 * 24 * 3600_000);
    const got = await loadOrCreateIdentity('old-mcp', dir);
    expect(serializeIdentity(got)).toBe(bytes);
    expect(readFileSync(path, 'utf8')).toBe(bytes);
  });

  it('does not replace an old file that is corrupt rather than truncated', async () => {
    const dir = scratch('fp-old-corrupt-');
    const path = identityFilePath(dir, 'corrupt-mcp');
    // Complete (closed) but not JSON: somebody edited it. Not a crashed first
    // run, so replacing it with a new key would hide the problem.
    writeFileSync(path, '{"x25519Priv": }', { mode: 0o600 });
    age(path);
    await expect(loadOrCreateIdentity('corrupt-mcp', dir)).rejects.toBeInstanceOf(SyntaxError);
    expect(readFileSync(path, 'utf8')).toBe('{"x25519Priv": }');
  });

  it('breaks a recovery lock left by a recoverer that crashed', async () => {
    const dir = scratch('fp-stale-lock-');
    const path = identityFilePath(dir, 'crashed-mcp');
    writeFileSync(path, '', { mode: 0o600 });
    age(path);
    writeFileSync(`${path}.recover.lock`, '', { mode: 0o600 });
    age(`${path}.recover.lock`);
    const id = await loadOrCreateIdentity('crashed-mcp', dir);
    expect(readFileSync(path, 'utf8')).toBe(serializeIdentity(id));
    expect(readdirSync(dir).sort()).toEqual(['crashed-mcp.json']);
  });

  it('defers to a live recovery lock held by another process', async () => {
    const dir = scratch('fp-live-lock-');
    const path = identityFilePath(dir, 'crashed-mcp');
    writeFileSync(path, '', { mode: 0o600 });
    age(path);
    writeFileSync(`${path}.recover.lock`, '', { mode: 0o600 });
    await expect(loadOrCreateIdentity('crashed-mcp', dir)).rejects.toBeInstanceOf(SyntaxError);
    expect(readFileSync(path, 'utf8')).toBe('');
  });
});
