import { describe, it, expect } from 'vitest';
import { mkdtempSync, readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  loadOrCreateIdentity,
  identityFilePath,
  parseIdentity,
  serializeIdentity,
} from '../src/identity.js';
import { writeExtensionPin, readExtensionPin } from '../src/extension-trust.js';

// B-BUG-11: two processes of the same serverName starting together on first
// run both generated a key and both renamed it into place — last writer won,
// and the loser ran (and could get paired) under an identity no longer on disk.

describe('B-BUG-11: concurrent first-run identity creation', () => {
  it('every concurrent caller gets the identity that ends up on disk', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fp-race-'));
    const ids = await Promise.all(
      Array.from({ length: 8 }, () => loadOrCreateIdentity('racer-mcp', dir)),
    );
    const onDisk = parseIdentity(readFileSync(identityFilePath(dir, 'racer-mcp'), 'utf8'));
    for (const id of ids) expect(serializeIdentity(id)).toBe(serializeIdentity(onDisk));
    // No staging files (private key material) left behind.
    expect(readdirSync(dir).filter((n) => n.endsWith('.tmp'))).toEqual([]);
  });
});

describe('B-BUG-11: concurrent extension-pin writes', () => {
  it('do not collide on a shared staging file', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fp-pin-race-'));
    const pin = (n: number) => ({
      identityX25519Pub: `x${n}`,
      identityEd25519Pub: `e${n}`,
      pinnedAt: n,
    });
    await Promise.all(
      Array.from({ length: 8 }, (_, n) => writeExtensionPin('racer-mcp', pin(n), dir)),
    );
    const got = await readExtensionPin('racer-mcp', dir);
    expect(got).not.toBeNull();
    expect(readdirSync(dir).filter((n) => n.endsWith('.tmp'))).toEqual([]);
  });
});
