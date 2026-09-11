import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { chmodSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

/**
 * A crash, a full disk or a ^C mid-write. The open has already truncated
 * whatever the path named by the time a write can fail, so the interruption
 * leaves an EMPTY file behind — which is the whole reason the target must not
 * be the file being written.
 */
const fs = vi.hoisted(() => ({ failWrite: false }));

vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  return {
    ...actual,
    writeFileSync: ((path: never, data: never, opts: never) => {
      if (!fs.failWrite) return actual.writeFileSync(path, data, opts);
      actual.writeFileSync(path, '', opts);
      throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' });
    }) as typeof actual.writeFileSync,
  };
});

const { emptyProfile, loadProfiles, saveProfiles } = await import('../src/profiles.js');

let home: string;
beforeEach(() => {
  fs.failWrite = false;
  home = mkdtempSync(join(tmpdir(), 'fpx-atomic-'));
});
afterEach(() => {
  fs.failWrite = false;
  rmSync(home, { recursive: true, force: true });
});

describe('saveProfiles is atomic', () => {
  it('leaves the previous profiles readable when the write is interrupted', () => {
    saveProfiles({ keep: emptyProfile(['tripadvisor.com']) }, home);

    fs.failWrite = true;
    expect(() => saveProfiles(
      { keep: emptyProfile(['tripadvisor.com']), added: emptyProfile(['x.com']) },
      home,
    )).toThrow(/ENOSPC/);

    // The identity the profile carries — its declared domains and scope — is
    // still there. Written in place, this file would now be empty and
    // loadProfiles would refuse the whole set as invalid JSON.
    fs.failWrite = false;
    const loaded = loadProfiles(home);
    expect(Object.keys(loaded)).toEqual(['keep']);
    expect(loaded.keep!.domains).toEqual(['tripadvisor.com']);
  });

  it('leaves nothing behind in the home when the write is interrupted', () => {
    saveProfiles({ keep: emptyProfile(['tripadvisor.com']) }, home);
    fs.failWrite = true;
    expect(() => saveProfiles({ keep: emptyProfile(['y.com']) }, home)).toThrow();
    expect(readdirSync(home)).toEqual(['profiles.json']);
  });

  it('still writes the profile when nothing interrupts it (control)', () => {
    saveProfiles({ keep: emptyProfile(['tripadvisor.com']) }, home);
    saveProfiles({ keep: emptyProfile(['tripadvisor.com']), added: emptyProfile(['x.com']) }, home);
    expect(Object.keys(loadProfiles(home)).sort()).toEqual(['added', 'keep']);
    expect(readdirSync(home)).toEqual(['profiles.json']);
  });

  it('tightens a loose mode on a file that already exists', () => {
    const path = join(home, 'profiles.json');
    writeFileSync(path, '{}\n');
    chmodSync(path, 0o644);
    saveProfiles({ keep: emptyProfile(['tripadvisor.com']) }, home);
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });
});
