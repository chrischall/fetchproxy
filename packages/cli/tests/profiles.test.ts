import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  cliHome, emptyProfile, loadProfiles, saveProfiles, getProfile, identityPath,
} from '../src/profiles.js';
import { UsageError } from '../src/output.js';

let home: string;
beforeEach(() => { home = mkdtempSync(join(tmpdir(), 'fpx-test-')); });
afterEach(() => { rmSync(home, { recursive: true, force: true }); });

describe('profiles', () => {
  it('cliHome prefers FETCHPROXY_CLI_HOME', () => {
    expect(cliHome({ FETCHPROXY_CLI_HOME: '/x' })).toBe('/x');
    expect(cliHome({})).toMatch(/\.fetchproxy[\\/]cli$/);
  });

  it('round-trips a profile with 0600/0700 permissions', () => {
    saveProfiles({ trip: emptyProfile(['tripadvisor.com']) }, home);
    const loaded = loadProfiles(home);
    expect(loaded.trip.domains).toEqual(['tripadvisor.com']);
    expect(loaded.trip.cookies).toEqual([]);
    expect(statSync(join(home, 'profiles.json')).mode & 0o777).toBe(0o600);
    expect(statSync(home).mode & 0o777).toBe(0o700);
  });

  it('loadProfiles returns {} when no file exists', () => {
    expect(loadProfiles(join(home, 'nope'))).toEqual({});
  });

  it('rejects malformed profile entries with a UsageError naming the field', () => {
    saveProfiles({ bad: { ...emptyProfile(['x.com']), domains: [] } as never }, home);
    expect(() => loadProfiles(home)).toThrow(UsageError);
    expect(() => loadProfiles(home)).toThrow(/bad.*domains/);
  });

  it('getProfile throws a UsageError listing known profiles', () => {
    saveProfiles({ trip: emptyProfile(['tripadvisor.com']) }, home);
    expect(() => getProfile('nope', home)).toThrow(/known profiles: trip/);
  });

  it('identityPath derives the fpx-prefixed identity file', () => {
    expect(identityPath('trip', '/id')).toBe(join('/id', 'fpx-trip.json'));
    expect(identityPath('trip')).toMatch(/\.fetchproxy[\\/]identity[\\/]fpx-trip\.json$/);
  });
});
