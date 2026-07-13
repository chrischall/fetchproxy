import { describe, it, expect } from 'vitest';
import { parseCliArgs } from '../src/args.js';
import { UsageError } from '../src/output.js';

describe('parseCliArgs', () => {
  it('parses profile add with repeated domains', () => {
    expect(parseCliArgs(['profile', 'add', 'hb', '--domain', 'honeybook.com', '--domain', 'hbportal.co']))
      .toEqual({ kind: 'profile-add', name: 'hb', domains: ['honeybook.com', 'hbportal.co'] });
  });

  it('parses profile declare with capture-header name@host/path', () => {
    const cmd = parseCliArgs(['profile', 'declare', 'trip', '--cookie', 'datadome',
      '--capture-header', 'x-csrf-token@www.tripadvisor.com/data/*']);
    expect(cmd).toEqual({
      kind: 'profile-declare', name: 'trip', cookies: ['datadome'],
      localStorage: [], sessionStorage: [],
      captureHeaders: [{ headerName: 'x-csrf-token', host: 'www.tripadvisor.com', path: '/data/*' }],
    });
  });

  it('parses get with headers and --json', () => {
    const cmd = parseCliArgs(['get', 'https://www.tripadvisor.com/x', '-p', 'trip',
      '--json', '-H', 'Accept: application/json']);
    expect(cmd).toEqual({
      kind: 'fetch', profile: 'trip', method: 'GET', url: 'https://www.tripadvisor.com/x',
      headers: { Accept: 'application/json' }, body: undefined, json: true,
    });
  });

  it('post-json resolves @file bodies and sets content-type', () => {
    const cmd = parseCliArgs(['post-json', 'https://x.com/api', '@body.json', '-p', 'x'],
      (p) => { expect(p).toBe('body.json'); return '{"a":1}'; });
    expect(cmd).toEqual({
      kind: 'fetch', profile: 'x', method: 'POST', url: 'https://x.com/api',
      headers: { 'Content-Type': 'application/json' }, body: '{"a":1}', json: false,
    });
  });

  it('post-json rejects invalid JSON bodies', () => {
    expect(() => parseCliArgs(['post-json', 'https://x.com/a', 'not json', '-p', 'x']))
      .toThrow(UsageError);
  });

  it('parses read verbs with keys and storage-domain', () => {
    expect(parseCliArgs(['local-storage', 'tok', '-p', 'hb', '--storage-domain', 'hbportal.co']))
      .toEqual({ kind: 'read', profile: 'hb', bucket: 'localStorage', keys: ['tok'],
        storageDomain: 'hbportal.co', storageSubdomain: undefined });
  });

  it('requires -p on verb commands', () => {
    expect(() => parseCliArgs(['get', 'https://x.com/'])).toThrow(/--profile/);
  });

  it('rejects unknown commands with a UsageError', () => {
    expect(() => parseCliArgs(['frobnicate'])).toThrow(UsageError);
  });

  it('rejects unknown flags with a UsageError, not a raw TypeError', () => {
    expect(() => parseCliArgs(['get', 'https://x.com/', '--bogus', '-p', 'x'])).toThrow(UsageError);
  });
});
