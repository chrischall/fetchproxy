import { describe, it, expect } from 'vitest';
import { serverOptsFor } from '../src/server-opts.js';
import { emptyProfile } from '../src/profiles.js';

describe('serverOptsFor', () => {
  it('fetch-only profile → capabilities [fetch] and empty scopes', () => {
    const opts = serverOptsFor('trip', emptyProfile(['tripadvisor.com']), '1.4.0');
    expect(opts).toEqual({
      serverName: 'fpx-trip', version: '1.4.0', domains: ['tripadvisor.com'],
      capabilities: ['fetch'], cookieKeys: [], localStorageKeys: [],
      sessionStorageKeys: [], captureHeaders: [], indexedDbScopes: [],
    });
  });

  it('derives capabilities in bootstrap push order and auto-adds pointer storageKeys', () => {
    const p = {
      ...emptyProfile(['resy.com']),
      cookies: ['authToken'],
      localStoragePointers: [{ outputKey: 'tok', storageKey: 'persist:auth', jsonPointer: '/t' }],
      sessionStorage: ['sid'],
      captureHeaders: [{ headerName: 'x-api-key', host: 'api.resy.com' }],
      indexedDb: [{ origin: 'https://resy.com', database: 'db', store: 's', keys: ['k'] }],
    };
    const opts = serverOptsFor('resy', p, '1.4.0');
    expect(opts.capabilities).toEqual([
      'fetch', 'read_cookies', 'read_local_storage', 'read_session_storage',
      'capture_request_header', 'read_indexed_db',
    ]);
    expect(opts.localStorageKeys).toEqual(['persist:auth']);
    expect(opts.sessionStorageKeys).toEqual(['sid']);
  });

  it('read_local_storage appears for raw keys with no pointers (and vice versa)', () => {
    const raw = serverOptsFor('a', { ...emptyProfile(['x.com']), localStorage: ['k'] }, '1.4.0');
    expect(raw.capabilities).toEqual(['fetch', 'read_local_storage']);
    expect(raw.localStorageKeys).toEqual(['k']);
  });
});
