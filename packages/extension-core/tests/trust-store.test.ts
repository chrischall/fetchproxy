import { describe, it, expect, beforeEach } from 'vitest';
import { TrustStore } from '../src/trust-store.js';

function mockStorage(): { data: Record<string, unknown> } {
  const data: Record<string, unknown> = {};
  (globalThis as { chrome?: unknown }).chrome = {
    storage: {
      local: {
        get: async (k: string | string[]) => {
          const ks = Array.isArray(k) ? k : [k];
          const out: Record<string, unknown> = {};
          for (const x of ks) if (x in data) out[x] = data[x];
          return out;
        },
        set: async (kv: Record<string, unknown>) => Object.assign(data, kv),
        remove: async (k: string) => { delete data[k]; },
      },
    },
  };
  return { data };
}

describe('TrustStore (identity-hash keyed)', () => {
  beforeEach(() => mockStorage());

  it('returns null for unknown identity hash', async () => {
    const store = new TrustStore('0.1.0');
    expect(await store.get('abc')).toBeNull();
  });

  it('persists and retrieves a trust record', async () => {
    const store = new TrustStore('0.1.0');
    await store.put('hash1', {
      serverName: 'opentable-mcp',
      domains: ['opentable.com'],
      capabilities: ['fetch'],
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'BBBB',
    });
    const got = await store.get('hash1');
    expect(got).not.toBeNull();
    expect(got!.serverName).toBe('opentable-mcp');
    expect(got!.domains).toEqual(['opentable.com']);
    expect(got!.identityX25519Pub).toBe('AAAA');
    expect(got!.extensionVersionAtPair).toBe('0.1.0');
    expect(typeof got!.pairedAt).toBe('number');
  });

  it('invalidates trust on extension major version bump', async () => {
    const s1 = new TrustStore('0.1.0');
    await s1.put('hash1', {
      serverName: 'opentable-mcp',
      domains: ['opentable.com'],
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'BBBB',
    });
    const s2 = new TrustStore('1.0.0');
    expect(await s2.get('hash1')).toBeNull();
  });

  it('preserves trust on patch/minor version bump', async () => {
    const s1 = new TrustStore('0.1.0');
    await s1.put('hash1', {
      serverName: 'opentable-mcp',
      domains: ['opentable.com'],
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'BBBB',
    });
    const s2a = new TrustStore('0.1.5');
    expect(await s2a.get('hash1')).not.toBeNull();
    const s2b = new TrustStore('0.2.0');
    expect(await s2b.get('hash1')).not.toBeNull();
  });

  it('remove drops the record', async () => {
    const store = new TrustStore('0.1.0');
    await store.put('hash1', {
      serverName: 'a',
      domains: ['a.com'],
      capabilities: ['fetch'],
      identityX25519Pub: 'X',
      identityEd25519Pub: 'Y',
    });
    await store.remove('hash1');
    expect(await store.get('hash1')).toBeNull();
  });

  it('list returns all records', async () => {
    const store = new TrustStore('0.1.0');
    await store.put('hash1', {
      serverName: 'a', domains: ['a.com'], capabilities: ['fetch'], identityX25519Pub: 'X', identityEd25519Pub: 'Y',
    });
    await store.put('hash2', {
      serverName: 'b', domains: ['b.com'], capabilities: ['fetch'], identityX25519Pub: 'X', identityEd25519Pub: 'Y',
    });
    const all = await store.list();
    expect(Object.keys(all)).toHaveLength(2);
    expect(all['hash1']!.serverName).toBe('a');
    expect(all['hash2']!.serverName).toBe('b');
  });

  it('put overwrites existing record', async () => {
    const store = new TrustStore('0.1.0');
    await store.put('hash1', {
      serverName: 'old', domains: ['a.com'], capabilities: ['fetch'], identityX25519Pub: 'X', identityEd25519Pub: 'Y',
    });
    await store.put('hash1', {
      serverName: 'new', domains: ['a.com'], capabilities: ['fetch'], identityX25519Pub: 'X', identityEd25519Pub: 'Y',
    });
    const got = await store.get('hash1');
    expect(got!.serverName).toBe('new');
  });

  it('persists and retrieves a multi-domain trust record', async () => {
    const store = new TrustStore('0.1.0');
    await store.put('hashm', {
      serverName: 'honeybook-mcp',
      domains: ['honeybook.com', 'hbsplit.com'],
      capabilities: ['fetch'],
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'BBBB',
    });
    const got = await store.get('hashm');
    expect(got).not.toBeNull();
    expect(got!.domains).toEqual(['honeybook.com', 'hbsplit.com']);
  });

  it('persists a capability set, including read_cookies', async () => {
    const store = new TrustStore('0.2.0');
    await store.put('hashc', {
      serverName: 'credit-karma-mcp',
      domains: ['creditkarma.com'],
      capabilities: ['fetch', 'read_cookies'],
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'BBBB',
    });
    const got = await store.get('hashc');
    expect(got).not.toBeNull();
    expect(got!.capabilities).toEqual(['fetch', 'read_cookies']);
  });

  it('treats malformed extensionVersionAtPair as a version mismatch (forces re-pair)', async () => {
    // trust-store.ts:61-63 — `majorOf` guards against empty / NaN inputs
    // by returning NaN, which never equals NaN under !==. The effect is
    // that a record written with a bogus "version string" can't be auto-
    // trusted from a normal extension version. This is the conservative
    // path the user would actually want (anything weird → re-pair).
    const store = new TrustStore('0.2.0');
    const cs = (globalThis as { chrome?: { storage: { local: { set: (kv: Record<string, unknown>) => Promise<void> } } } }).chrome!.storage.local;
    await cs.set({
      trustedMcps: {
        records: {
          weird: {
            serverName: 'a',
            domains: ['a.com'],
            capabilities: ['fetch'],
            identityX25519Pub: 'X',
            identityEd25519Pub: 'Y',
            pairedAt: 1,
            extensionVersionAtPair: '', // empty — `head` is '' → !head branch → NaN
          },
        },
      },
    });
    expect(await store.get('weird')).toBeNull();
    // Also exercise the "head is a non-numeric token" branch.
    await cs.set({
      trustedMcps: {
        records: {
          weird2: {
            serverName: 'a',
            domains: ['a.com'],
            capabilities: ['fetch'],
            identityX25519Pub: 'X',
            identityEd25519Pub: 'Y',
            pairedAt: 1,
            extensionVersionAtPair: 'next.0.0',
          },
        },
      },
    });
    expect(await store.get('weird2')).toBeNull();
  });

  it('round-trips 0.3.0 scope fields (cookieKeys, localStorageKeys, etc.)', async () => {
    const store = new TrustStore('0.3.0');
    await store.put('hash3', {
      serverName: 'ofw-mcp',
      domains: ['ourfamilywizard.com'],
      capabilities: ['fetch', 'read_local_storage'],
      cookieKeys: [],
      localStorageKeys: ['auth', 'tokenExpiry'],
      sessionStorageKeys: [],
      captureHeaders: [],
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'BBBB',
    });
    const got = await store.get('hash3');
    expect(got).not.toBeNull();
    expect(got!.localStorageKeys).toEqual(['auth', 'tokenExpiry']);
    expect(got!.cookieKeys).toEqual([]);
    expect(got!.sessionStorageKeys).toEqual([]);
    expect(got!.captureHeaders).toEqual([]);
  });

  it('round-trips captureHeaders entries', async () => {
    const store = new TrustStore('0.3.0');
    await store.put('hashh', {
      serverName: 'honeybook-mcp',
      domains: ['honeybook.com'],
      capabilities: ['fetch', 'capture_request_header'],
      cookieKeys: [],
      localStorageKeys: [],
      sessionStorageKeys: [],
      captureHeaders: [
        { urlPattern: 'https://api.honeybook.com/api/v2/*', headerName: 'hb-api-fingerprint' },
      ],
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'BBBB',
    });
    const got = await store.get('hashh');
    expect(got).not.toBeNull();
    expect(got!.captureHeaders).toEqual([
      { urlPattern: 'https://api.honeybook.com/api/v2/*', headerName: 'hb-api-fingerprint' },
    ]);
  });

  it('normalises pre-0.3.0 records to empty scope arrays on read', async () => {
    const store = new TrustStore('0.3.0');
    const cs = (globalThis as { chrome?: { storage: { local: { set: (kv: Record<string, unknown>) => Promise<void> } } } }).chrome!.storage.local;
    await cs.set({
      trustedMcps: {
        records: {
          legacy2: {
            serverName: 'legacy-mcp',
            domains: ['legacy.example'],
            capabilities: ['fetch', 'read_cookies'],
            identityX25519Pub: 'X',
            identityEd25519Pub: 'Y',
            pairedAt: 1,
            extensionVersionAtPair: '0.3.0',
            // No 0.3.0 scope fields.
          },
        },
      },
    });
    const got = await store.get('legacy2');
    expect(got).not.toBeNull();
    expect(got!.cookieKeys).toEqual([]);
    expect(got!.localStorageKeys).toEqual([]);
    expect(got!.sessionStorageKeys).toEqual([]);
    expect(got!.captureHeaders).toEqual([]);
  });

  it('normalises pre-capability records to ["fetch"] on read', async () => {
    // Simulate a record stored before 0.2.0 added capabilities by writing
    // directly through the underlying storage layer without the field.
    const store = new TrustStore('0.2.0');
    // Hack: stash a synthetic legacy record into chrome.storage.local.
    const cs = (globalThis as { chrome?: { storage: { local: { set: (kv: Record<string, unknown>) => Promise<void> } } } }).chrome!.storage.local;
    await cs.set({
      trustedMcps: {
        records: {
          legacy1: {
            serverName: 'legacy-mcp',
            domains: ['legacy.example'],
            identityX25519Pub: 'X',
            identityEd25519Pub: 'Y',
            pairedAt: 1,
            extensionVersionAtPair: '0.2.0',
            // No capabilities field — older shape.
          },
        },
      },
    });
    const got = await store.get('legacy1');
    expect(got).not.toBeNull();
    expect(got!.capabilities).toEqual(['fetch']);
  });
});
