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
      identityX25519Pub: 'X',
      identityEd25519Pub: 'Y',
    });
    await store.remove('hash1');
    expect(await store.get('hash1')).toBeNull();
  });

  it('list returns all records', async () => {
    const store = new TrustStore('0.1.0');
    await store.put('hash1', {
      serverName: 'a', domains: ['a.com'], identityX25519Pub: 'X', identityEd25519Pub: 'Y',
    });
    await store.put('hash2', {
      serverName: 'b', domains: ['b.com'], identityX25519Pub: 'X', identityEd25519Pub: 'Y',
    });
    const all = await store.list();
    expect(Object.keys(all)).toHaveLength(2);
    expect(all['hash1']!.serverName).toBe('a');
    expect(all['hash2']!.serverName).toBe('b');
  });

  it('put overwrites existing record', async () => {
    const store = new TrustStore('0.1.0');
    await store.put('hash1', {
      serverName: 'old', domains: ['a.com'], identityX25519Pub: 'X', identityEd25519Pub: 'Y',
    });
    await store.put('hash1', {
      serverName: 'new', domains: ['a.com'], identityX25519Pub: 'X', identityEd25519Pub: 'Y',
    });
    const got = await store.get('hash1');
    expect(got!.serverName).toBe('new');
  });

  it('persists and retrieves a multi-domain trust record', async () => {
    const store = new TrustStore('0.1.0');
    await store.put('hashm', {
      serverName: 'honeybook-mcp',
      domains: ['honeybook.com', 'hbsplit.com'],
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'BBBB',
    });
    const got = await store.get('hashm');
    expect(got).not.toBeNull();
    expect(got!.domains).toEqual(['honeybook.com', 'hbsplit.com']);
  });
});
