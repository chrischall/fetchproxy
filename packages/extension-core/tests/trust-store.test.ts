import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TrustStore, type TrustedMcp } from '../src/trust-store.js';

// Mock chrome.storage.local
function mockStorage() {
  const store = new Map<string, unknown>();
  return {
    get: vi.fn(async (keys?: string | string[]) => {
      if (!keys) return Object.fromEntries(store);
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const k of list) {
        if (store.has(k)) out[k] = store.get(k);
      }
      return out;
    }),
    set: vi.fn(async (items: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(items)) store.set(k, v);
    }),
    remove: vi.fn(async (keys: string | string[]) => {
      const list = Array.isArray(keys) ? keys : [keys];
      for (const k of list) store.delete(k);
    }),
  };
}

describe('TrustStore', () => {
  let storage: ReturnType<typeof mockStorage>;
  let trust: TrustStore;

  beforeEach(() => {
    storage = mockStorage();
    trust = new TrustStore(storage as unknown as chrome.storage.StorageArea);
  });

  it('returns null for an unknown (port, server, domain) tuple', async () => {
    expect(await trust.lookup({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }))
      .toBeNull();
  });

  it('persists an "always allow" decision and finds it back', async () => {
    await trust.approve({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }, 'always');
    const found = await trust.lookup({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' });
    expect(found?.approval).toBe('always');
  });

  it('re-prompts (returns null) when the version major changes', async () => {
    await trust.approve({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }, 'always');
    const found = await trust.lookup({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '1.0.0' });
    expect(found).toBeNull();
  });

  it('does not re-prompt on patch version bump', async () => {
    await trust.approve({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }, 'always');
    const found = await trust.lookup({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.2' });
    expect(found?.approval).toBe('always');
  });

  it('re-prompts when the domain changes', async () => {
    await trust.approve({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }, 'always');
    const found = await trust.lookup({ port: 37149, server: 'opentable-mcp', domain: 'yourbank.com', version: '0.9.1' });
    expect(found).toBeNull();
  });

  it('revokes an approval', async () => {
    await trust.approve({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }, 'always');
    await trust.revoke({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com' });
    expect(await trust.lookup({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }))
      .toBeNull();
  });

  it('lists all trusted MCPs', async () => {
    await trust.approve({ port: 37149, server: 'opentable-mcp', domain: 'opentable.com', version: '0.9.1' }, 'always');
    await trust.approve({ port: 37148, server: 'resy-mcp', domain: 'resy.com', version: '0.1.0' }, 'always');
    const list = await trust.list();
    expect(list).toHaveLength(2);
    expect(list.map((m: TrustedMcp) => m.server).sort()).toEqual(['opentable-mcp', 'resy-mcp']);
  });
});
