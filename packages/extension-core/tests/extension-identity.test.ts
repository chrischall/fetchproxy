import { describe, it, expect, beforeEach } from 'vitest';
import { loadOrCreateExtensionIdentity } from '../src/extension-identity.js';
import { toB64 } from '@fetchproxy/protocol';

function mockStorage(): { data: Record<string, unknown> } {
  const data: Record<string, unknown> = {};
  (globalThis as { chrome?: unknown }).chrome = {
    storage: {
      local: {
        get: async (k: string) => {
          if (k in data) return { [k]: data[k] };
          return {};
        },
        set: async (kv: Record<string, unknown>) => {
          Object.assign(data, kv);
        },
      },
    },
  };
  return { data };
}

describe('loadOrCreateExtensionIdentity', () => {
  beforeEach(() => mockStorage());

  it('generates a fresh keypair on first call and persists it', async () => {
    const id = await loadOrCreateExtensionIdentity();
    expect(id.x25519Priv).toBeInstanceOf(Uint8Array);
    expect(id.x25519Priv.byteLength).toBe(32);
    expect(id.x25519Pub.byteLength).toBe(32);
    expect(id.ed25519Priv.byteLength).toBe(32);
    expect(id.ed25519Pub.byteLength).toBe(32);
    expect(typeof id.createdAt).toBe('number');
    expect(id.createdAt).toBeGreaterThan(0);
  });

  it('returns the same identity on subsequent calls', async () => {
    const id1 = await loadOrCreateExtensionIdentity();
    const id2 = await loadOrCreateExtensionIdentity();
    expect(toB64(id2.x25519Priv)).toBe(toB64(id1.x25519Priv));
    expect(toB64(id2.x25519Pub)).toBe(toB64(id1.x25519Pub));
    expect(toB64(id2.ed25519Priv)).toBe(toB64(id1.ed25519Priv));
    expect(toB64(id2.ed25519Pub)).toBe(toB64(id1.ed25519Pub));
    expect(id2.createdAt).toBe(id1.createdAt);
  });

  it('persists with base64 string encoding in storage', async () => {
    const id = await loadOrCreateExtensionIdentity();
    // Storage round-tripped: a second call gets the same bytes back.
    const id2 = await loadOrCreateExtensionIdentity();
    expect(toB64(id.x25519Pub)).toBe(toB64(id2.x25519Pub));
  });

  it('regenerates if storage was wiped between calls', async () => {
    const id1 = await loadOrCreateExtensionIdentity();
    // Simulate a wipe — fresh chrome.storage mock.
    mockStorage();
    const id2 = await loadOrCreateExtensionIdentity();
    // Different identity bytes.
    expect(toB64(id2.x25519Pub)).not.toBe(toB64(id1.x25519Pub));
  });
});
