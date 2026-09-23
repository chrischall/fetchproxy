import { describe, it, expect, beforeEach } from 'vitest';
import {
  loadOrCreateExtensionIdentity,
  signWithExtensionIdentity,
} from '../src/extension-identity.js';
import {
  toB64,
  generateX25519,
  generateEd25519,
  ed25519Sign,
  ed25519Verify,
  ecdhX25519,
} from '@fetchproxy/protocol';
import { freshVault, installChromeLocal, type LocalArea } from './helpers/vault.js';

/**
 * FOLLOWUP-2 (fleet-audit #253): the extension's long-term private keys used
 * to live base64-encoded in `chrome.storage.local["extensionIdentity"]`, which
 * every site's content script can read. They now live ONLY as non-extractable
 * WebCrypto keys in the extension-origin IndexedDB. `chrome.storage.local` is
 * modelled here as the attacker's view: whatever a compromised renderer can
 * read or write.
 */

const enc = new TextEncoder();

async function legacyStored(): Promise<{
  stored: Record<string, unknown>;
  x: { privateKey: Uint8Array; publicKey: Uint8Array };
  ed: { privateKey: Uint8Array; publicKey: Uint8Array };
}> {
  const x = await generateX25519();
  const ed = await generateEd25519();
  return {
    x,
    ed,
    stored: {
      x25519Priv: toB64(x.privateKey),
      x25519Pub: toB64(x.publicKey),
      ed25519Priv: toB64(ed.privateKey),
      ed25519Pub: toB64(ed.publicKey),
      createdAt: 1234,
    },
  };
}

function allStrings(v: unknown): string {
  return JSON.stringify(v);
}

describe('loadOrCreateExtensionIdentity — fresh install', () => {
  let local: LocalArea;
  beforeEach(() => {
    freshVault();
    local = installChromeLocal();
  });

  it('generates an identity whose private keys are NON-EXTRACTABLE CryptoKeys', async () => {
    const id = await loadOrCreateExtensionIdentity();
    expect(id.x25519PrivateKey).toBeInstanceOf(CryptoKey);
    expect(id.ed25519PrivateKey).toBeInstanceOf(CryptoKey);
    expect(id.x25519PrivateKey.extractable).toBe(false);
    expect(id.ed25519PrivateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('pkcs8', id.ed25519PrivateKey)).rejects.toThrow();
    await expect(crypto.subtle.exportKey('pkcs8', id.x25519PrivateKey)).rejects.toThrow();
    expect(id.x25519Pub.byteLength).toBe(32);
    expect(id.ed25519Pub.byteLength).toBe(32);
    expect(id.createdAt).toBeGreaterThan(0);
    // No raw private bytes are exposed on the in-memory identity either.
    expect(Object.keys(id)).not.toContain('x25519Priv');
    expect(Object.keys(id)).not.toContain('ed25519Priv');
  });

  it('signs with the Ed25519 key so the signature verifies under ed25519Pub', async () => {
    const id = await loadOrCreateExtensionIdentity();
    const msg = enc.encode('ready payload');
    const sig = await signWithExtensionIdentity(id, msg);
    expect(sig.byteLength).toBe(64);
    expect(await ed25519Verify(id.ed25519Pub, msg, sig)).toBe(true);
  });

  it('writes NOTHING to chrome.storage.local (a content script finds no key material)', async () => {
    await loadOrCreateExtensionIdentity();
    expect(local.data).toEqual({});
  });

  it('returns the same identity on later calls (and after a service-worker restart)', async () => {
    const id1 = await loadOrCreateExtensionIdentity();
    const id2 = await loadOrCreateExtensionIdentity();
    expect(toB64(id2.x25519Pub)).toBe(toB64(id1.x25519Pub));
    expect(toB64(id2.ed25519Pub)).toBe(toB64(id1.ed25519Pub));
    expect(id2.createdAt).toBe(id1.createdAt);
    // The key persisted in IndexedDB is the one that signs after a reload.
    const msg = enc.encode('x');
    expect(
      await ed25519Verify(id1.ed25519Pub, msg, await signWithExtensionIdentity(id2, msg)),
    ).toBe(true);
  });

  it('two concurrent first loads (popup + service worker) agree on ONE identity', async () => {
    const [a, b] = await Promise.all([
      loadOrCreateExtensionIdentity(),
      loadOrCreateExtensionIdentity(),
    ]);
    expect(toB64(a.ed25519Pub)).toBe(toB64(b.ed25519Pub));
  });

  it('a new profile (fresh IndexedDB) mints a different identity', async () => {
    const id1 = await loadOrCreateExtensionIdentity();
    freshVault();
    installChromeLocal();
    const id2 = await loadOrCreateExtensionIdentity();
    expect(toB64(id2.x25519Pub)).not.toBe(toB64(id1.x25519Pub));
  });

  it('ignores an identity a content script plants in storage.local AFTER the vault exists', async () => {
    const id = await loadOrCreateExtensionIdentity();
    const planted = await legacyStored();
    local.data['extensionIdentity'] = planted.stored;
    const again = await loadOrCreateExtensionIdentity();
    expect(toB64(again.ed25519Pub)).toBe(toB64(id.ed25519Pub));
    expect(toB64(again.ed25519Pub)).not.toBe(toB64(planted.ed.publicKey));
  });
});

describe('loadOrCreateExtensionIdentity — migration from storage.local (no re-pair)', () => {
  let local: LocalArea;
  beforeEach(() => {
    freshVault();
    local = installChromeLocal();
  });

  it('keeps the SAME keys: pubs unchanged, signatures byte-identical to the legacy key', async () => {
    const legacy = await legacyStored();
    local.data['extensionIdentity'] = legacy.stored;
    const id = await loadOrCreateExtensionIdentity();
    expect(toB64(id.x25519Pub)).toBe(toB64(legacy.x.publicKey));
    expect(toB64(id.ed25519Pub)).toBe(toB64(legacy.ed.publicKey));
    expect(id.createdAt).toBe(1234);
    // Ed25519 is deterministic: the imported key IS the legacy key.
    const msg = enc.encode('same key');
    expect(toB64(await signWithExtensionIdentity(id, msg))).toBe(
      toB64(await ed25519Sign(legacy.ed.privateKey, msg)),
    );
    // Same for X25519: the imported private key derives the same secret.
    const peer = await generateX25519();
    const peerPub = await crypto.subtle.importKey(
      'raw',
      peer.publicKey as BufferSource,
      { name: 'X25519' },
      false,
      [],
    );
    const bits = new Uint8Array(
      await crypto.subtle.deriveBits({ name: 'X25519', public: peerPub }, id.x25519PrivateKey, 256),
    );
    expect(toB64(bits)).toBe(toB64(await ecdhX25519(legacy.x.privateKey, peer.publicKey)));
  });

  it('imports the legacy keys as NON-EXTRACTABLE and deletes them from storage.local', async () => {
    const legacy = await legacyStored();
    local.data['extensionIdentity'] = legacy.stored;
    const id = await loadOrCreateExtensionIdentity();
    expect(id.ed25519PrivateKey.extractable).toBe(false);
    expect(id.x25519PrivateKey.extractable).toBe(false);
    expect('extensionIdentity' in local.data).toBe(false);
    const dump = allStrings(local.data);
    expect(dump).not.toContain(legacy.stored.ed25519Priv as string);
    expect(dump).not.toContain(legacy.stored.x25519Priv as string);
  });

  it('migrates once: the identity survives the legacy copy being gone', async () => {
    const legacy = await legacyStored();
    local.data['extensionIdentity'] = legacy.stored;
    await loadOrCreateExtensionIdentity();
    const again = await loadOrCreateExtensionIdentity();
    expect(toB64(again.ed25519Pub)).toBe(toB64(legacy.ed.publicKey));
  });

  it('refuses a legacy record whose private key does not match its public key', async () => {
    const legacy = await legacyStored();
    const other = await generateEd25519();
    local.data['extensionIdentity'] = { ...legacy.stored, ed25519Pub: toB64(other.publicKey) };
    const id = await loadOrCreateExtensionIdentity();
    expect(toB64(id.ed25519Pub)).not.toBe(toB64(other.publicKey));
    expect(toB64(id.ed25519Pub)).not.toBe(toB64(legacy.ed.publicKey));
    expect('extensionIdentity' in local.data).toBe(false);
  });

  it('refuses a malformed legacy record and mints a fresh identity', async () => {
    local.data['extensionIdentity'] = { x25519Priv: 'nope', createdAt: 'x' };
    const id = await loadOrCreateExtensionIdentity();
    expect(id.ed25519Pub.byteLength).toBe(32);
    expect('extensionIdentity' in local.data).toBe(false);
  });
});
