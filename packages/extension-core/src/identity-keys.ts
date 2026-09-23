/**
 * The extension's long-term identity keys as NON-EXTRACTABLE WebCrypto keys
 * (fleet-audit #253).
 *
 * Before the vault the private halves were raw bytes, base64-encoded in
 * `chrome.storage.local["extensionIdentity"]` — readable by the content
 * script on every site, so one renderer compromise could lift them and pose
 * as this extension to every paired MCP (T-fake-extension). Now:
 *
 * - a private key is created (or imported, once, from the legacy record) with
 *   `extractable: false`. WebCrypto will use it — sign, derive — but no API
 *   will hand its bytes back, not even to extension code;
 * - it is persisted by structured clone into the extension-origin IndexedDB
 *   (`vault.ts`), which content scripts cannot open.
 *
 * Both primitives are available non-extractably: `generateKey` /
 * `importKey('pkcs8', …, false, …)` accept `extractable: false` for Ed25519
 * and X25519 exactly as for any other algorithm. The PUBLIC halves stay raw
 * bytes, because they are sent in every hello and compared in trust records.
 *
 * The X25519 private key has no caller today — since protocol 4 the session
 * ECDH is ephemeral × ephemeral, and the long-term X25519 pub is only an
 * identity handle (trust-record hash, pair-code input). It is kept, under the
 * same protection, so the identity stays one coherent keypair set.
 */

import { fromB64 } from '@fetchproxy/protocol';

export interface ExtensionIdentity {
  /** Non-extractable X25519 private key (`deriveBits`). */
  x25519PrivateKey: CryptoKey;
  x25519Pub: Uint8Array;
  /** Non-extractable Ed25519 private key (`sign`). */
  ed25519PrivateKey: CryptoKey;
  ed25519Pub: Uint8Array;
  createdAt: number;
}

const subtle = (): SubtleCrypto => globalThis.crypto.subtle;

// Minimal PKCS#8 envelopes around a raw 32-byte private key (RFC 8410).
const X25519_PKCS8_PREFIX = [
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];
const ED25519_PKCS8_PREFIX = [
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

function pkcs8(prefix: number[], raw: Uint8Array): Uint8Array {
  const out = new Uint8Array(prefix.length + raw.length);
  out.set(prefix, 0);
  out.set(raw, prefix.length);
  return out;
}

function isNonExtractable(k: unknown, alg: string, usage: KeyUsage): k is CryptoKey {
  return (
    typeof CryptoKey !== 'undefined' &&
    k instanceof CryptoKey &&
    k.type === 'private' &&
    k.extractable === false &&
    k.algorithm.name === alg &&
    k.usages.includes(usage)
  );
}

function isPub(b: unknown): b is Uint8Array {
  return b instanceof Uint8Array && b.byteLength === 32;
}

/** Shape check for an identity read back out of the vault. */
export function isExtensionIdentity(x: unknown): x is ExtensionIdentity {
  if (!x || typeof x !== 'object') return false;
  const r = x as Record<string, unknown>;
  return (
    isNonExtractable(r.x25519PrivateKey, 'X25519', 'deriveBits') &&
    isNonExtractable(r.ed25519PrivateKey, 'Ed25519', 'sign') &&
    isPub(r.x25519Pub) &&
    isPub(r.ed25519Pub) &&
    typeof r.createdAt === 'number'
  );
}

/** Mint a fresh identity whose private keys are never extractable. */
export async function generateExtensionIdentity(): Promise<ExtensionIdentity> {
  const x = (await subtle().generateKey({ name: 'X25519' }, false, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const ed = (await subtle().generateKey({ name: 'Ed25519' }, false, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  return {
    x25519PrivateKey: x.privateKey,
    x25519Pub: new Uint8Array(await subtle().exportKey('raw', x.publicKey)),
    ed25519PrivateKey: ed.privateKey,
    ed25519Pub: new Uint8Array(await subtle().exportKey('raw', ed.publicKey)),
    createdAt: Date.now(),
  };
}

/** Sign `msg` with the identity's Ed25519 key (64-byte signature). */
export async function signWithExtensionIdentity(
  id: ExtensionIdentity,
  msg: Uint8Array,
): Promise<Uint8Array> {
  return new Uint8Array(
    await subtle().sign({ name: 'Ed25519' }, id.ed25519PrivateKey, msg as BufferSource),
  );
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let d = 0;
  for (let i = 0; i < a.byteLength; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

function decode32(v: unknown): Uint8Array | null {
  if (typeof v !== 'string') return null;
  try {
    const b = fromB64(v);
    return b.byteLength === 32 ? b : null;
  } catch {
    return null;
  }
}

/**
 * Import a pre-#253 `storage.local["extensionIdentity"]` record as a
 * non-extractable identity, so an upgrade keeps the SAME keys and nobody has
 * to re-pair. Returns null for anything malformed or self-inconsistent — a
 * record whose private halves do not produce its public halves is not this
 * extension's identity, whoever wrote it.
 *
 * The raw bytes are zeroed once imported. (JavaScript cannot promise the
 * base64 strings they came from are gone from memory; they are deleted from
 * storage by the caller, which is what matters.)
 */
export async function importLegacyIdentity(stored: unknown): Promise<ExtensionIdentity | null> {
  if (!stored || typeof stored !== 'object') return null;
  const r = stored as Record<string, unknown>;
  const xPriv = decode32(r.x25519Priv);
  const xPub = decode32(r.x25519Pub);
  const edPriv = decode32(r.ed25519Priv);
  const edPub = decode32(r.ed25519Pub);
  if (!xPriv || !xPub || !edPriv || !edPub || typeof r.createdAt !== 'number') return null;
  const xEnv = pkcs8(X25519_PKCS8_PREFIX, xPriv);
  const edEnv = pkcs8(ED25519_PKCS8_PREFIX, edPriv);
  try {
    const x25519PrivateKey = await subtle().importKey(
      'pkcs8',
      xEnv as BufferSource,
      { name: 'X25519' },
      false,
      ['deriveBits'],
    );
    const ed25519PrivateKey = await subtle().importKey(
      'pkcs8',
      edEnv as BufferSource,
      { name: 'Ed25519' },
      false,
      ['sign'],
    );
    const id: ExtensionIdentity = {
      x25519PrivateKey,
      x25519Pub: xPub,
      ed25519PrivateKey,
      ed25519Pub: edPub,
      createdAt: r.createdAt,
    };
    return (await identityIsConsistent(id)) ? id : null;
  } catch {
    return null;
  } finally {
    xPriv.fill(0);
    edPriv.fill(0);
    xEnv.fill(0);
    edEnv.fill(0);
  }
}

/**
 * Prove each private key belongs to its public key without exporting it:
 * Ed25519 by a sign/verify round trip, X25519 by agreeing a secret with a
 * throwaway key from both ends.
 */
async function identityIsConsistent(id: ExtensionIdentity): Promise<boolean> {
  const probe = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const sig = await signWithExtensionIdentity(id, probe);
  const edPub = await subtle().importKey(
    'raw',
    id.ed25519Pub as BufferSource,
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
  if (
    !(await subtle().verify({ name: 'Ed25519' }, edPub, sig as BufferSource, probe as BufferSource))
  ) {
    return false;
  }
  const eph = (await subtle().generateKey({ name: 'X25519' }, false, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const xPub = await subtle().importKey(
    'raw',
    id.x25519Pub as BufferSource,
    { name: 'X25519' },
    false,
    [],
  );
  const ours = new Uint8Array(
    await subtle().deriveBits({ name: 'X25519', public: eph.publicKey }, id.x25519PrivateKey, 256),
  );
  const theirs = new Uint8Array(
    await subtle().deriveBits({ name: 'X25519', public: xPub }, eph.privateKey, 256),
  );
  return bytesEqual(ours, theirs);
}
