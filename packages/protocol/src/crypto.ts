// Web Crypto wrappers. Pure async, no Node-only APIs — works in both Node 22+
// (which has X25519/Ed25519 in webcrypto) and modern browsers/MV3 service workers.
//
// Note on the `as BufferSource` casts: recent @types/node ship a generic
// `Uint8Array<ArrayBufferLike>` whose buffer may be SharedArrayBuffer, while
// `SubtleCrypto`'s lib.dom types still require `BufferSource =
// ArrayBuffer | ArrayBufferView<ArrayBuffer>`. The runtime accepts both, so we
// cast at the boundary rather than burden callers with an `<ArrayBuffer>`
// generic. See https://github.com/microsoft/TypeScript/issues/61081.

const subtle: SubtleCrypto = (globalThis.crypto as Crypto).subtle;

export interface RawKeyPair {
  privateKey: Uint8Array; // raw, 32 bytes
  publicKey: Uint8Array; // raw, 32 bytes
}

async function exportRaw(key: CryptoKey, format: 'raw' | 'pkcs8' | 'spki'): Promise<Uint8Array> {
  const buf = await subtle.exportKey(format, key);
  return new Uint8Array(buf);
}

export async function generateX25519(): Promise<RawKeyPair> {
  const kp = (await subtle.generateKey({ name: 'X25519' }, true, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const priv = await exportRaw(kp.privateKey, 'pkcs8');
  const pub = await exportRaw(kp.publicKey, 'raw');
  // pkcs8 wraps the 32-byte raw key — last 32 bytes
  return { privateKey: priv.slice(-32), publicKey: pub };
}

export async function generateEd25519(): Promise<RawKeyPair> {
  const kp = (await subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const priv = await exportRaw(kp.privateKey, 'pkcs8');
  const pub = await exportRaw(kp.publicKey, 'raw');
  return { privateKey: priv.slice(-32), publicKey: pub };
}

async function importX25519Priv(raw: Uint8Array): Promise<CryptoKey> {
  // Wrap 32-byte raw in a minimal pkcs8 envelope.
  // OID 1.3.101.110 (X25519): 30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20 [32 bytes]
  const prefix = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8 = new Uint8Array(prefix.length + raw.length);
  pkcs8.set(prefix, 0);
  pkcs8.set(raw, prefix.length);
  return subtle.importKey('pkcs8', pkcs8 as BufferSource, { name: 'X25519' }, false, [
    'deriveBits',
  ]);
}

async function importX25519Pub(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey('raw', raw as BufferSource, { name: 'X25519' }, false, []);
}

async function importEd25519Priv(raw: Uint8Array): Promise<CryptoKey> {
  // OID 1.3.101.112 (Ed25519): 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 [32 bytes]
  const prefix = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8 = new Uint8Array(prefix.length + raw.length);
  pkcs8.set(prefix, 0);
  pkcs8.set(raw, prefix.length);
  return subtle.importKey('pkcs8', pkcs8 as BufferSource, { name: 'Ed25519' }, false, ['sign']);
}

async function importEd25519Pub(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey('raw', raw as BufferSource, { name: 'Ed25519' }, false, ['verify']);
}

export async function ecdhX25519(privRaw: Uint8Array, pubRaw: Uint8Array): Promise<Uint8Array> {
  const priv = await importX25519Priv(privRaw);
  const pub = await importX25519Pub(pubRaw);
  const bits = await subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256);
  return new Uint8Array(bits);
}

export async function ed25519Sign(privRaw: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const priv = await importEd25519Priv(privRaw);
  const sig = await subtle.sign({ name: 'Ed25519' }, priv, msg as BufferSource);
  return new Uint8Array(sig);
}

export async function ed25519Verify(
  pubRaw: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array,
): Promise<boolean> {
  const pub = await importEd25519Pub(pubRaw);
  return subtle.verify({ name: 'Ed25519' }, pub, sig as BufferSource, msg as BufferSource);
}

export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  lenBytes: number,
): Promise<Uint8Array> {
  const baseKey = await subtle.importKey('raw', ikm as BufferSource, { name: 'HKDF' }, false, [
    'deriveBits',
  ]);
  const bits = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as BufferSource,
      info: info as BufferSource,
    },
    baseKey,
    lenBytes * 8,
  );
  return new Uint8Array(bits);
}

export async function aesGcmSeal(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', key as BufferSource, { name: 'AES-GCM' }, false, [
    'encrypt',
  ]);
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    k,
    plaintext as BufferSource,
  );
  return new Uint8Array(ct);
}

export async function aesGcmOpen(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', key as BufferSource, { name: 'AES-GCM' }, false, [
    'decrypt',
  ]);
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    k,
    ciphertext as BufferSource,
  );
  return new Uint8Array(pt);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const h = await subtle.digest('SHA-256', data as BufferSource);
  return new Uint8Array(h);
}
