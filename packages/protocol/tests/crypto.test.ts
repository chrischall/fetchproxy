import { describe, it, expect } from 'vitest';
import {
  generateX25519,
  generateEd25519,
  ed25519Sign,
  ed25519Verify,
  ecdhX25519,
  hkdfSha256,
  aesGcmSeal,
  aesGcmOpen,
  sha256,
} from '../src/crypto.js';

describe('crypto', () => {
  it('generates X25519 keypair with 32-byte raw values', async () => {
    const kp = await generateX25519();
    expect(kp.privateKey.byteLength).toBe(32);
    expect(kp.publicKey.byteLength).toBe(32);
  });

  it('ECDH agrees on a shared secret', async () => {
    const a = await generateX25519();
    const b = await generateX25519();
    const ab = await ecdhX25519(a.privateKey, b.publicKey);
    const ba = await ecdhX25519(b.privateKey, a.publicKey);
    expect(Buffer.from(ab).equals(Buffer.from(ba))).toBe(true);
  });

  it('Ed25519 sign+verify round-trips', async () => {
    const kp = await generateEd25519();
    const msg = new TextEncoder().encode('hello');
    const sig = await ed25519Sign(kp.privateKey, msg);
    expect(await ed25519Verify(kp.publicKey, msg, sig)).toBe(true);
    const tampered = new TextEncoder().encode('hellp');
    expect(await ed25519Verify(kp.publicKey, tampered, sig)).toBe(false);
  });

  it('HKDF-SHA256 derives 32 bytes deterministically', async () => {
    const ikm = new Uint8Array(32).fill(1);
    const salt = new Uint8Array(16).fill(2);
    const info = new TextEncoder().encode('test');
    const k1 = await hkdfSha256(ikm, salt, info, 32);
    const k2 = await hkdfSha256(ikm, salt, info, 32);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(true);
    expect(k1.byteLength).toBe(32);
  });

  it('AES-GCM seal+open round-trips and detects tampering', async () => {
    const key = new Uint8Array(32).fill(7);
    const iv = new Uint8Array(12).fill(3);
    const pt = new TextEncoder().encode('{"x":1}');
    const ct = await aesGcmSeal(key, iv, pt);
    expect(ct.byteLength).toBe(pt.byteLength + 16); // GCM tag
    const dec = await aesGcmOpen(key, iv, ct);
    expect(new TextDecoder().decode(dec)).toBe('{"x":1}');
    const tampered = new Uint8Array(ct);
    tampered[0] ^= 1;
    await expect(aesGcmOpen(key, iv, tampered)).rejects.toThrow();
  });

  it('sha256 produces 32 bytes', async () => {
    const h = await sha256(new TextEncoder().encode('abc'));
    expect(h.byteLength).toBe(32);
    expect(Buffer.from(h).toString('hex')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});
