import { aesGcmSeal, aesGcmOpen } from './crypto.js';
import { toB64, fromB64 } from './encoding.js';
import type { InnerFrame, EncryptedFrame } from './frames.js';
import { validateInnerFrame } from './validate.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

function randomIv(): Uint8Array {
  const iv = new Uint8Array(12);
  (globalThis.crypto as Crypto).getRandomValues(iv);
  return iv;
}

/**
 * Encrypt an inner frame and produce the wire-format EncryptedFrame.
 * IV is freshly generated per call. AES-256-GCM tag is bundled into ciphertext.
 */
export async function sealInnerFrame(
  sessionKey: Uint8Array,
  mcpId: string,
  seq: number,
  inner: InnerFrame,
): Promise<EncryptedFrame> {
  const iv = randomIv();
  const pt = enc.encode(JSON.stringify(inner));
  const ct = await aesGcmSeal(sessionKey, iv, pt);
  return {
    type: 'frame',
    mcpId,
    seq,
    iv: toB64(iv),
    ciphertext: toB64(ct),
  };
}

/**
 * Decrypt an EncryptedFrame and return the validated inner frame.
 * Throws if the ciphertext is forged or the inner JSON is malformed.
 */
export async function openEncryptedFrame(
  sessionKey: Uint8Array,
  frame: EncryptedFrame,
): Promise<InnerFrame> {
  const iv = fromB64(frame.iv);
  const ct = fromB64(frame.ciphertext);
  const pt = await aesGcmOpen(sessionKey, iv, ct);
  const parsed: unknown = JSON.parse(dec.decode(pt));
  return validateInnerFrame(parsed);
}
