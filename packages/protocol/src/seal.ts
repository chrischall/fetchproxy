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
 *
 * Implemented as a thin wrapper over {@link openEncryptedFrameDetailed} so
 * the decrypt→parse→validate sequence exists in exactly one place; callers
 * that don't need to distinguish "wrong key" from "malformed payload" (this
 * function's original two consumers, `host.ts` and the extension's own
 * request-decode path) keep the simple throw-only contract unchanged.
 */
export async function openEncryptedFrame(
  sessionKey: Uint8Array,
  frame: EncryptedFrame,
): Promise<InnerFrame> {
  const result = await openEncryptedFrameDetailed(sessionKey, frame);
  if (result.stage === 'ok') return result.inner;
  throw result.error instanceof Error ? result.error : new Error(String(result.error));
}

/**
 * Discriminated outcome of {@link openEncryptedFrameDetailed} — lets a
 * caller tell apart WHERE the open failed, which matters because the two
 * failure stages carry very different trust implications:
 *
 *  - `decrypt-failed`: AES-GCM authentication failed — either the wrong
 *    session key (e.g. a straggler frame from a session that already
 *    rotated) or genuinely tampered ciphertext. Nothing about the
 *    plaintext can be trusted or even read; there is no `id` to recover.
 *  - `validation-failed`: decryption SUCCEEDED (AES-GCM authenticated the
 *    ciphertext under the current session key, so this frame really is
 *    from the current, live peer on the other end) but the plaintext
 *    isn't valid JSON, or doesn't match the wire schema. This is a real
 *    protocol bug from a source we just proved is legitimate — not a
 *    stale-key symptom — so it's worth surfacing loudly rather than
 *    dropping silently. `recoveredId` is set when the malformed JSON is
 *    at least a plain object with a positive-integer `id` field, letting
 *    the caller synthesize a targeted `ok:false` response for whichever
 *    pending call is waiting on that id, instead of leaving it to hang
 *    until its own timeout.
 */
export type OpenFrameResult =
  | { stage: 'ok'; inner: InnerFrame }
  | { stage: 'decrypt-failed'; error: unknown }
  | { stage: 'validation-failed'; error: unknown; recoveredId: number | undefined };

/**
 * Like {@link openEncryptedFrame}, but never throws — it returns which
 * stage failed instead. Exists so a caller (currently `peer.ts`) can log a
 * validation failure loudly and, when a numeric `id` is recoverable, route
 * a synthetic error response to the specific pending call rather than
 * either (a) silently dropping the frame — leaving that call to hang until
 * its own timeout with zero diagnostic signal, or (b) tearing down the
 * whole connection over one malformed response, which would be an
 * over-broad reaction to something decryption just proved came from the
 * current, legitimate peer.
 */
export async function openEncryptedFrameDetailed(
  sessionKey: Uint8Array,
  frame: EncryptedFrame,
): Promise<OpenFrameResult> {
  let pt: Uint8Array;
  try {
    // `fromB64` throws on malformed base64 (BASE64_RE doesn't enforce a
    // length multiple of 4, so e.g. `iv: "A"` passes structural frame
    // validation upstream but still isn't decodable) — that decode failure
    // belongs in the SAME "can't trust anything about this frame" bucket
    // as an AES-GCM auth failure, not a separate uncaught throw out of a
    // function documented as never throwing.
    const iv = fromB64(frame.iv);
    const ct = fromB64(frame.ciphertext);
    pt = await aesGcmOpen(sessionKey, iv, ct);
  } catch (error) {
    return { stage: 'decrypt-failed', error };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(dec.decode(pt));
  } catch (error) {
    return { stage: 'validation-failed', error, recoveredId: undefined };
  }
  try {
    const inner = validateInnerFrame(parsed);
    return { stage: 'ok', inner };
  } catch (error) {
    const recoveredId =
      parsed !== null &&
      typeof parsed === 'object' &&
      !Array.isArray(parsed) &&
      typeof (parsed as { id?: unknown }).id === 'number' &&
      Number.isInteger((parsed as { id: number }).id) &&
      (parsed as { id: number }).id > 0
        ? (parsed as { id: number }).id
        : undefined;
    return { stage: 'validation-failed', error, recoveredId };
  }
}
