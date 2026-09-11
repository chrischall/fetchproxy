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

/** The AES-GCM authentication tag `aesGcmSeal` appends to every ciphertext. */
export const AES_GCM_TAG_BYTES = 16;

/** Base64 of the 12-byte IV: four characters per three bytes, no remainder. */
const IV_B64_BYTES = 16;

/** How many bytes standard padded base64 takes for `byteLength` bytes in. */
export function base64Length(byteLength: number): number {
  return Math.ceil(byteLength / 3) * 4;
}

/**
 * The exact plaintext bytes {@link sealInnerFrame} encrypts for this inner
 * frame — the one place `JSON.stringify` is applied to one.
 *
 * Exported so a caller that must MEASURE a frame before sending it pays for
 * the serialisation once: {@link sealedFrameWireBytes} and
 * {@link sealInnerFrame} both take these bytes in place of the object, so the
 * number measured and the frame that goes out come from the same string by
 * construction rather than by two calls agreeing. Measuring and then sealing
 * the object serialised it twice — a second multi-megabyte string plus its
 * encoded copy, inside an MV3 service worker at that.
 */
export function encodeInnerFrame(inner: InnerFrame): Uint8Array {
  return enc.encode(JSON.stringify(inner));
}

/**
 * An inner frame, or the plaintext {@link encodeInnerFrame} already made of
 * one. Interchangeable everywhere either is accepted.
 */
export type InnerFrameOrPlaintext = InnerFrame | Uint8Array;

function plaintextOf(inner: InnerFrameOrPlaintext): Uint8Array {
  return inner instanceof Uint8Array ? inner : encodeInnerFrame(inner);
}

/**
 * Exactly how many bytes this inner frame will occupy on the wire once
 * {@link sealInnerFrame} has sealed it and `JSON.stringify` has rendered the
 * envelope — answered WITHOUT encrypting anything.
 *
 * Exists because the size of a frame has to be decided by its PRODUCER. A
 * WebSocket peer that receives a payload over its `maxPayload` answers by
 * closing the connection (1009), and on the concentrator the extension's
 * connection is the one socket every MCP shares — so "this response is too
 * big" has to be a fact about one request, decided before the frame is sent,
 * rather than a discovery the receiver makes by tearing the socket down.
 *
 * Exact, not an estimate: an under-count lets an oversize frame out, and an
 * over-count refuses one that would have fitted. The only freedom is `seq`,
 * whose decimal width the caller cannot know before it spends one — pass
 * `Number.MAX_SAFE_INTEGER` to measure against the widest a session can
 * reach, which over-counts by a few bytes and never under-counts.
 *
 * Pass {@link encodeInnerFrame}'s output rather than the object when the same
 * frame is about to be sealed: the bytes measured are then literally the bytes
 * encrypted, and the big string is built once.
 */
export function sealedFrameWireBytes(
  mcpId: string,
  seq: number,
  inner: InnerFrameOrPlaintext,
): number {
  const plaintext = plaintextOf(inner).length;
  // The same object `sealInnerFrame` builds, with the two base64 fields empty
  // so their lengths can be added back exactly. Key order and escaping of
  // `mcpId` therefore match the real frame character for character.
  const envelope = enc.encode(
    JSON.stringify({ type: 'frame', mcpId, seq, iv: '', ciphertext: '' }),
  ).length;
  return envelope + IV_B64_BYTES + base64Length(plaintext + AES_GCM_TAG_BYTES);
}

/**
 * The largest frame a conforming end of this protocol may put on the wire.
 *
 * DERIVED, not picked — and the thing it is derived from is the biggest
 * payload a legitimate frame can carry, which is a relayed `fetch` response
 * body. The extension caps one at `MAX_RESPONSE_BODY_BYTES` = 5 MiB, counted
 * in UTF-16 code units (`body.length`), not bytes. From there:
 *
 * ```
 *   body                     5 MiB = 5,242,880 UTF-16 code units
 *   JSON.stringify           x6 bytes/unit worst case: a C0 control character
 *                            with no short escape, or a lone surrogate, is
 *                            rendered `\u001f` — six ASCII bytes for one code
 *                            unit. Ordinary non-ASCII is cheaper (a 3-byte
 *                            BMP character is one unit; a 4-byte astral one is
 *                            two).                         = 31,457,280 bytes
 *   the rest of the inner frame (type/id/ok/op/status/url)
 *                                                          +     65,536 bytes
 *   AES-GCM tag                                            +         16 bytes
 *   base64 of the ciphertext, ceil(n/3)*4                  x 4/3
 *                                                          = 42,030,444 bytes
 *   the {"type":"frame","mcpId":...,"seq":...,"iv":...} envelope
 *                                                          +        512 bytes
 *                                                          = 42,030,956 bytes
 * ```
 *
 * 42 MiB is the next whole mebibyte above that. It is deliberately NOT a
 * number chosen for how much memory a receiver should be willing to buffer:
 * an 8 MiB cap picked that way is what this replaces, and it sat BELOW the
 * frame above, so a large non-ASCII response would have closed the shared
 * socket for every MCP on it.
 *
 * The memory question is answered at the other end instead. The extension
 * measures each frame with {@link sealedFrameWireBytes} before sealing it and
 * refuses the ONE request whose answer would exceed this, so a conforming
 * sender never reaches the receiver's cap at all — which also, finally, puts
 * a bound on `read_indexed_db`, `read_local_storage` and `read_dom`, none of
 * which has a size cap of its own. What is left at the receiver is a backstop
 * against a sender that is not this extension, and 42 MiB still takes 58% off
 * what `ws` would otherwise let an unauthenticated local peer allocate.
 */
export const MAX_FRAME_BYTES = 42 * 1024 * 1024;

/**
 * Encrypt an inner frame and produce the wire-format EncryptedFrame.
 * IV is freshly generated per call. AES-256-GCM tag is bundled into ciphertext.
 *
 * Accepts {@link encodeInnerFrame}'s plaintext as well as the object, so a
 * caller that measured the frame with {@link sealedFrameWireBytes} first can
 * hand over the bytes it already has instead of serialising them again.
 */
export async function sealInnerFrame(
  sessionKey: Uint8Array,
  mcpId: string,
  seq: number,
  inner: InnerFrameOrPlaintext,
): Promise<EncryptedFrame> {
  const iv = randomIv();
  const pt = plaintextOf(inner);
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
