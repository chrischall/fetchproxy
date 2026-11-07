/**
 * #460: binary `fetch` — an opt-in mode that carries a response's BYTES.
 *
 * Every `fetch` before this decoded the body with `response.text()`, which is
 * lossy: invalid UTF-8 becomes U+FFFD and cannot be recovered, so a PDF, a
 * zip-based office file or an image came back corrupted. A hosted MCP whose
 * files live on a host it cannot reach directly had no route to the bytes.
 *
 * The mode is additive inside protocol 4, in four places:
 *
 * 1. `FetchInit.responseType: 'base64'` asks for it. Absent means text, and a
 *    text request's frame is byte-for-byte what it was.
 * 2. The answer reuses `body`, holding standard padded base64, marked
 *    `bodyEncoding: 'base64'`, beside a relayed header subset
 *    ({@link RELAYED_RESPONSE_HEADERS}). Reusing `body` keeps every published
 *    validator accepting the frame (they require `body` to be a string and
 *    ignore the rest); the marker is what makes the bytes unambiguous.
 * 3. `HelloFrameFromExtension.features` lists {@link EXTENSION_FEATURE_FETCH_BASE64}
 *    when the extension can serve it, so a server can refuse locally — "update
 *    the extension" — rather than send a request an older extension would
 *    silently answer as text. Unsigned and advisory, like
 *    `unavailableCapabilities`: the marker in (2) is what a server trusts.
 * 4. A refusal for size carries `code: 'response_too_large'` and the wording
 *    from {@link responseTooLargeMessage}.
 *
 * Nothing here feeds trust, pinning, the pair code, key derivation or a grant.
 */

/** `FetchInit.responseType` value that asks for the body as base64 bytes. */
export const FETCH_RESPONSE_TYPE_BASE64 = 'base64' as const;

/** The response types a `FetchInit` may name. Absent means text. */
export type FetchResponseType = typeof FETCH_RESPONSE_TYPE_BASE64;

/**
 * Feature names an extension may list in its hello. One today. A name this
 * build does not know is admitted by the validator and ignored by a receiver,
 * so an extension can add one without refusing older MCPs.
 */
export const EXTENSION_FEATURE_FETCH_BASE64 = 'fetch_base64' as const;

export type ExtensionFeature = typeof EXTENSION_FEATURE_FETCH_BASE64;

export const KNOWN_EXTENSION_FEATURES: ReadonlySet<ExtensionFeature> = new Set<ExtensionFeature>([
  EXTENSION_FEATURE_FETCH_BASE64,
]);

/** Upper bound the validator puts on `features`. */
export const MAX_EXTENSION_FEATURES = 32;

/** Bounds on one feature name's length, in UTF-16 code units. */
export const MAX_EXTENSION_FEATURE_LENGTH = 64;

/**
 * What the extension spreads into its hello: `{}` for nothing, so a hello
 * listing no features keeps its old bytes, otherwise sorted and de-duplicated.
 */
export function extensionFeaturesHelloField(features: Iterable<ExtensionFeature>): {
  features?: ExtensionFeature[];
} {
  const list = [...new Set(features)].sort();
  return list.length === 0 ? {} : { features: list };
}

/**
 * The per-message limit of the hosted relay a remote bridge link crosses —
 * a Cloudflare Durable Object WebSocket, which accepts at most 32 MiB in one
 * message. A frame over it is not refused per request: the platform closes
 * the socket, and every session on that link goes with it.
 *
 * Recorded here because it is the binding limit for the binary cap below, and
 * a test holds the cap's worst-case frame under it. It is NOT enforced by this
 * package; {@link MAX_FRAME_BYTES} is the receiver cap the protocol enforces.
 */
export const HOSTED_RELAY_MESSAGE_BYTES = 32 * 1024 * 1024;

/**
 * The largest binary body, in BYTES, an extension relays in one response.
 *
 * Derived from the two transport limits, not picked for convenience. A
 * binary body crosses as base64 inside JSON (×4/3, and base64 needs no JSON
 * escaping), then the sealed frame base64s the ciphertext again (×4/3), so the
 * wire frame is about 16/9 of the body:
 *
 * ```
 *   16 MiB body                         16,777,216 bytes
 *   base64 in the inner frame           22,369,624
 *   + url, relayed headers, keys        ~   12,000  (an 8 KB URL is generous)
 *   + AES-GCM tag, ×4/3, envelope       29,842,000  ≈ 28.5 MiB on the wire
 * ```
 *
 * That clears the hosted relay's 32 MiB message limit
 * ({@link HOSTED_RELAY_MESSAGE_BYTES}) with room for a long URL, and
 * {@link MAX_FRAME_BYTES} (42 MiB) easily. 20 MiB would already be 35.6 MiB
 * on the wire and close a hosted link; 25 MiB would exceed the local cap too.
 * Raising this needs a chunked transfer, not a bigger number.
 */
export const MAX_BINARY_RESPONSE_BYTES = 16 * 1024 * 1024;

/**
 * The response headers a binary answer relays, lower-cased. Exactly what a
 * server needs before it trusts a body — what it is, how big it claimed to
 * be, and what it is called — and nothing that would leak more of the
 * response (no `set-cookie`, which the browser withholds anyway).
 */
export const RELAYED_RESPONSE_HEADERS = [
  'content-type',
  'content-length',
  'content-disposition',
] as const;

export type RelayedResponseHeader = (typeof RELAYED_RESPONSE_HEADERS)[number];

/** `InnerResponseError.code` for a body over the binary cap. */
export const RESPONSE_TOO_LARGE_CODE = 'response_too_large' as const;

/**
 * The fixed wording of a binary-size refusal. It starts `response body too
 * large:` on purpose: every published server already classifies that prefix
 * as `body_too_large`, so an MCP older than this refusal still files it in
 * the right bucket.
 *
 * `declaredBytes` is set when the refusal came from `content-length`, before
 * any of the body was read; absent when the cap was hit while streaming
 * (no length, or one that lied).
 */
export function responseTooLargeMessage(info: {
  limitBytes: number;
  declaredBytes?: number;
}): string {
  return info.declaredBytes !== undefined
    ? `response body too large: content-length ${info.declaredBytes} exceeds the ${info.limitBytes}-byte binary cap`
    : `response body too large: more than the ${info.limitBytes}-byte binary cap was received`;
}

const TOO_LARGE_DECLARED_RE =
  /^response body too large: content-length (\d{1,16}) exceeds the (\d{1,16})-byte binary cap/;
const TOO_LARGE_STREAMED_RE =
  /^response body too large: more than the (\d{1,16})-byte binary cap was received/;

/** Parse {@link responseTooLargeMessage}'s wording back out, or `null`. */
export function parseResponseTooLarge(
  error: string,
): { limitBytes: number; declaredBytes: number | null } | null {
  const declared = TOO_LARGE_DECLARED_RE.exec(error);
  if (declared) return { limitBytes: Number(declared[2]), declaredBytes: Number(declared[1]) };
  const streamed = TOO_LARGE_STREAMED_RE.exec(error);
  if (streamed) return { limitBytes: Number(streamed[1]), declaredBytes: null };
  return null;
}

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Is `s` standard, padded base64 with no whitespace — exactly what `btoa`
 * produces? Strict on purpose: Node's `Buffer.from(s, 'base64')` silently
 * drops characters it does not understand, so a lenient check here would let
 * a corrupted body decode to the wrong bytes without a word.
 */
export function isBase64Body(s: string): boolean {
  return s.length % 4 === 0 && BASE64_RE.test(s);
}
