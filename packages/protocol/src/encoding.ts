/**
 * Tiny base64/hex/byte-concat helpers used by every fetchproxy package.
 *
 * Implemented with the browser-friendly `btoa`/`atob` pair plus a tight
 * loop so the same module works unmodified in Node 22+, modern browsers,
 * and MV3 service workers. Node's `Buffer` is intentionally NOT used
 * here — this file is imported from the extension where `Buffer` does
 * not exist.
 *
 * Callers that already have a `Buffer` (Node-only paths in the server
 * package) can keep using it; these helpers are the lowest-common-
 * denominator path for code that has to compile against both runtimes.
 */

/** Standard base64 encode of a Uint8Array (no URL-safe variant). */
export function toB64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return btoa(s);
}

/** Inverse of `toB64`. Throws on invalid base64 (DOMException via `atob`). */
export function fromB64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Lower-case hex encoding. Each byte renders as two characters. */
export function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += (bytes[i] as number).toString(16).padStart(2, '0');
  return s;
}

/**
 * Concatenate two Uint8Arrays into a fresh one. Used to build the
 * `mcpId || sessionNonce` message that we Ed25519-sign on every hello.
 */
export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
