import { sha256 } from './crypto.js';
import { concatBytes } from './encoding.js';

/**
 * Derive a human-verifiable 6-digit pair code from a public key.
 * SAS (Short Authentication String) pattern: code commits to the key,
 * so verifying code matches MCP's terminal output authenticates the key.
 *
 * code = first 4 bytes of SHA256(pub) → uint32 → mod 1_000_000 → "XXX-XXX"
 *
 * 0.4.0+: prefer `derivePairCodeFromIds(mcpPub, extPub)` for new
 * code — that variant commits to BOTH endpoints' identities and
 * defeats a MITM-as-extension relay attempt. This single-arg variant
 * is retained as the SHA-256-then-digits primitive for both code
 * paths.
 */
export async function derivePairCode(pub: Uint8Array): Promise<string> {
  const h = await sha256(pub);
  // Read first 4 bytes as big-endian uint32, then mod 1_000_000 for 6 digits.
  // sha256 returns 32 bytes, so h[0..3] are guaranteed present.
  const b0 = h[0] ?? 0;
  const b1 = h[1] ?? 0;
  const b2 = h[2] ?? 0;
  const b3 = h[3] ?? 0;
  const u32 = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
  const n = u32 % 1_000_000;
  const s = n.toString().padStart(6, '0');
  return `${s.slice(0, 3)}-${s.slice(3)}`;
}

/**
 * Derive a 6-digit pair code committed to BOTH endpoints' X25519
 * identity pubs (MCP || extension). Used by the 0.4.0 mutual-auth
 * design: a MITM-as-extension process X cannot produce the same code
 * as the real extension because its identity pub differs, so the
 * user sees a code mismatch when comparing the MCP terminal output
 * against the browser popup.
 *
 * Concatenation is fixed: `mcpPub || extPub` in that order. Both
 * sides must agree on the order or the codes diverge.
 */
export async function derivePairCodeFromIds(
  mcpPub: Uint8Array,
  extPub: Uint8Array,
): Promise<string> {
  return derivePairCode(concatBytes(mcpPub, extPub));
}
