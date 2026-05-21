import { sha256 } from './crypto.js';

/**
 * Derive a human-verifiable 6-digit pair code from a public key.
 * SAS (Short Authentication String) pattern: code commits to the key,
 * so verifying code matches MCP's terminal output authenticates the key.
 *
 * code = first 4 bytes of SHA256(pub) → uint32 → mod 1_000_000 → "XXX-XXX"
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
