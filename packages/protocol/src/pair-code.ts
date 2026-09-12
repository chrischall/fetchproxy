import { sha256 } from './crypto.js';

const enc = new TextEncoder();

/**
 * Domain label, so a pair transcript can never be mistaken for any other
 * hashed or signed string in this protocol. Same convention as `frameAad`.
 */
const PAIR_LABEL = 'fetchproxy/4/pair';

/**
 * The human-verifiable pair code (SAS — Short Authentication String), in one
 * place so the MCP that prints the number and the extension that shows it
 * cannot drift apart.
 *
 * ```
 * pairTranscript(mcpIdentityPub, extIdentityPub, mcpNonce, extNonce, mcpSessionPub)
 *   = SHA256(utf8('fetchproxy/4/pair') || NUL || mcpIdentityPub
 *            || extIdentityPub || mcpNonce || extNonce || mcpSessionPub)
 * code = first 8 bytes, big-endian → BigInt → mod 100_000_000 → "XXXX-XXXX"
 * ```
 *
 * **Why this is not {@link transcriptHash}.** The session transcript contains
 * the EXTENSION's ephemeral, which arrives in the `ready`; the pair code has
 * to be on screen at the pair PROMPT, before any `ready` exists. At that
 * moment the extension has minted no ephemeral of its own and the MCP has no
 * `ready` in hand either, so this is a second, separate transcript over the
 * five values both ends do hold there: the two long-term identity pubs, the
 * two hello nonces, and the MCP's session ephemeral.
 *
 * **What it buys, stated honestly.** It does NOT remove the grind. A MITM
 * posing as the extension chooses its own identity, its own nonce and its own
 * ephemeral, so it can always grind its own side against a code it wants to
 * hit. What changes is:
 *
 * 1. the grind is ONLINE and PER-PAIRING. The v3 derivation was
 *    `SHA256(mcpPub || extPub)` over two public, LONG-TERM values, so one
 *    OFFLINE grind against a given MCP identity produced a code that stayed
 *    usable against that MCP forever. A transcript carrying both fresh nonces
 *    and the MCP's per-session ephemeral makes every pairing attempt its own
 *    puzzle, inside the pairing window; and
 * 2. the cost of that online grind rises from ~10⁶ to ~10⁸ hashes (6 digits
 *    to 8).
 *
 * Eight bytes read as a BigInt rather than v3's `h[0..3]` uint32: `2**32 %
 * 10**8` leaves a 2.4% skew across the digit space, which is sloppy in a SAS
 * and free to avoid. From 64 bits the bias is ~5e-12.
 *
 * Both orders are fixed — the MCP's identity before the extension's, the
 * MCP's nonce before the extension's — and both ends must agree on them or
 * the codes diverge. Only the label is variable-length, and a single NUL ends
 * it; every field after it is 32 octets, so the encoding is unambiguous with
 * no separators between them.
 */
export async function pairTranscript(
  mcpIdentityPub: Uint8Array,
  extIdentityPub: Uint8Array,
  mcpNonce: Uint8Array,
  extNonce: Uint8Array,
  mcpSessionPub: Uint8Array,
): Promise<string> {
  const label = enc.encode(PAIR_LABEL);
  const parts = [mcpIdentityPub, extIdentityPub, mcpNonce, extNonce, mcpSessionPub];
  const out = new Uint8Array(label.length + 1 + parts.reduce((n, p) => n + p.length, 0));
  out.set(label, 0);
  // The NUL that ends the label. `out` is zero-filled, so this byte is
  // already zero — written explicitly because the separator is part of the
  // encoding rather than an accident of how the buffer was allocated.
  out[label.length] = 0;
  let at = label.length + 1;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return digits(await sha256(out));
}

/**
 * The digit reduction. Module-private on purpose: a second exported entry
 * point over the raw primitive is exactly how v3's derivation stayed
 * reachable after the wrapper above it was deprecated, and there is only one
 * number in this protocol a person reads off a screen.
 */
function digits(hash: Uint8Array): string {
  // sha256 returns 32 bytes, so hash[0..7] are guaranteed present. Read them
  // big-endian into a BigInt: there is no 32-bit intermediate, so there is no
  // signed/unsigned slip of the kind v3's `>>> 0` existed to prevent.
  let n = 0n;
  for (let i = 0; i < 8; i++) n = (n << 8n) | BigInt(hash[i] ?? 0);
  const s = (n % 100_000_000n).toString().padStart(8, '0');
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}
