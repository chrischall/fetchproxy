import { describe, it, expect } from 'vitest';
import * as pairCodeModule from '../src/pair-code.js';
import { pairTranscript } from '../src/pair-code.js';

const MCP_ID_PUB = new Uint8Array(32).fill(1);
const EXT_ID_PUB = new Uint8Array(32).fill(2);
const MCP_NONCE = new Uint8Array(32).fill(3);
const EXT_NONCE = new Uint8Array(32).fill(4);
const MCP_SESSION_PUB = new Uint8Array(32).fill(5);

const code = (
  over: Partial<{
    mcpIdentityPub: Uint8Array;
    extIdentityPub: Uint8Array;
    mcpNonce: Uint8Array;
    extNonce: Uint8Array;
    mcpSessionPub: Uint8Array;
  }> = {},
): Promise<string> =>
  pairTranscript(
    over.mcpIdentityPub ?? MCP_ID_PUB,
    over.extIdentityPub ?? EXT_ID_PUB,
    over.mcpNonce ?? MCP_NONCE,
    over.extNonce ?? EXT_NONCE,
    over.mcpSessionPub ?? MCP_SESSION_PUB,
  );

describe('pair-code', () => {
  it('produces XXXX-XXXX format', async () => {
    expect(await code()).toMatch(/^\d{4}-\d{4}$/);
  });

  it('is deterministic for the same five inputs', async () => {
    expect(await code()).toBe(await code());
  });

  // One assertion per input. Five inputs is four more chances for the two
  // ends to disagree than v3's two had, and a derivation that silently
  // dropped one would still produce a matching pair of codes right up until
  // the dropped value was the only thing an attacker had to control.
  it('changes when the MCP identity pub changes', async () => {
    expect(await code()).not.toBe(await code({ mcpIdentityPub: new Uint8Array(32).fill(9) }));
  });

  it('changes when the extension identity pub changes (MITM-as-extension detection)', async () => {
    expect(await code()).not.toBe(await code({ extIdentityPub: new Uint8Array(32).fill(9) }));
  });

  it('changes when the MCP hello nonce changes', async () => {
    expect(await code()).not.toBe(await code({ mcpNonce: new Uint8Array(32).fill(9) }));
  });

  it('changes when the extension hello nonce changes', async () => {
    expect(await code()).not.toBe(await code({ extNonce: new Uint8Array(32).fill(9) }));
  });

  it('changes when the MCP session ephemeral changes', async () => {
    expect(await code()).not.toBe(await code({ mcpSessionPub: new Uint8Array(32).fill(9) }));
  });

  // Both orders are fixed and neither is recoverable from the bytes: every
  // field is 32 octets, so a side that concatenated a pair the other way
  // round hashes a different message of the same length and just shows a
  // different number at pair time.
  it('is order-sensitive across the two identity pubs', async () => {
    expect(await code()).not.toBe(
      await code({ mcpIdentityPub: EXT_ID_PUB, extIdentityPub: MCP_ID_PUB }),
    );
  });

  it('is order-sensitive across the two nonces', async () => {
    expect(await code()).not.toBe(await code({ mcpNonce: EXT_NONCE, extNonce: MCP_NONCE }));
  });

  // Known-answer vectors. They pin the exact encoding —
  //   SHA-256(utf8('fetchproxy/4/pair') || NUL || mcpIdentityPub ||
  //           extIdentityPub || mcpNonce || extNonce || mcpSessionPub)
  //   → first 8 bytes, big-endian → BigInt → mod 100_000_000 → "XXXX-XXXX"
  // so a refactor that moves the hash, the domain label, the NUL, the field
  // order, the width or the reduction fails HERE rather than at pair time,
  // when the user is staring at a mismatched code and nothing says which
  // side moved. Computed with node:crypto independently of this package,
  // which is the only thing that makes a known-answer vector worth having.
  //
  // v3's `>>> 0` high-bit regression vector (`848-182`) is deliberately NOT
  // carried over, and that is a real loss of coverage stated rather than
  // hidden: its whole subject was the signed/unsigned slip in a 32-bit read,
  // and reading 8 bytes as a BigInt removes the read that could slip. The
  // third vector below keeps the same INPUT shape — a digest whose first
  // byte has its high bit set — so the hazard's absence is asserted rather
  // than assumed. Do not restore a test for a 32-bit path this code no
  // longer has.
  it('known-answer: 1/2/3/4/5-filled inputs produce 1686-3825', async () => {
    expect(await code()).toBe('1686-3825');
  });

  it('known-answer: all-zero inputs produce 4223-2044', async () => {
    const zero = new Uint8Array(32);
    expect(await pairTranscript(zero, zero, zero, zero, zero)).toBe('4223-2044');
  });

  it('known-answer: 0x02-filled inputs produce 9666-7484 (digest byte 0 is 0xf4, high bit set)', async () => {
    const two = new Uint8Array(32).fill(2);
    expect(await pairTranscript(two, two, two, two, two)).toBe('9666-7484');
  });

  // Nothing may keep the v3 derivation reachable. `derivePairCode` WAS the v3
  // code — SHA-256 → h[0..3] → uint32 → mod 1e6 — and it was exported through
  // the package's public API, so deleting only the `derivePairCodeFromIds`
  // wrapper over it would have left the long-term, public, offline-grindable
  // derivation one import away.
  it('exports the transcript derivation and nothing else', () => {
    expect(Object.keys(pairCodeModule).sort()).toEqual(['pairTranscript']);
  });
});
