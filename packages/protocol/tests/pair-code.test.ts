import { describe, it, expect } from 'vitest';
import { derivePairCode, derivePairCodeFromIds } from '../src/pair-code.js';

describe('pair-code', () => {
  it('produces XXX-XXX format', async () => {
    const pub = new Uint8Array(32).fill(7);
    const code = await derivePairCode(pub);
    expect(code).toMatch(/^\d{3}-\d{3}$/);
  });

  it('is deterministic for same pubkey', async () => {
    const pub = new Uint8Array(32).fill(42);
    const a = await derivePairCode(pub);
    const b = await derivePairCode(pub);
    expect(a).toBe(b);
  });

  it('different pubkeys produce different codes (high probability)', async () => {
    const a = await derivePairCode(new Uint8Array(32).fill(1));
    const b = await derivePairCode(new Uint8Array(32).fill(2));
    expect(a).not.toBe(b);
  });

  // Known-answer vectors: pin the exact "first 4 bytes of SHA-256(pub) →
  // big-endian uint32 → mod 1_000_000 → XXX-XXX" derivation so any future
  // refactor (different hash, different endian, signed/unsigned slip on
  // high bit) is caught the moment a test runs, not at pair time when the
  // user is staring at a mismatched code and we have no fast way to tell
  // which side moved.
  it('known-answer: all-zeros pubkey produces 123-181', async () => {
    const code = await derivePairCode(new Uint8Array(32));
    expect(code).toBe('123-181');
  });

  it('known-answer: all-0xFF pubkey produces 848-182 (exercises high-bit >>> 0 path)', async () => {
    // SHA-256 of all-0xff bytes happens to put a high-bit byte in the
    // first 4 positions — without the `>>> 0` unsigned coerce, the
    // signed mod would produce a different value. This is the
    // regression test for that subtle bug class.
    const code = await derivePairCode(new Uint8Array(32).fill(0xff));
    expect(code).toBe('848-182');
  });

  it('known-answer: identity-ish 1..32 pubkey produces 425-966', async () => {
    const k = new Uint8Array(32);
    for (let i = 0; i < 32; i++) k[i] = i + 1;
    const code = await derivePairCode(k);
    expect(code).toBe('425-966');
  });

  describe('derivePairCodeFromIds (mutual auth)', () => {
    it('is deterministic for same (mcpPub, extPub)', async () => {
      const mcp = new Uint8Array(32).fill(1);
      const ext = new Uint8Array(32).fill(2);
      const a = await derivePairCodeFromIds(mcp, ext);
      const b = await derivePairCodeFromIds(mcp, ext);
      expect(a).toBe(b);
    });

    it('produces XXX-XXX format', async () => {
      const code = await derivePairCodeFromIds(
        new Uint8Array(32).fill(3),
        new Uint8Array(32).fill(4),
      );
      expect(code).toMatch(/^\d{3}-\d{3}$/);
    });

    it('order-sensitive: (mcpPub, extPub) differs from (extPub, mcpPub)', async () => {
      const mcp = new Uint8Array(32).fill(0xa);
      const ext = new Uint8Array(32).fill(0xb);
      const ab = await derivePairCodeFromIds(mcp, ext);
      const ba = await derivePairCodeFromIds(ext, mcp);
      expect(ab).not.toBe(ba);
    });

    it('different extension pub produces a different code (MITM detection)', async () => {
      const mcp = new Uint8Array(32).fill(7);
      const ext1 = new Uint8Array(32).fill(8);
      const ext2 = new Uint8Array(32).fill(9);
      const code1 = await derivePairCodeFromIds(mcp, ext1);
      const code2 = await derivePairCodeFromIds(mcp, ext2);
      expect(code1).not.toBe(code2);
    });

    it('differs from single-arg derivePairCode (binds both sides)', async () => {
      const mcp = new Uint8Array(32).fill(11);
      const ext = new Uint8Array(32).fill(12);
      const joint = await derivePairCodeFromIds(mcp, ext);
      const mcpOnly = await derivePairCode(mcp);
      expect(joint).not.toBe(mcpOnly);
    });
  });
});
