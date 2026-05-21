import { describe, it, expect } from 'vitest';
import { derivePairCode } from '../src/pair-code.js';

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
});
