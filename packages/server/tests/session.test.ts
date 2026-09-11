import { describe, it, expect } from 'vitest';
import { SessionState } from '../src/session.js';

/**
 * The inbound gate as its call sites now spell it: ask, open the frame,
 * commit. The two halves are separate so a frame that never authenticated
 * cannot move the counter — see `session.ts`.
 */
function accept(s: SessionState, seq: number): boolean {
  if (!s.isFreshInboundSeq(seq)) return false;
  // In the real callers the AES-GCM open happens here.
  s.commitInboundSeq(seq);
  return true;
}

describe('SessionState', () => {
  it('exposes session key as-is', () => {
    const k = new Uint8Array(32).fill(7);
    const s = new SessionState(k);
    expect(Buffer.from(s.sessionKey).equals(Buffer.from(k))).toBe(true);
  });

  it('outbound seq starts at 1 and increments', () => {
    const s = new SessionState(new Uint8Array(32));
    expect(s.nextOutboundSeq()).toBe(1);
    expect(s.nextOutboundSeq()).toBe(2);
    expect(s.nextOutboundSeq()).toBe(3);
  });

  it('accepts strictly-increasing inbound seq', () => {
    const s = new SessionState(new Uint8Array(32));
    expect(accept(s, 1)).toBe(true);
    expect(accept(s, 2)).toBe(true);
    expect(accept(s, 5)).toBe(true);  // gaps OK as long as strictly increasing
  });

  it('rejects replayed inbound seq (equal)', () => {
    const s = new SessionState(new Uint8Array(32));
    expect(accept(s, 1)).toBe(true);
    expect(accept(s, 1)).toBe(false);
  });

  it('rejects out-of-order inbound seq', () => {
    const s = new SessionState(new Uint8Array(32));
    expect(accept(s, 5)).toBe(true);
    expect(accept(s, 3)).toBe(false);
  });

  it('asking about an inbound seq does not advance the counter', () => {
    // The property the split exists for: a frame that fails to authenticate
    // is asked about and then dropped, and the genuine frames behind it —
    // carrying LOWER seqs — must still be accepted.
    const s = new SessionState(new Uint8Array(32));
    expect(s.isFreshInboundSeq(9)).toBe(true);
    expect(s.isFreshInboundSeq(9)).toBe(true);
    expect(accept(s, 1)).toBe(true);
    expect(accept(s, 1)).toBe(false);
  });

  it('committing never moves the counter backwards', () => {
    const s = new SessionState(new Uint8Array(32));
    s.commitInboundSeq(5);
    s.commitInboundSeq(2);
    expect(s.isFreshInboundSeq(5)).toBe(false);
    expect(s.isFreshInboundSeq(6)).toBe(true);
  });

  it('outbound and inbound counters are independent', () => {
    const s = new SessionState(new Uint8Array(32));
    expect(s.nextOutboundSeq()).toBe(1);
    expect(accept(s, 1)).toBe(true);
    expect(s.nextOutboundSeq()).toBe(2);
    expect(accept(s, 2)).toBe(true);
  });
});
