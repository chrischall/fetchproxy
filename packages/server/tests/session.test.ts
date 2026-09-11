import { describe, it, expect } from 'vitest';
import { SessionState } from '../src/session.js';

/**
 * The inbound gate as its call sites now spell it: claim, open the frame,
 * commit (or release). The claim is synchronous and the commit is not, which
 * is the whole point — see `session.ts`.
 */
function accept(s: SessionState, seq: number): boolean {
  if (!s.claimInboundSeq(seq)) return false;
  // In the real callers the AES-GCM open happens here.
  s.commitInboundSeq(seq);
  return true;
}

/** A frame that claimed its seq and then failed to authenticate. */
function refuse(s: SessionState, seq: number): boolean {
  if (!s.claimInboundSeq(seq)) return false;
  s.releaseInboundSeq(seq);
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

  it('a released claim does not advance the counter', () => {
    // The property the split exists for: a frame that fails to authenticate
    // gives its claim back, and the genuine frames behind it — carrying LOWER
    // seqs — must still be accepted.
    const s = new SessionState(new Uint8Array(32));
    expect(refuse(s, 9)).toBe(true);
    expect(refuse(s, 9)).toBe(true);
    expect(accept(s, 1)).toBe(true);
    expect(accept(s, 1)).toBe(false);
  });

  it('a claim is exclusive until it is resolved', () => {
    // The regression the claim closes: two identical frames read in one pass
    // both reach the gate before either can commit. The second must be
    // refused there, because after it there is nothing left to refuse it.
    const s = new SessionState(new Uint8Array(32));
    expect(s.claimInboundSeq(4)).toBe(true);
    expect(s.claimInboundSeq(4)).toBe(false);
    // Resolved either way, the seq is settled: spent by a commit…
    s.commitInboundSeq(4);
    expect(s.claimInboundSeq(4)).toBe(false);
    // …and open again after a release, since that frame never happened.
    expect(refuse(s, 5)).toBe(true);
    expect(accept(s, 5)).toBe(true);
  });

  it('outstanding claims are bounded, and the bound spends no seq', () => {
    // Every claim is released or committed by the caller that made it, so the
    // set drains on its own; the bound is there so a flood of frames that are
    // never opened cannot make it a leak. Past it a frame is dropped unread —
    // and nothing is committed by that, so the same seq is taken once the
    // flood drains.
    const s = new SessionState(new Uint8Array(32));
    for (let seq = 1; seq <= 1024; seq += 1) expect(s.claimInboundSeq(seq)).toBe(true);
    expect(s.claimInboundSeq(2000)).toBe(false);
    for (let seq = 1; seq <= 1024; seq += 1) s.releaseInboundSeq(seq);
    expect(accept(s, 2000)).toBe(true);
  });

  it('committing never moves the counter backwards', () => {
    const s = new SessionState(new Uint8Array(32));
    s.commitInboundSeq(5);
    s.commitInboundSeq(2);
    expect(s.claimInboundSeq(5)).toBe(false);
    expect(s.claimInboundSeq(6)).toBe(true);
  });

  it('outbound and inbound counters are independent', () => {
    const s = new SessionState(new Uint8Array(32));
    expect(s.nextOutboundSeq()).toBe(1);
    expect(accept(s, 1)).toBe(true);
    expect(s.nextOutboundSeq()).toBe(2);
    expect(accept(s, 2)).toBe(true);
  });
});
