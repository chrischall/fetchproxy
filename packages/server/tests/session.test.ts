import { describe, it, expect } from 'vitest';
import { SessionState } from '../src/session.js';

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
    expect(s.acceptInboundSeq(1)).toBe(true);
    expect(s.acceptInboundSeq(2)).toBe(true);
    expect(s.acceptInboundSeq(5)).toBe(true);  // gaps OK as long as strictly increasing
  });

  it('rejects replayed inbound seq (equal)', () => {
    const s = new SessionState(new Uint8Array(32));
    expect(s.acceptInboundSeq(1)).toBe(true);
    expect(s.acceptInboundSeq(1)).toBe(false);
  });

  it('rejects out-of-order inbound seq', () => {
    const s = new SessionState(new Uint8Array(32));
    expect(s.acceptInboundSeq(5)).toBe(true);
    expect(s.acceptInboundSeq(3)).toBe(false);
  });

  it('outbound and inbound counters are independent', () => {
    const s = new SessionState(new Uint8Array(32));
    expect(s.nextOutboundSeq()).toBe(1);
    expect(s.acceptInboundSeq(1)).toBe(true);
    expect(s.nextOutboundSeq()).toBe(2);
    expect(s.acceptInboundSeq(2)).toBe(true);
  });
});
