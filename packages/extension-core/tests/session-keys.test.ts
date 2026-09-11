import { describe, it, expect } from 'vitest';
import { SessionKeys, type SessionEntry } from '../src/session-keys.js';

/**
 * The inbound gate as `onEncryptedFrame` now spells it: ask, open the frame,
 * commit. The two halves are separate so a frame that never authenticated
 * cannot move the counter — see `session-keys.ts`.
 */
function accept(s: SessionEntry, seq: number): boolean {
  if (!s.isFreshInboundSeq(seq)) return false;
  // In the real caller the AES-GCM open happens here.
  s.commitInboundSeq(seq);
  return true;
}

describe('SessionKeys', () => {
  it('returns null for unknown mcpId', () => {
    const sk = new SessionKeys();
    expect(sk.get('opentable-mcp:0.1.0:abc1234567890def')).toBeNull();
  });

  it('stores and retrieves a session', () => {
    const sk = new SessionKeys();
    const key = new Uint8Array(32).fill(7);
    sk.set('opentable-mcp:0.1.0:abc1234567890def', key);
    const s = sk.get('opentable-mcp:0.1.0:abc1234567890def');
    expect(s).not.toBeNull();
    expect(Buffer.from(s!.sessionKey).equals(Buffer.from(key))).toBe(true);
  });

  it('rejects replayed inbound seq', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    const s = sk.get('mcp:1.0.0:0000000000000000')!;
    expect(accept(s, 1)).toBe(true);
    expect(accept(s, 1)).toBe(false);
  });

  it('rejects out-of-order inbound seq', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    const s = sk.get('mcp:1.0.0:0000000000000000')!;
    expect(accept(s, 5)).toBe(true);
    expect(accept(s, 3)).toBe(false);
  });

  it('asking about an inbound seq does not advance the counter', () => {
    // The property the split exists for: a frame that fails to authenticate
    // is asked about and then dropped, and the genuine frames behind it —
    // carrying LOWER seqs — must still be accepted.
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    const s = sk.get('mcp:1.0.0:0000000000000000')!;
    expect(s.isFreshInboundSeq(9)).toBe(true);
    expect(s.isFreshInboundSeq(9)).toBe(true);
    expect(accept(s, 1)).toBe(true);
    expect(accept(s, 1)).toBe(false);
  });

  it('committing never moves the counter backwards', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    const s = sk.get('mcp:1.0.0:0000000000000000')!;
    s.commitInboundSeq(5);
    s.commitInboundSeq(2);
    expect(s.isFreshInboundSeq(5)).toBe(false);
    expect(s.isFreshInboundSeq(6)).toBe(true);
  });

  it('issues monotonic outbound seq', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    const s = sk.get('mcp:1.0.0:0000000000000000')!;
    expect(s.nextOutboundSeq()).toBe(1);
    expect(s.nextOutboundSeq()).toBe(2);
    expect(s.nextOutboundSeq()).toBe(3);
  });

  it('different mcpIds have independent seq counters', () => {
    const sk = new SessionKeys();
    sk.set('a:1.0.0:0000000000000000', new Uint8Array(32));
    sk.set('b:1.0.0:0000000000000000', new Uint8Array(32));
    const a = sk.get('a:1.0.0:0000000000000000')!;
    const b = sk.get('b:1.0.0:0000000000000000')!;
    expect(a.nextOutboundSeq()).toBe(1);
    expect(b.nextOutboundSeq()).toBe(1);
    expect(accept(a, 1)).toBe(true);
    expect(accept(b, 1)).toBe(true);
  });

  it('removes a session', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    sk.remove('mcp:1.0.0:0000000000000000');
    expect(sk.get('mcp:1.0.0:0000000000000000')).toBeNull();
  });

  it('clear removes all sessions', () => {
    const sk = new SessionKeys();
    sk.set('a:1.0.0:0000000000000000', new Uint8Array(32));
    sk.set('b:1.0.0:0000000000000000', new Uint8Array(32));
    sk.clear();
    expect(sk.get('a:1.0.0:0000000000000000')).toBeNull();
    expect(sk.get('b:1.0.0:0000000000000000')).toBeNull();
  });

  it('set overwrites an existing session with fresh counters', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32).fill(1));
    const first = sk.get('mcp:1.0.0:0000000000000000')!;
    first.nextOutboundSeq();
    first.nextOutboundSeq();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32).fill(2));
    const second = sk.get('mcp:1.0.0:0000000000000000')!;
    expect(second.nextOutboundSeq()).toBe(1);  // fresh counter
  });
});
