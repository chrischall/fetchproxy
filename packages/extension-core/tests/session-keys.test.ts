import { describe, it, expect } from 'vitest';
import { SessionKeys, type SessionEntry } from '../src/session-keys.js';

/**
 * The inbound gate as `onEncryptedFrame` now spells it: claim, open the frame,
 * commit (or release). The claim is synchronous and the commit is not, which
 * is the whole point — see `session-keys.ts`.
 */
function accept(s: SessionEntry, seq: number): boolean {
  if (!s.claimInboundSeq(seq)) return false;
  // In the real caller the AES-GCM open happens here.
  s.commitInboundSeq(seq);
  return true;
}

/** A frame that claimed its seq and then failed to authenticate. */
function refuse(s: SessionEntry, seq: number): boolean {
  if (!s.claimInboundSeq(seq)) return false;
  s.releaseInboundSeq(seq);
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

  it('a released claim does not advance the counter', () => {
    // The property the split exists for: a frame that fails to authenticate
    // gives its claim back, and the genuine frames behind it — carrying LOWER
    // seqs — must still be accepted.
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    const s = sk.get('mcp:1.0.0:0000000000000000')!;
    expect(refuse(s, 9)).toBe(true);
    expect(refuse(s, 9)).toBe(true);
    expect(accept(s, 1)).toBe(true);
    expect(accept(s, 1)).toBe(false);
  });

  it('a claim is exclusive until it is resolved', () => {
    // Two identical frames delivered in one read both reach the gate before
    // either can commit; on this side letting the second through is a second
    // EXECUTION of the request, so it has to be refused here.
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    const s = sk.get('mcp:1.0.0:0000000000000000')!;
    expect(s.claimInboundSeq(4)).toBe(true);
    expect(s.claimInboundSeq(4)).toBe(false);
    s.commitInboundSeq(4);
    expect(s.claimInboundSeq(4)).toBe(false);
    expect(refuse(s, 5)).toBe(true);
    expect(accept(s, 5)).toBe(true);
  });

  it('outstanding claims are bounded, and the bound spends no seq', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    const s = sk.get('mcp:1.0.0:0000000000000000')!;
    for (let seq = 1; seq <= 1024; seq += 1) expect(s.claimInboundSeq(seq)).toBe(true);
    expect(s.claimInboundSeq(2000)).toBe(false);
    for (let seq = 1; seq <= 1024; seq += 1) s.releaseInboundSeq(seq);
    expect(accept(s, 2000)).toBe(true);
  });

  it('committing never moves the counter backwards', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    const s = sk.get('mcp:1.0.0:0000000000000000')!;
    s.commitInboundSeq(5);
    s.commitInboundSeq(2);
    expect(s.claimInboundSeq(5)).toBe(false);
    expect(s.claimInboundSeq(6)).toBe(true);
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
