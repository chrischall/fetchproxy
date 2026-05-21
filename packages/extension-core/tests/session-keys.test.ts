import { describe, it, expect } from 'vitest';
import { SessionKeys } from '../src/session-keys.js';

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
    expect(s.acceptInboundSeq(1)).toBe(true);
    expect(s.acceptInboundSeq(1)).toBe(false);
  });

  it('rejects out-of-order inbound seq', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    const s = sk.get('mcp:1.0.0:0000000000000000')!;
    expect(s.acceptInboundSeq(5)).toBe(true);
    expect(s.acceptInboundSeq(3)).toBe(false);
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
    expect(a.acceptInboundSeq(1)).toBe(true);
    expect(b.acceptInboundSeq(1)).toBe(true);
  });

  it('removes a session', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    sk.remove('mcp:1.0.0:0000000000000000');
    expect(sk.get('mcp:1.0.0:0000000000000000')).toBeNull();
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
