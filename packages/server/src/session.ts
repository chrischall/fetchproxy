/**
 * Per-MCP-↔-extension session state on the server side.
 *
 * Holds the derived AES-256-GCM session key and per-direction sequence
 * counters. Outbound seq is monotonic (1, 2, 3, …). Inbound seq must be
 * strictly increasing — anything ≤ the last accepted seq is treated as
 * replay and rejected.
 *
 * Frames are not stored here — this is just the lightweight per-session
 * gate state.
 */
export class SessionState {
  public readonly sessionKey: Uint8Array;
  private outboundSeq = 0;
  private lastInboundSeq = 0;

  constructor(sessionKey: Uint8Array) {
    this.sessionKey = sessionKey;
  }

  nextOutboundSeq(): number {
    this.outboundSeq += 1;
    return this.outboundSeq;
  }

  acceptInboundSeq(seq: number): boolean {
    if (seq <= this.lastInboundSeq) return false;
    this.lastInboundSeq = seq;
    return true;
  }
}
