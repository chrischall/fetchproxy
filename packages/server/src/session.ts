/**
 * Per-MCP-↔-extension session state on the server side.
 *
 * Holds the derived AES-256-GCM session key and per-direction sequence
 * counters. Outbound seq is monotonic (1, 2, 3, …). Inbound seq must be
 * strictly increasing — anything ≤ the last accepted seq is treated as
 * replay and rejected.
 *
 * The inbound gate is deliberately TWO calls rather than one
 * check-and-advance, because only the caller knows whether the frame
 * authenticated: ask {@link isFreshInboundSeq} before the AES-GCM open and
 * record {@link commitInboundSeq} after it succeeds. Advancing on the way in
 * meant anything that could put bytes on the socket could name a seq and have
 * every genuine frame behind it — all carrying lower numbers — dropped as
 * replays, without ever holding the session key.
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

  /** Would this seq be accepted right now? Asks only — changes nothing. */
  isFreshInboundSeq(seq: number): boolean {
    return seq > this.lastInboundSeq;
  }

  /**
   * Record a seq as seen. Call only for a frame that authenticated. Never
   * moves the counter backwards, so an out-of-order commit cannot reopen a
   * seq an earlier one already closed.
   */
  commitInboundSeq(seq: number): void {
    if (seq > this.lastInboundSeq) this.lastInboundSeq = seq;
  }
}
