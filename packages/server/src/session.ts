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
 * authenticated: {@link claimInboundSeq} before the AES-GCM open, then
 * {@link commitInboundSeq} once it has (or {@link releaseInboundSeq} when it
 * has not). Advancing on the way in meant anything that could put bytes on
 * the socket could name a seq and have every genuine frame behind it — all
 * carrying lower numbers — dropped as replays, without ever holding the
 * session key.
 *
 * The claim is what makes the split safe. A bare "is it fresh?" question
 * changes nothing, so two identical frames arriving in ONE read both got
 * their yes before either could commit — and an `await` sits between the two
 * calls, so that is deterministic rather than lucky. The claim therefore
 * happens SYNCHRONOUSLY, before any await: the first frame takes the seq out
 * of circulation the instant it is read, and the duplicate behind it is
 * refused as a replay exactly as one arriving a second later would be. A
 * released claim leaves the counter untouched, so a frame that never
 * authenticated still costs its sender nothing and blocks nobody.
 *
 * Frames are not stored here — this is just the lightweight per-session
 * gate state.
 */

/**
 * How many inbound seqs may be claimed but not yet resolved at one time.
 *
 * Every claim is released or committed by the caller that made it, so the set
 * is self-draining and this bound is never approached by real traffic — one
 * AES-GCM open per claim, and a bridge's concurrency is its pending verbs. It
 * exists so a flood of frames that are never opened cannot make the set the
 * memory leak the counter never was: past it, a claim is refused and the
 * frame is dropped unread. Nothing is committed by that refusal, so a genuine
 * frame at the same seq is accepted once the flood drains.
 */
const MAX_INFLIGHT_INBOUND_SEQS = 1024;

export class SessionState {
  public readonly sessionKey: Uint8Array;
  private outboundSeq = 0;
  private lastInboundSeq = 0;
  private inflightInbound = new Set<number>();

  constructor(sessionKey: Uint8Array) {
    this.sessionKey = sessionKey;
  }

  nextOutboundSeq(): number {
    this.outboundSeq += 1;
    return this.outboundSeq;
  }

  /**
   * Take this seq out of circulation for the frame about to be opened, and
   * say whether it was available. SYNCHRONOUS and single-shot: call it before
   * the first `await` of the receive path, or a duplicate frame read in the
   * same pass will be judged against a counter neither frame has moved yet.
   *
   * Answering false means "not this frame's to process" — replayed, or a
   * duplicate of one still in flight. Every true MUST be answered by exactly
   * one {@link commitInboundSeq} or {@link releaseInboundSeq}.
   */
  claimInboundSeq(seq: number): boolean {
    if (seq <= this.lastInboundSeq) return false;
    if (this.inflightInbound.has(seq)) return false;
    if (this.inflightInbound.size >= MAX_INFLIGHT_INBOUND_SEQS) return false;
    this.inflightInbound.add(seq);
    return true;
  }

  /**
   * Give a claim back without spending the seq — for a frame that did not
   * authenticate, which is a frame that never happened. The counter does not
   * move, so the genuine frames behind it, carrying lower numbers, are still
   * accepted. Idempotent, so a caller may release in a `catch` after a commit
   * it is not sure ran.
   */
  releaseInboundSeq(seq: number): void {
    this.inflightInbound.delete(seq);
  }

  /**
   * Record a seq as spent. Call only for a frame that authenticated. Never
   * moves the counter backwards, so an out-of-order commit cannot reopen a
   * seq an earlier one already closed.
   */
  commitInboundSeq(seq: number): void {
    this.inflightInbound.delete(seq);
    if (seq > this.lastInboundSeq) this.lastInboundSeq = seq;
  }
}
