/**
 * Per-mcpId session state on the extension side. Stores the AES-256-GCM
 * session key plus monotonic outbound seq and replay-rejecting inbound seq.
 *
 * Mirrors packages/server/src/session.ts on the MCP side, including the
 * two-call inbound gate: `claimInboundSeq` before the AES-GCM open, then
 * `commitInboundSeq` once it has authenticated or `releaseInboundSeq` when it
 * has not, so a frame that never authenticated cannot move the counter past
 * the genuine ones behind it.
 *
 * The claim is SYNCHRONOUS and single-shot for the reason session.ts sets out
 * at length: a question that changes nothing is answered "yes" twice when two
 * identical frames arrive in one read, and there is an `await` between the
 * question and the answer for the second frame to slip through. It matters
 * more here than anywhere — the extension is the RESPONDER, so a duplicate
 * that gets past the gate is not a wedge but a second EXECUTION of a
 * `write_cookies` or a non-GET `fetch`: `handlers/dispatch.ts` has no per-id
 * guard of its own, and this gate is where one belongs.
 *
 * Kept in memory only — no chrome.storage persistence — because session keys
 * are derived fresh each WS connection from the MCP's sessionNonce.
 */

/**
 * How many inbound seqs may be claimed but not yet resolved at one time.
 * See the same constant in packages/server/src/session.ts — the set is
 * self-draining, and this is the bound that keeps a flood of frames that
 * never open from turning it into a leak.
 */
const MAX_INFLIGHT_INBOUND_SEQS = 1024;

/**
 * What {@link SessionEntry.claimInboundSeq} decided — the same three verdicts
 * as `InboundClaim` in packages/server/src/session.ts. `'saturated'` is logged
 * by the caller, since otherwise a flood is indistinguishable from a replay.
 */
export type InboundClaim = 'ok' | 'replay' | 'saturated';

export class SessionEntry {
  public readonly sessionKey: Uint8Array;
  private outbound = 0;
  private lastInbound = 0;
  private inflightInbound = new Set<number>();
  private saturationWarned = false;

  constructor(sessionKey: Uint8Array) {
    this.sessionKey = sessionKey;
  }

  /**
   * Whether the caller holding this claim verdict should log saturation now —
   * true only on the transition into it, re-armed by the next `'ok'` claim.
   * The same latch as `saturationWarningDue` in packages/server/src/session.ts
   * (#376), which says why.
   */
  saturationWarningDue(claim: InboundClaim): boolean {
    if (claim === 'ok') this.saturationWarned = false;
    if (claim !== 'saturated' || this.saturationWarned) return false;
    this.saturationWarned = true;
    return true;
  }

  nextOutboundSeq(): number {
    this.outbound += 1;
    return this.outbound;
  }

  /**
   * Take this seq out of circulation for the frame about to be opened, and
   * say whether it was available. Call before the first `await` of the
   * receive path. Replay is checked before the bound, as on the MCP side.
   * Every `'ok'` MUST be answered by exactly one {@link commitInboundSeq} or
   * {@link releaseInboundSeq}.
   */
  claimInboundSeq(seq: number): InboundClaim {
    if (seq <= this.lastInbound) return 'replay';
    if (this.inflightInbound.has(seq)) return 'replay';
    if (this.inflightInbound.size >= MAX_INFLIGHT_INBOUND_SEQS) return 'saturated';
    this.inflightInbound.add(seq);
    return 'ok';
  }

  /**
   * Give a claim back without spending the seq — for a frame that did not
   * authenticate, which is a frame that never happened. Idempotent.
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
    if (seq > this.lastInbound) this.lastInbound = seq;
  }
}

export class SessionKeys {
  private map = new Map<string, SessionEntry>();

  get(mcpId: string): SessionEntry | null {
    return this.map.get(mcpId) ?? null;
  }

  set(mcpId: string, sessionKey: Uint8Array): SessionEntry {
    const e = new SessionEntry(sessionKey);
    this.map.set(mcpId, e);
    return e;
  }

  remove(mcpId: string): void {
    this.map.delete(mcpId);
  }

  clear(): void {
    this.map.clear();
  }
}
