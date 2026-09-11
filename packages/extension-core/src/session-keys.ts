/**
 * Per-mcpId session state on the extension side. Stores the AES-256-GCM
 * session key plus monotonic outbound seq and replay-rejecting inbound seq.
 *
 * Mirrors packages/server/src/session.ts on the MCP side, including the
 * two-call inbound gate: ask `isFreshInboundSeq` before the AES-GCM open and
 * record `commitInboundSeq` after it succeeds, so a frame that never
 * authenticated cannot move the counter past the genuine ones behind it.
 *
 * Kept in memory only — no chrome.storage persistence — because session keys
 * are derived fresh each WS connection from the MCP's sessionNonce.
 */

export class SessionEntry {
  public readonly sessionKey: Uint8Array;
  private outbound = 0;
  private lastInbound = 0;

  constructor(sessionKey: Uint8Array) {
    this.sessionKey = sessionKey;
  }

  nextOutboundSeq(): number {
    this.outbound += 1;
    return this.outbound;
  }

  /** Would this seq be accepted right now? Asks only — changes nothing. */
  isFreshInboundSeq(seq: number): boolean {
    return seq > this.lastInbound;
  }

  /**
   * Record a seq as seen. Call only for a frame that authenticated. Never
   * moves the counter backwards, so an out-of-order commit cannot reopen a
   * seq an earlier one already closed.
   */
  commitInboundSeq(seq: number): void {
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
