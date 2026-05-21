/**
 * Per-mcpId session state on the extension side. Stores the AES-256-GCM
 * session key plus monotonic outbound seq and replay-rejecting inbound seq.
 *
 * Mirrors packages/server/src/session.ts on the MCP side. Kept in memory
 * only — no chrome.storage persistence — because session keys are derived
 * fresh each WS connection from the MCP's sessionNonce.
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

  acceptInboundSeq(seq: number): boolean {
    if (seq <= this.lastInbound) return false;
    this.lastInbound = seq;
    return true;
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
