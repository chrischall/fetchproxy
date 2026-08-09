/**
 * One extension, N bridges.
 *
 * Until a remote target existed the extension had exactly one socket, so
 * "which bridge does this `mcpId` belong to?" had one answer and nobody had to
 * ask it. With a loopback link and zero-or-more remote links, the question is
 * real and getting it wrong is not a routing bug — it is a disclosure. An
 * `mcpId` is `<serverName>:<version>:<16-hex>`, minted by the MCP, so it is
 * NOT a name this extension can trust to be unique across bridges.
 *
 * Two rules follow, and they are the whole of this module:
 *
 * 1. **A binding is only ever created from a hello that ARRIVED on that
 *    link.** Nothing may bind an `mcpId` to a link because a frame said so.
 * 2. **The first live binding wins.** A second link presenting an `mcpId`
 *    already bound to a live link is refused, not re-pointed — otherwise a
 *    relay could claim an id it saw and have this extension answer its
 *    requests, or send another bridge's MCP a response.
 *
 * Session teardown is per link for the same reason a reconnect tears down
 * today: the extension's hello nonce is per connection, and every session
 * derived under it dies with it. One link dropping must not clear another's
 * sessions.
 */

import type { RemoteTarget } from '../remote-targets.js';

export const LOCAL_LINK_ID = 'local';

export interface Link {
  /** `'local'`, or `remote:<target id>`. Also the popup's identity for it. */
  readonly id: string;
  readonly kind: 'local' | 'remote';
  readonly url: string;
  /** Subprotocols to open with — the credential, for a remote link. */
  readonly protocols: string[];
  /** Human label for diagnostics; the URL for a remote link. */
  readonly label: string;
  ws: WebSocket | null;
  reconnectAttempt: number;
  /**
   * Epoch ms before which this link must not be dialled again.
   *
   * The backoff cannot live in a timer alone: the keepalive alarm calls
   * `connect()` every 24 s to survive service-worker eviction, and that would
   * re-dial a dead remote target on every tick no matter what the backoff
   * table said. This is what makes a bridge that is down stay cheap.
   */
  nextAttemptAt: number;
  /**
   * The per-connection nonce sent in THIS link's extension hello. The ready
   * signature commits to it, so it must be read from the link a hello arrived
   * on and never from a global — signing with another link's nonce produces a
   * signature the MCP correctly rejects.
   */
  sessionNonce: Uint8Array | null;
  /** True once this link has been removed from the registry; stops reconnects. */
  closed: boolean;
}

/** Every link this extension currently intends to hold open, by link id. */
export const links = new Map<string, Link>();

/** Which link each live `mcpId` arrived on. Written only by the hello path. */
const mcpLink = new Map<string, Link>();

export function localLink(): Link {
  return {
    id: LOCAL_LINK_ID,
    kind: 'local',
    url: 'ws://127.0.0.1:37149',
    protocols: [],
    label: 'localhost',
    ws: null,
    reconnectAttempt: 0,
    nextAttemptAt: 0,
    sessionNonce: null,
    closed: false,
  };
}

export function remoteLink(target: RemoteTarget, protocols: string[]): Link {
  return {
    id: `remote:${target.id}`,
    kind: 'remote',
    url: target.url,
    protocols,
    label: target.label && target.label !== '' ? target.label : target.url,
    ws: null,
    reconnectAttempt: 0,
    nextAttemptAt: 0,
    sessionNonce: null,
    closed: false,
  };
}

/** The link an `mcpId` is bound to, or `null` if it is bound to none. */
export function linkForMcp(mcpId: string): Link | null {
  return mcpLink.get(mcpId) ?? null;
}

/**
 * Bind an `mcpId` to the link its hello arrived on.
 *
 * Returns false when the id is already bound to a DIFFERENT link, which is
 * the cross-bridge case rule 2 above refuses. Re-binding to the same link is
 * fine and idempotent: an MCP re-handshakes on every reconnect.
 */
export function bindMcpToLink(mcpId: string, link: Link): boolean {
  const existing = mcpLink.get(mcpId);
  if (existing && existing !== link) return false;
  mcpLink.set(mcpId, link);
  return true;
}

/** Every `mcpId` currently bound to `link`. */
export function mcpIdsForLink(link: Link): string[] {
  const out: string[] = [];
  for (const [mcpId, l] of mcpLink) if (l === link) out.push(mcpId);
  return out;
}

/** Drop every binding held by `link`. Returns the ids that were dropped. */
export function unbindLink(link: Link): string[] {
  const dropped = mcpIdsForLink(link);
  for (const mcpId of dropped) mcpLink.delete(mcpId);
  return dropped;
}

/** Drop every binding, on every link. */
export function unbindAll(): void {
  mcpLink.clear();
}

/** True while at least one link has an open socket. */
export function anyLinkOpen(): boolean {
  for (const link of links.values()) {
    if (link.ws && link.ws.readyState === WebSocket.OPEN) return true;
  }
  return false;
}

/** Send on a link, if it is open. Returns whether the frame went out. */
export function sendOnLink(link: Link, payload: string): boolean {
  if (!link.ws || link.ws.readyState !== WebSocket.OPEN) return false;
  link.ws.send(payload);
  return true;
}
