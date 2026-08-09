/**
 * Remote bridge targets — the configured `wss://` relays this extension dials
 * IN ADDITION TO `ws://127.0.0.1:37149`.
 *
 * Until now the extension had exactly one place to connect: the loopback
 * concentrator, which can only be a process on the user's own machine. That is
 * the whole of fetchproxy's stated trust model, and it is why the extension
 * never had to ask which bridge it was talking to. A remote target is the one
 * change that makes the question meaningful, so this module exists to make the
 * answer a decision rather than a default:
 *
 * - **the loopback link is not configurable and cannot be removed.** Remote
 *   targets are additional. Nothing here can redirect the local bridge;
 * - **a remote target must be `wss://`** unless it names a loopback host, so a
 *   pair code, a hello and an `mcpId` are not readable by anything between the
 *   browser and the relay. The frames themselves are already sealed under a
 *   per-MCP key the relay never has — the handshake around them is not;
 * - **credentials in the URL are refused.** A target is a URL plus a token
 *   HELD SEPARATELY, because the URL is the part that gets pasted into chats
 *   and screenshots;
 * - **the token has to survive being a WebSocket subprotocol.** A service
 *   worker cannot set a request header, so the credential travels in
 *   `Sec-WebSocket-Protocol`, whose grammar is narrower than base64. A token
 *   that would make `new WebSocket(...)` throw is refused at save time, where
 *   the user can still see why, rather than at connect time inside a retry
 *   loop.
 *
 * Everything here is pure: no chrome APIs, no sockets. `background/links.ts`
 * turns these records into connections.
 */

/** Storage key holding the configured remote targets (an array of records). */
export const REMOTE_TARGETS_KEY = 'remoteBridges';

/** The subprotocol that names this wire contract to the relay. */
export const BRIDGE_SUBPROTOCOL = 'fetchproxy.bridge.v1';

/** Prefix under which the credential travels as a second subprotocol. */
export const BRIDGE_TOKEN_SUBPROTOCOL_PREFIX = 'fetchproxy.token.';

/**
 * How many remote targets may be configured at once. Not a security bound —
 * a cap so a corrupted or hostile storage write cannot turn boot into an
 * unbounded fan-out of reconnecting sockets.
 */
export const MAX_REMOTE_TARGETS = 4;

export interface RemoteTarget {
  /** Stable id, used as the link id and as the storage identity of the row. */
  id: string;
  /** `wss://host/path` (or `ws://` for a loopback host). */
  url: string;
  /** Bearer credential for the relay; travels as a WebSocket subprotocol. */
  token: string;
  /** Optional human label for the popup. */
  label?: string;
  /** A disabled target is remembered but never dialled. */
  enabled: boolean;
}

export type Validation = { ok: true } | { ok: false; reason: string };

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);

/**
 * RFC 6455 subprotocol values are RFC 7230 tokens. `=` is NOT a token
 * character, which rules out padded base64 — device tokens are minted
 * unpadded base64url for exactly this reason, but a hand-typed one might not
 * be.
 */
const TOKEN_CHARS = /^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/;

export function validateRemoteTargetUrl(raw: string): Validation {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return { ok: false, reason: 'not a URL' };
  }
  if (url.username !== '' || url.password !== '') {
    return { ok: false, reason: 'credentials in the URL are not allowed — use the token field' };
  }
  if (url.hash !== '') return { ok: false, reason: 'a fragment is not allowed' };
  if (url.protocol === 'wss:') return { ok: true };
  if (url.protocol === 'ws:') {
    return LOOPBACK_HOSTS.has(url.hostname)
      ? { ok: true }
      : { ok: false, reason: 'ws:// is allowed only for a loopback host — use wss://' };
  }
  return { ok: false, reason: `unsupported scheme ${url.protocol} — use wss://` };
}

export function validateRemoteTargetToken(token: string): Validation {
  if (token === '') return { ok: false, reason: 'a token is required' };
  if (!TOKEN_CHARS.test(token)) {
    return {
      ok: false,
      reason:
        'the token travels as a WebSocket subprotocol, so it may not contain spaces, "=", "/" or ","',
    };
  }
  return { ok: true };
}

/** The subprotocol list to open a remote link with. */
export function bridgeSubprotocols(token: string): string[] {
  return [BRIDGE_SUBPROTOCOL, `${BRIDGE_TOKEN_SUBPROTOCOL_PREFIX}${token}`];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Read the stored targets into a list this extension will actually dial.
 *
 * Total: anything malformed is DROPPED rather than throwing or being
 * repaired into something dialable. Storage is written by the popup, but it is
 * also writable by anything else with access to it, and boot has to survive
 * whatever it finds there — a target it cannot validate is a target it must
 * not connect to.
 */
export function normaliseRemoteTargets(stored: unknown): RemoteTarget[] {
  const rows = Array.isArray(stored) ? stored : [];
  const out: RemoteTarget[] = [];
  const seenIds = new Set<string>();
  const seenUrls = new Set<string>();
  for (const row of rows) {
    if (out.length >= MAX_REMOTE_TARGETS) break;
    if (!isRecord(row)) continue;
    const { id, url, token, label, enabled } = row;
    if (typeof id !== 'string' || id === '') continue;
    if (typeof url !== 'string' || !validateRemoteTargetUrl(url).ok) continue;
    if (typeof token !== 'string' || !validateRemoteTargetToken(token).ok) continue;
    if (seenIds.has(id) || seenUrls.has(url)) continue;
    seenIds.add(id);
    seenUrls.add(url);
    out.push({
      id,
      url,
      token,
      ...(typeof label === 'string' && label !== '' ? { label } : {}),
      // Absent means enabled: a row written by an older popup has no flag, and
      // refusing to dial it would look like the target had been lost.
      enabled: enabled === undefined ? true : enabled === true,
    });
  }
  return out;
}

/** What the popup shows for a target — never the token. */
export function remoteTargetDisplay(t: RemoteTarget): string {
  return t.label && t.label !== '' ? `${t.label} (${t.url})` : t.url;
}
