/**
 * The bridge transport: the loopback link, plus zero-or-more configured
 * remote links, held open together.
 *
 * Before remote targets this module held ONE socket in `state.ws` and one
 * per-connection nonce in `state.currentExtSessionNonce`. Both are now
 * per-link (`links.ts`), and that is the substance of the change rather than
 * a refactor: the ready signature commits to the nonce of the connection its
 * hello arrived on, so a global nonce would sign one link's ready with
 * another link's handshake and the MCP would correctly reject it.
 *
 * What did NOT change, and must not:
 *
 * - **`connect` is still the keepalive's `ensureConnected`** — no parameters,
 *   idempotent, safe to call on every alarm tick. It now ensures EVERY link
 *   rather than one, and the `readyState` short-circuit still turns a tick
 *   into a no-op per link.
 * - **the loopback link is unconditional.** Remote targets are additional; no
 *   configuration removes or redirects `ws://127.0.0.1:37149`.
 * - **frames route DOWN** — `onEncryptedFrame` → `handlers/dispatch.ts`, and
 *   handlers reply through `send-inner.ts` rather than back through here.
 *
 * The one new refusal: a frame is dropped unless its `mcpId` is bound to the
 * link it arrived on. Decryption would fail anyway (the session key is
 * per-MCP and this extension holds a different one for the other link's
 * session), but "the id is not yours" is a routing answer and belongs before
 * the crypto rather than behind it.
 */

import {
  openEncryptedFrame,
  validateFrame,
  toB64,
  PROTOCOL_VERSION,
  type Frame,
  type HelloFrameFromExtension,
  type InnerFrame,
  type EncryptedFrame,
} from '@fetchproxy/protocol';

import type { ChromeApi } from '../chrome-api.js';
import {
  REMOTE_TARGETS_KEY,
  bridgeSubprotocols,
  normaliseRemoteTargets,
  type RemoteTarget,
} from '../remote-targets.js';

import { state } from './state.js';
import { setConnectionStatus, flashActivity } from './badge.js';
import { sendInner } from './send-inner.js';
import { onServerHello } from './server-hello.js';
import { handleRequest } from './handlers/dispatch.js';
import { broadcastConnectionsChanged, clearSessionScopeFor } from './session-scope.js';
import {
  LOCAL_LINK_ID,
  anyLinkOpen,
  linkForMcp,
  links,
  localLink,
  remoteLink,
  unbindLink,
  type Link,
} from './links.js';

declare const chrome: ChromeApi;

const RECONNECT_BACKOFF_MS = [500, 1000, 2000, 5000, 10_000];
/**
 * A remote link backs off further than the loopback one. Loopback failure
 * means "the MCP is not running yet" and is expected to clear in seconds; a
 * remote failure means a WAN round-trip to something that may be down,
 * revoked or unreachable, and retrying that every ten seconds forever is a
 * service worker that never idles.
 */
const REMOTE_RECONNECT_BACKOFF_MS = [1000, 2000, 5000, 15_000, 30_000, 60_000];

/** Ensure the loopback link exists. Called before every connect sweep. */
function ensureLocalLink(): Link {
  const existing = links.get(LOCAL_LINK_ID);
  if (existing) return existing;
  const link = localLink();
  links.set(link.id, link);
  return link;
}

/**
 * Bring the live link set in line with the configured remote targets.
 *
 * Called at boot and on every storage change. Targets that vanished (or were
 * disabled) are torn down here rather than left dangling: a target the user
 * removed must stop being dialled, and its sessions must go with it.
 */
export function reconcileRemoteLinks(targets: RemoteTarget[]): void {
  const wanted = new Map<string, RemoteTarget>();
  for (const t of targets) {
    if (t.enabled) wanted.set(`remote:${t.id}`, t);
  }
  for (const link of [...links.values()]) {
    if (link.kind !== 'remote') continue;
    const target = wanted.get(link.id);
    // A URL or credential change is a different bridge, not the same one with
    // new details: drop the link so the new one handshakes from scratch. The
    // credential counts because a rotated token means the old socket is
    // authenticated as something the user has stopped meaning.
    const sameCredential =
      target !== undefined &&
      bridgeSubprotocols(target.token).join(',') === link.protocols.join(',');
    if (!target || target.url !== link.url || !sameCredential) removeLink(link);
  }
  for (const [id, target] of wanted) {
    if (links.has(id)) continue;
    links.set(id, remoteLink(target, bridgeSubprotocols(target.token)));
  }
  connect();
}

/** Read the configured targets from storage and reconcile onto them. */
export async function loadRemoteLinks(): Promise<void> {
  try {
    const got = await chrome.storage.local.get(REMOTE_TARGETS_KEY);
    reconcileRemoteLinks(normaliseRemoteTargets(got[REMOTE_TARGETS_KEY]));
  } catch (e) {
    console.error('[fetchproxy] could not read remote bridge targets:', e);
  }
}

function removeLink(link: Link): void {
  link.closed = true;
  links.delete(link.id);
  teardownLink(link);
  try {
    link.ws?.close();
  } catch {
    /* already gone */
  }
  link.ws = null;
}

/**
 * Drop everything derived from one link's current connection: its sessions,
 * their scope grants, and their bindings. Sessions on other links are
 * deliberately untouched — this is the whole reason teardown became per-link.
 */
function teardownLink(link: Link): void {
  const dropped = unbindLink(link);
  for (const mcpId of dropped) {
    state.sessions?.remove(mcpId);
    clearSessionScopeFor(mcpId);
  }
  link.sessionNonce = null;
  if (dropped.length > 0) broadcastConnectionsChanged();
}

/**
 * Idempotent connect for every link. This is the keepalive's
 * `ensureConnected` — do not wrap it or give it parameters.
 */
export function connect(): void {
  if (!state.trust || !state.sessions || !state.extIdentity) return;
  ensureLocalLink();
  for (const link of links.values()) connectLink(link);
}

function connectLink(link: Link): void {
  if (link.closed) return;
  if (!state.trust || !state.sessions || !state.extIdentity) return;
  if (Date.now() < link.nextAttemptAt) return;
  if (link.ws && (link.ws.readyState === WebSocket.CONNECTING || link.ws.readyState === WebSocket.OPEN)) {
    return;
  }
  let ws: WebSocket;
  try {
    ws = link.protocols.length > 0 ? new WebSocket(link.url, link.protocols) : new WebSocket(link.url);
  } catch (e) {
    // A malformed URL or subprotocol throws synchronously. There is no socket
    // to hang a close handler on, so schedule the retry here — the target may
    // be repaired in storage while this link keeps failing.
    console.error(`[fetchproxy] could not open ${link.label}:`, e);
    scheduleReconnect(link);
    return;
  }
  link.ws = ws;
  ws.addEventListener('open', () => {
    if (!state.extIdentity || link.closed) return;
    link.reconnectAttempt = 0;
    link.nextAttemptAt = 0;
    setConnectionStatus('connected');
    // Fresh per-LINK, per-connection nonce. The corresponding ready-frame
    // signature commits to (mcpHelloNonce || this nonce || the ephemeral pub),
    // so each connection on each link gets a fresh handshake — replaying a
    // captured ready frame against a future connection, or against the other
    // link, fails.
    const sessionNonce = new Uint8Array(32);
    (globalThis.crypto as Crypto).getRandomValues(sessionNonce);
    link.sessionNonce = sessionNonce;
    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: PROTOCOL_VERSION,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: chrome.runtime.getManifest().version,
      identityX25519Pub: toB64(state.extIdentity.x25519Pub),
      identityEd25519Pub: toB64(state.extIdentity.ed25519Pub),
      sessionNonce: toB64(sessionNonce),
    };
    ws.send(JSON.stringify(extHello));
  });
  ws.addEventListener('message', (ev: MessageEvent) => {
    void onMessage(link, ev.data as string).catch((e) =>
      console.error('[fetchproxy] onMessage:', e),
    );
  });
  ws.addEventListener('close', (ev: CloseEvent) => {
    teardownLink(link);
    if (!anyLinkOpen()) setConnectionStatus('disconnected');
    // 1008 on a remote link is the relay refusing this browser — a revoked or
    // wrong credential, or another browser already holding the account's
    // bridge. Say so once per close rather than letting it read as a network
    // blip in the retry log.
    if (link.kind === 'remote' && ev?.code === 1008) {
      console.warn(`[fetchproxy] ${link.label} refused this browser: ${ev.reason || 'no reason given'}`);
    }
    scheduleReconnect(link);
  });
  ws.addEventListener('error', () => {
    /* close will follow */
  });
}

function scheduleReconnect(link: Link): void {
  if (link.closed) return;
  const table = link.kind === 'remote' ? REMOTE_RECONNECT_BACKOFF_MS : RECONNECT_BACKOFF_MS;
  const ms = table[Math.min(link.reconnectAttempt, table.length - 1)]!;
  link.reconnectAttempt++;
  link.nextAttemptAt = Date.now() + ms;
  setTimeout(() => connectLink(link), ms);
}

async function onMessage(link: Link, data: string): Promise<void> {
  if (!state.trust) return;
  if (link.closed) return;
  let frame: Frame;
  try {
    frame = validateFrame(JSON.parse(data));
  } catch (e) {
    console.warn('[fetchproxy] dropped malformed frame:', e);
    return;
  }
  if (frame.type === 'hello' && frame.role === 'server') {
    await onServerHello(link, frame);
  } else if (frame.type === 'frame') {
    await onEncryptedFrame(link, frame);
  }
  // ready frames from the host shouldn't reach us; ignore.
}

async function onEncryptedFrame(link: Link, frame: EncryptedFrame): Promise<void> {
  if (!state.sessions) return;
  // Routing before crypto: an mcpId bound to another link is not this link's
  // to speak for, whatever it can or cannot decrypt.
  if (linkForMcp(frame.mcpId) !== link) return;
  const entry = state.sessions.get(frame.mcpId);
  if (!entry) return;
  if (!entry.acceptInboundSeq(frame.seq)) return;
  flashActivity();
  let inner: InnerFrame;
  try {
    inner = await openEncryptedFrame(entry.sessionKey, frame);
  } catch (e) {
    console.warn('[fetchproxy] decrypt failed:', e);
    return;
  }
  if (inner.type === 'ping') {
    await sendInner(frame.mcpId, { type: 'pong' });
  } else if (inner.type === 'request') {
    await handleRequest(frame.mcpId, inner);
  }
  // pong + response from server: ignore (we don't ping or request inward yet).
}
