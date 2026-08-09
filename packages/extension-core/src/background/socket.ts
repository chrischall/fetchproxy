/**
 * The host WebSocket transport, moved verbatim out of `background.ts`:
 * `connect`, `scheduleReconnect`, `onMessage` and `onEncryptedFrame`.
 *
 * Only `connect` is exported — the other three were file-private in
 * `background.ts` and stay module-private here, so the visibility surface is
 * unchanged. The `connect` ⇄ `scheduleReconnect` mutual recursion is
 * therefore entirely intra-module.
 *
 * `connect` is handed to `startKeepalive` as `ensureConnected` and re-invoked
 * on every alarm tick, so its identity and its idempotence both matter: the
 * `readyState` short-circuit is what turns a tick into a no-op while the
 * socket is healthy. Do not wrap it or give it parameters.
 *
 * The `extIdentity` check appears twice on purpose — once before opening the
 * socket and again inside the `open` callback — because the callback can fire
 * before the async identity assignment on boot completes.
 *
 * Frames route DOWN from here: `onEncryptedFrame` → `handlers/dispatch.ts`,
 * and the handlers reply through `send-inner.ts` rather than back through
 * this module, which is what keeps the transport out of a cycle.
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

import { state } from './state.js';
import { setConnectionStatus, flashActivity } from './badge.js';
import { sendInner } from './send-inner.js';
import { onServerHello } from './server-hello.js';
import { handleRequest } from './handlers/dispatch.js';
import { broadcastConnectionsChanged, clearAllSessionScopes } from './session-scope.js';

declare const chrome: ChromeApi;

const HOST_PORT = 37149;
const HOST_URL = `ws://127.0.0.1:${HOST_PORT}`;
const RECONNECT_BACKOFF_MS = [500, 1000, 2000, 5000, 10_000];

export function connect(): void {
  if (!state.trust || !state.sessions || !state.extIdentity) return;
  if (state.ws && (state.ws.readyState === WebSocket.CONNECTING || state.ws.readyState === WebSocket.OPEN)) return;
  state.ws = new WebSocket(HOST_URL);
  state.ws.addEventListener('open', () => {
    if (!state.extIdentity) return;
    state.reconnectAttempt = 0;
    setConnectionStatus('connected');
    // Fresh per-WS nonce. The corresponding ready-frame signature
    // commits to (mcpHelloNonce || this nonce), so each WS connect
    // gets a fresh handshake — replaying a captured ready frame
    // against a future connection fails.
    const sessionNonce = new Uint8Array(32);
    (globalThis.crypto as Crypto).getRandomValues(sessionNonce);
    state.currentExtSessionNonce = sessionNonce;
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
    state.ws!.send(JSON.stringify(extHello));
  });
  state.ws.addEventListener('message', (ev: MessageEvent) => {
    void onMessage(ev.data as string).catch((e) => console.error('[fetchproxy] onMessage:', e));
  });
  state.ws.addEventListener('close', () => {
    setConnectionStatus('disconnected');
    state.sessions?.clear();
    clearAllSessionScopes();
    broadcastConnectionsChanged();
    scheduleReconnect();
  });
  state.ws.addEventListener('error', () => {
    /* close will follow */
  });
}

function scheduleReconnect(): void {
  const ms = RECONNECT_BACKOFF_MS[Math.min(state.reconnectAttempt, RECONNECT_BACKOFF_MS.length - 1)]!;
  state.reconnectAttempt++;
  setTimeout(connect, ms);
}

async function onMessage(data: string): Promise<void> {
  if (!state.trust) return;
  let frame: Frame;
  try {
    frame = validateFrame(JSON.parse(data));
  } catch (e) {
    console.warn('[fetchproxy] dropped malformed frame:', e);
    return;
  }
  if (frame.type === 'hello' && frame.role === 'server') {
    await onServerHello(frame);
  } else if (frame.type === 'frame') {
    await onEncryptedFrame(frame);
  }
  // ready frames from the host shouldn't reach us; ignore.
}

async function onEncryptedFrame(frame: EncryptedFrame): Promise<void> {
  if (!state.sessions) return;
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
