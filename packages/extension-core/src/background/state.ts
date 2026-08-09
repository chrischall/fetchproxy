/**
 * The background service worker's reassignable module state, moved out of
 * `background.ts` into one exported holder object.
 *
 * This is a holder rather than six exported `let`s because ESM import
 * bindings are immutable for the importer: `boot()` assigns `trust`,
 * `sessions` and `extIdentity`, and `connect()` assigns `ws`,
 * `reconnectAttempt` and `currentExtSessionNonce`. Writing to an imported
 * `let` is a compile error, so the writers and readers share this object
 * instead.
 *
 * Read `state.X` at the point of use — several call sites deliberately
 * re-read after an `await` so a mid-handshake reconnect is observed
 * (e.g. the ready-frame nonce and the socket it is sent on).
 */

import type { TrustStore } from '../trust-store.js';
import type { SessionKeys } from '../session-keys.js';
import type { ExtensionIdentity } from '../extension-identity.js';

export interface BackgroundState {
  ws: WebSocket | null;
  reconnectAttempt: number;
  trust: TrustStore | null;
  sessions: SessionKeys | null;
  // 0.4.0+: the extension's long-term identity. Loaded once on boot via
  // `loadOrCreateExtensionIdentity`, then threaded into every hello +
  // every ready-frame signature. Generated on first run, persisted in
  // chrome.storage.local across MV3 service-worker restarts.
  extIdentity: ExtensionIdentity | null;
  // 0.4.0+: per-WS-connection nonce the extension sends in its hello.
  // The MCP host's session signature on the corresponding ReadyFrame
  // commits to (mcpNonce || extNonce), so a relay can neither replay
  // nor substitute a different identity without producing a visibly
  // different pair code.
  currentExtSessionNonce: Uint8Array | null;
}

export const state: BackgroundState = {
  ws: null,
  reconnectAttempt: 0,
  trust: null,
  sessions: null,
  extIdentity: null,
  currentExtSessionNonce: null,
};
