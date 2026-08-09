/**
 * The background service worker's reassignable module state, moved out of
 * `background.ts` into one exported holder object.
 *
 * This is a holder rather than exported `let`s because ESM import bindings are
 * immutable for the importer: `boot()` assigns `trust`, `sessions` and
 * `extIdentity`. Writing to an imported `let` is a compile error, so the
 * writers and readers share this object instead.
 *
 * What is NOT here any more is the connection: the socket, its reconnect
 * counter and its per-connection nonce moved to `links.ts` when the extension
 * gained remote bridge targets, because there is no longer one of any of them.
 * A global nonce in particular was the shape of a bug — the ready signature
 * commits to the nonce of the connection its hello arrived on, so signing from
 * a global would sign one link's ready with another link's handshake.
 *
 * Read `state.X` at the point of use — several call sites deliberately
 * re-read after an `await` so a mid-handshake reconnect is observed.
 */

import type { TrustStore } from '../trust-store.js';
import type { SessionKeys } from '../session-keys.js';
import type { ExtensionIdentity } from '../extension-identity.js';

export interface BackgroundState {
  trust: TrustStore | null;
  sessions: SessionKeys | null;
  // 0.4.0+: the extension's long-term identity. Loaded once on boot via
  // `loadOrCreateExtensionIdentity`, then threaded into every hello +
  // every ready-frame signature. Generated on first run, persisted in
  // chrome.storage.local across MV3 service-worker restarts.
  extIdentity: ExtensionIdentity | null;
}

export const state: BackgroundState = {
  trust: null,
  sessions: null,
  extIdentity: null,
};
