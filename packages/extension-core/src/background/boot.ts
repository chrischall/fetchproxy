/**
 * Service-worker boot: construct the singletons, register every listener
 * exactly once, and open the WS connection.
 *
 * `maybeBoot` self-guards on `chrome.runtime.getManifest` /
 * `chrome.storage.local.onChanged.addListener`, so importing the background
 * entry from a test (where neither is mocked) is a no-op — that guard is
 * what keeps `tests/*.test.ts` importing `../src/background.js` harmless.
 *
 * Ordering is load-bearing: `state.trust` and `state.sessions` are built
 * SYNCHRONOUSLY before any listener can fire, and `connect()` is deferred
 * until `loadOrCreateExtensionIdentity()` resolves because the extension
 * hello cannot be built without `state.extIdentity`.
 *
 * This module sits at the top of the import graph — only `../background.ts`
 * imports it — so it cannot take part in a cycle.
 */

import { TrustStore } from '../trust-store.js';
import { SessionKeys } from '../session-keys.js';
import { loadOrCreateExtensionIdentity } from '../extension-identity.js';
import { startKeepalive } from '../keepalive.js';

import type { ChromeApi } from '../chrome-api.js';

declare const chrome: ChromeApi;

import { setPairPendingBadge, clearPairPendingBadge } from './badge.js';
import type { AnyPendingRecord } from './pending-records.js';
import { state } from './state.js';
import { connect } from './socket.js';
import { connectedIdentityHashes } from './session-scope.js';
import { PENDING_PAIR_KEY, APPROVED_PAIR_KEY, mergePending } from './pending-pair-store.js';
import { onApproval, onScopeUpdateDismiss } from './approval.js';

// Boot: only run in a real MV3 service worker context. Skipped under vitest
// (no chrome.runtime.getManifest, no chrome.storage.local.onChanged).
export function maybeBoot(): void {
  const c = (globalThis as { chrome?: unknown }).chrome as
    | {
        runtime?: { getManifest?: () => { version: string } };
        storage?: { local?: { onChanged?: { addListener?: unknown } } };
        alarms?: { create?: unknown; onAlarm?: { addListener?: unknown } };
      }
    | undefined;
  if (
    typeof c?.runtime?.getManifest !== 'function' ||
    typeof c?.storage?.local?.onChanged?.addListener !== 'function'
  ) {
    return;
  }
  state.trust = new TrustStore(chrome.runtime.getManifest().version);
  state.sessions = new SessionKeys();
  // Part 3: respond to popup queries for the connected identity hash set.
  if (typeof chrome.runtime.onMessage?.addListener === 'function') {
    chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
      if (
        msg !== null &&
        typeof msg === 'object' &&
        (msg as { type?: unknown }).type === 'get-connected-identities'
      ) {
        sendResponse({ connectedHashes: [...connectedIdentityHashes()] });
        return true;
      }
    });
  }
  chrome.storage.local.onChanged.addListener((changes) => {
    const approved = changes[APPROVED_PAIR_KEY]?.newValue as AnyPendingRecord | undefined;
    if (approved) {
      void onApproval(approved).catch((e) => console.error('[fetchproxy] approval:', e));
    }
    // Part 2: dismiss message from popup — remove scope-update entry + record dismissed hash.
    const dismiss = changes['dismissedScopeUpdate']?.newValue as
      | { key: string; identityHash: string; scopeHash: string }
      | undefined;
    if (dismiss) {
      void onScopeUpdateDismiss(dismiss.key, dismiss.identityHash, dismiss.scopeHash)
        .catch((e) => console.error('[fetchproxy] dismiss:', e));
    }
    // 0.4.2: keep the badge in sync with the pending-pair state.
    // Cancel (popup) and the user-driven X removes the key without
    // going through onApproval, so this is the catch-all clear point.
    // 0.5.2+: the value is now a dict — has any non-empty content means
    // at least one pending entry remains and the badge should stay lit.
    if (PENDING_PAIR_KEY in changes) {
      const next = changes[PENDING_PAIR_KEY]?.newValue;
      const dict = mergePending(next);
      if (Object.keys(dict).length > 0) setPairPendingBadge();
      else clearPairPendingBadge();
    }
  });
  // 0.4.2: on SW boot, repaint the badge from current storage so a
  // pending pair survives a service-worker eviction without losing
  // its visual indicator.
  void chrome.storage.local.get(PENDING_PAIR_KEY).then((got) => {
    const dict = mergePending(got[PENDING_PAIR_KEY]);
    if (Object.keys(dict).length > 0) setPairPendingBadge();
    else clearPairPendingBadge();
  });
  // 0.4.1: register the MV3 keepalive alarm before anything else. Each
  // fire wakes the SW from idle and re-runs connect() — which is a
  // no-op when the WS is open and a reconnect when it isn't. This is
  // what keeps the bridge alive between bursts of MCP tool calls
  // without the user having to open DevTools to pin the worker.
  // Guarded so unit tests (which don't mock chrome.alarms) still skip.
  if (
    typeof c?.alarms?.create === 'function' &&
    typeof c?.alarms?.onAlarm?.addListener === 'function'
  ) {
    startKeepalive({
      alarms: chrome.alarms,
      ensureConnected: connect,
    });
  }
  // 0.4.0: load (or generate) the extension's long-term identity
  // before connecting. The identity is required to construct the
  // extension hello on WS open.
  void loadOrCreateExtensionIdentity()
    .then((id) => {
      state.extIdentity = id;
      connect();
    })
    .catch((e) => console.error('[fetchproxy] extension identity boot:', e));
}
