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
import { connect, loadRemoteLinks } from './socket.js';
import { connectedIdentityHashes } from './session-scope.js';
import { linkStatuses } from './links.js';
import {
  PENDING_PAIR_KEY,
  APPROVED_PAIR_KEY,
  DISMISS_SCOPE_UPDATE_KEY,
  mergePending,
} from './pending-pair-store.js';
import { REMOTE_TARGETS_CHANGED } from '../remote-targets.js';
import { onApproval, onScopeUpdateDismiss } from './approval.js';
import { maybeReinjectOnInstalled } from '../reinject-content-scripts.js';
import { armInstallSignal, noteInstalled } from '../vault-migration.js';

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
  // An extension UPDATE orphans the content script in every already-open tab
  // (Chrome tears the old ones down and injects no new ones), so every MCP
  // reading from a long-lived tab breaks at once until the person reloads it.
  // Re-inject instead of making them find that out. Guarded like the rest of
  // boot: absent in tests and on older Chrome, where it is simply skipped.
  //
  // The same event is the ONLY thing that authorises importing a 3.2.0-or-
  // earlier install's identity and trust out of storage.local
  // (`vault-migration.ts`): an empty vault alone is not enough, because a
  // lost vault is empty too and storage.local is content-script writable.
  // Arm the wait first, so the identity load below — which can reach the
  // vault before Chrome dispatches onInstalled — lets it decide.
  if (typeof chrome.runtime.onInstalled?.addListener === 'function') {
    armInstallSignal();
    chrome.runtime.onInstalled.addListener((details) => {
      void noteInstalled(details);
      void maybeReinjectOnInstalled(details);
    });
  }
  // Part 3: respond to popup queries for the connected identity hash set.
  if (typeof chrome.runtime.onMessage?.addListener === 'function') {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
      // 2.1.0: the popup changed the configured remote bridge targets — a
      // target added, removed, disabled or repointed. Reconcile the live links
      // onto the new set rather than waiting for a restart, and note that a
      // REMOVED target's sessions go with it: a bridge the user just deleted
      // must stop being one this browser answers. The targets are re-read
      // from the vault, never from the message, so a content script sending
      // this (it can reach onMessage too) can at most cause a no-op reload;
      // tab senders are ignored anyway. Up to 3.2.0 this listened on
      // storage.local.onChanged, back when a content script could write the
      // targets themselves (#252).
      if (
        msg !== null &&
        typeof msg === 'object' &&
        (msg as { type?: unknown }).type === REMOTE_TARGETS_CHANGED &&
        (sender as { tab?: unknown } | undefined)?.tab === undefined
      ) {
        void loadRemoteLinks().catch((e) =>
          console.error('[fetchproxy] remote bridge reconcile:', e),
        );
        return;
      }
      if (
        msg !== null &&
        typeof msg === 'object' &&
        (msg as { type?: unknown }).type === 'get-connected-identities'
      ) {
        // The link statuses ride the same query rather than a second one: the
        // popup asks once, and a bridge row that says "configured" while its
        // socket is down is the state this exists to make visible.
        sendResponse({ connectedHashes: [...connectedIdentityHashes()], links: linkStatuses() });
        return true;
      }
    });
  }
  // S-SEC-3: the pairing queue and the popup's decisions travel ONLY through
  // chrome.storage.session, which content scripts cannot read or write.
  // storage.local is writable from every site's content script, so an
  // `approvedPair` or `dismissedScopeUpdate` appearing there is never acted
  // on. Without the session area (Chrome < 102) this fails closed: nothing is
  // queued (server-hello.ts) and nothing is approved.
  const session = chrome.storage.session;
  if (session?.onChanged) {
    session.onChanged.addListener((changes) => {
      const approved = changes[APPROVED_PAIR_KEY]?.newValue as AnyPendingRecord | undefined;
      if (approved) {
        void onApproval(approved).catch((e) => console.error('[fetchproxy] approval:', e));
      }
      // Part 2: dismiss message from popup — remove scope-update entry + record dismissed hash.
      const dismiss = changes[DISMISS_SCOPE_UPDATE_KEY]?.newValue as
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
    void session.get(PENDING_PAIR_KEY).then((got) => {
      const dict = mergePending(got[PENDING_PAIR_KEY]);
      if (Object.keys(dict).length > 0) setPairPendingBadge();
      else clearPairPendingBadge();
    });
  } else {
    console.error('[fetchproxy] chrome.storage.session unavailable: pairing is disabled');
  }
  // Up to 3.1.0 the queue lived in storage.local. Drop what an older version
  // left there: nothing reads it any more, and a request from before this
  // update cannot be answered (its MCP will hello again).
  void chrome.storage.local.remove(PENDING_PAIR_KEY);
  void chrome.storage.local.remove(APPROVED_PAIR_KEY);
  void chrome.storage.local.remove(DISMISS_SCOPE_UPDATE_KEY);
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
      // Remote targets are additional and asynchronous: the loopback link is
      // dialled above without waiting on storage, so a slow (or empty) target
      // list cannot delay the bridge that has always worked.
      return loadRemoteLinks();
    })
    .catch((e) => console.error('[fetchproxy] extension identity boot:', e));
}
