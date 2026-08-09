/**
 * The user-approval flow: what happens after the popup writes its decision
 * to `chrome.storage.local`.
 *
 * `onApproval` persists trust, then — for a `pair` record — replays the
 * post-approval session setup for every waiting mcpId (fresh ephemeral
 * keypair, ECDH, HKDF, ReadyFrame) and, for a `scope-update` record,
 * refreshes the live in-memory scope maps with no reconnect.
 * `onScopeUpdateDismiss` is the decline path: drop the pending entry and
 * remember the dismissed scopeHash so it is not re-queued.
 *
 * Both are called only from `./boot.js`'s single `storage.local.onChanged`
 * listener; nothing else in the background imports this module.
 */

import {
  ed25519Sign,
  ecdhX25519,
  hkdfSha256,
  generateX25519,
  toB64,
  fromB64,
  readySignaturePayload,
  HKDF_SESSION_INFO,
  type ReadyFrame,
} from '@fetchproxy/protocol';
import { ensureDomainTab } from '../ensure-domain-tab.js';
import { enc } from '../lib/text.js';

import type { ChromeApi } from '../chrome-api.js';

declare const chrome: ChromeApi;

import { clearPairPendingBadge } from './badge.js';
import type { AnyPendingRecord } from './pending-records.js';
import { state } from './state.js';
import {
  PENDING_PAIR_KEY,
  APPROVED_PAIR_KEY,
  DISMISSED_SCOPE_KEY,
  mergePending,
  withPendingPairLock,
} from './pending-pair-store.js';
import {
  mcpDomains,
  mcpIdentityHash,
  grantedScopeFromApproval,
  applyGrantedScopeToSession,
  liveScopeApplications,
  broadcastConnectionsChanged,
} from './session-scope.js';

export async function onApproval(approved: AnyPendingRecord): Promise<void> {
  if (!state.trust || !state.sessions || !state.extIdentity || !state.currentExtSessionNonce) return;
  // Persist trust. Default to ['fetch'] when older popup state somehow
  // omits the field — defensive, the popup always populates it in 0.2.0+.
  const approvedCapabilities =
    approved.capabilities && approved.capabilities.length > 0
      ? [...approved.capabilities]
      : ['fetch'];
  // Trust is keyed by identityHash — write it once for the entire group of
  // waiting processes (all share the same identity and scope).
  await state.trust.put(approved.identityHash, {
    serverName: approved.serverName,
    domains: [...approved.domains],
    capabilities: approvedCapabilities,
    cookieKeys: [...(approved.cookieKeys ?? [])],
    localStorageKeys: [...(approved.localStorageKeys ?? [])],
    sessionStorageKeys: [...(approved.sessionStorageKeys ?? [])],
    captureHeaders: (approved.captureHeaders ?? []).map((d) => ({
      host: d.host,
      ...(d.path !== undefined ? { path: d.path } : {}),
      headerName: d.headerName,
    })),
    indexedDbScopes: (approved.indexedDbScopes ?? []).map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    })),
    domSelectors: (approved.domSelectors ?? []).map((d) => ({ ...d })),
    graphqlOps: (approved.graphqlOps ?? []).map((d) => ({
      name: d.name,
      operationName: d.operationName,
    })),
    localStoragePointers: (approved.localStoragePointers ?? []).map((d) => ({
      key: d.key,
      jsonPointer: d.jsonPointer,
    })),
    sessionStoragePointers: (approved.sessionStoragePointers ?? []).map((d) => ({
      key: d.key,
      jsonPointer: d.jsonPointer,
    })),
    identityX25519Pub: approved.identityX25519Pub,
    identityEd25519Pub: approved.identityEd25519Pub,
    // 0.4.0: remember the extension identity active when the user
    // approved. A wholesale extension reinstall produces a fresh
    // keypair and re-triggers the pair flow.
    extensionIdentityX25519Pub: toB64(state.extIdentity.x25519Pub),
    extensionIdentityEd25519Pub: toB64(state.extIdentity.ed25519Pub),
  });

  if (approved.kind === 'pair') {
    // 0.6.0+: replay the post-approval session setup for EVERY mcpId in the
    // entry. Each process had its own hello nonce (for ECDH uniqueness), but
    // they share the same identity pub and approval outcome — so we drive the
    // same session-key derivation + ReadyFrame send independently for each.
    const identityPub = fromB64(approved.identityX25519Pub);
    const mcpIdsToUnblock = approved.mcpIds ?? [];
    for (const mcpId of mcpIdsToUnblock) {
      const sessionNonceB64 = approved.sessionNonces?.[mcpId];
      if (!sessionNonceB64) {
        console.warn(`[fetchproxy] onApproval: missing sessionNonce for mcpId ${mcpId}; skipping`);
        continue;
      }
      const sessionNonce = fromB64(sessionNonceB64);
      // Each process gets its own fresh ephemeral keypair so the resulting
      // session keys are independent.
      const ephemeral = await generateX25519();
      const shared = await ecdhX25519(ephemeral.privateKey, identityPub);
      const sessionKey = await hkdfSha256(
        shared,
        sessionNonce,
        enc.encode(HKDF_SESSION_INFO),
        32,
      );
      state.sessions.set(mcpId, sessionKey);
      mcpDomains.set(mcpId, [...approved.domains]);
      applyGrantedScopeToSession(mcpId, grantedScopeFromApproval(approved));
      // Part 3: track identity hash per approved session.
      mcpIdentityHash.set(mcpId, approved.identityHash);
      broadcastConnectionsChanged();
      // 0.4.0: sign over the MCP hello nonce and ours; 2.0.0: and the
      // ephemeral pub below, so a relay cannot swap it for one of its own.
      // The MCP verifies this against our claimed Ed25519 pub and gates
      // session-key derivation on it.
      const sessionSig = await ed25519Sign(
        state.extIdentity.ed25519Priv,
        readySignaturePayload(sessionNonce, state.currentExtSessionNonce!, ephemeral.publicKey),
      );
      const ready: ReadyFrame = {
        type: 'ready',
        mcpId,
        extensionSessionPub: toB64(ephemeral.publicKey),
        sessionSig: toB64(sessionSig),
      };
      state.ws?.send(JSON.stringify(ready));
    }
    // Ensure domain tabs for the approved domains (once for the group).
    for (const d of approved.domains) {
      void ensureDomainTab(d).catch(() => {
        /* noop */
      });
    }
  }
  if (approved.kind === 'scope-update' && state.sessions) {
    // trust.put (above) persists the wider scope for future hellos. But the
    // session is already live — so refresh the in-memory scope maps the request
    // handler reads, for each still-connected mcpId of this identity. The grant
    // then takes effect immediately, with NO reconnect. Sessions are already
    // keyed, so there's no ECDH/ReadyFrame to redo (unlike the pair branch).
    const sess = state.sessions;
    let applied = false;
    for (const { mcpId, scope } of liveScopeApplications(
      approved,
      (id) => sess.get(id) !== null,
    )) {
      applyGrantedScopeToSession(mcpId, scope);
      applied = true;
    }
    if (applied) broadcastConnectionsChanged();
  }

  // 0.6.0+: clear popup state for the entire approved key entry. All waiting
  // mcpIds were handled in the loop above. The popup's onApprove handler
  // writes approvedPair → this listener fires → we clean up here. The RMW
  // shares `withPendingPairLock` with `onServerHello` so a hello arriving
  // mid-approval can't race the get/set pair.
  await withPendingPairLock(async () => {
    const got = await chrome.storage.local.get(PENDING_PAIR_KEY);
    const remaining = mergePending(got[PENDING_PAIR_KEY]);
    delete remaining[approved.key];
    if (Object.keys(remaining).length === 0) {
      await chrome.storage.local.remove(PENDING_PAIR_KEY);
      // Badge clears only when the queue is fully drained — other queued
      // identities still need a visible "!" so the user knows to come back.
      clearPairPendingBadge();
    } else {
      await chrome.storage.local.set({ [PENDING_PAIR_KEY]: remaining });
    }
  });
  await chrome.storage.local.remove(APPROVED_PAIR_KEY);
}

/** Part 2: dismiss a scope-update entry without writing trust. */

export async function onScopeUpdateDismiss(key: string, identityHash: string, dismissedScopeHash: string): Promise<void> {
  // Record the dismissed scopeHash so we don't re-queue it for this identity.
  await withPendingPairLock(async () => {
    const [pendingGot, dismissedGot] = await Promise.all([
      chrome.storage.local.get(PENDING_PAIR_KEY),
      chrome.storage.local.get(DISMISSED_SCOPE_KEY),
    ]);
    // Remove from pending.
    const remaining = mergePending(pendingGot[PENDING_PAIR_KEY]);
    delete remaining[key];
    if (Object.keys(remaining).length === 0) {
      await chrome.storage.local.remove(PENDING_PAIR_KEY);
      clearPairPendingBadge();
    } else {
      await chrome.storage.local.set({ [PENDING_PAIR_KEY]: remaining });
    }
    // Persist dismissed hash: Record<identityHash, string[]>
    const dismissed = (dismissedGot[DISMISSED_SCOPE_KEY] ?? {}) as Record<string, string[]>;
    const current = dismissed[identityHash] ?? [];
    if (!current.includes(dismissedScopeHash)) {
      dismissed[identityHash] = [...current, dismissedScopeHash];
    }
    await chrome.storage.local.set({ [DISMISSED_SCOPE_KEY]: dismissed });
  });
  await chrome.storage.local.remove('dismissedScopeUpdate');
}
