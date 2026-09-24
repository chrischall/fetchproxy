/**
 * The user-approval flow: what happens after the popup writes its decision
 * to `chrome.storage.session` (trusted contexts only — see `pendingArea()` in
 * ./pending-pair-store.ts for why never `storage.local`).
 *
 * `onApproval` persists trust, then — for a `pair` record — replays the
 * post-approval session setup for every waiting mcpId (fresh ephemeral
 * keypair, ECDH, HKDF, ReadyFrame) and, for a `scope-update` record,
 * refreshes the live in-memory scope maps with no reconnect.
 * `onScopeUpdateDismiss` is the decline path: drop the pending entry and
 * remember the dismissed scopeHash so it is not re-queued.
 *
 * Both are called only from `./boot.js`'s `storage.session.onChanged`
 * listener; nothing else in the background imports this module.
 *
 * The approval arrives from storage, so it carries no link — it is replayed
 * against the link each waiting `mcpId` is bound to, and an id whose link has
 * dropped in the meantime is skipped rather than answered on another socket.
 * That is not a fussy detail: the ready signature commits to the link's
 * per-connection nonce, so a ready sent on the wrong link is a signature the
 * MCP is right to refuse.
 */

import {
  ecdhX25519,
  hkdfSha256,
  generateX25519,
  toB64,
  fromB64,
  readySignaturePayload,
  transcriptHash,
  HKDF_SESSION_INFO,
  type ReadyFrame,
} from '@fetchproxy/protocol';
import { ensureDomainTab } from '../ensure-domain-tab.js';
import { signWithExtensionIdentity } from '../extension-identity.js';
import { recordDismissedScopeHash } from '../vault-records.js';
import { enc } from '../lib/text.js';

import type { ChromeApi } from '../chrome-api.js';

declare const chrome: ChromeApi;

import { clearPairPendingBadge } from './badge.js';
import type { AnyPendingRecord } from './pending-records.js';
import { state } from './state.js';
import { linkForMcp, sendOnLink } from './links.js';
import {
  PENDING_PAIR_KEY,
  APPROVED_PAIR_KEY,
  DISMISS_SCOPE_UPDATE_KEY,
  mergePending,
  pendingArea,
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
import { syncMainWorldBridgeFromTrust } from '../main-world-bridge.js';

export async function onApproval(approved: AnyPendingRecord): Promise<void> {
  if (!state.trust || !state.sessions || !state.extIdentity) return;
  // Fail closed without the trusted-only area. `./boot.js` only ever calls
  // this from `storage.session.onChanged`, so this is belt and braces.
  const area = pendingArea();
  if (!area) return;
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
    domListSelectors: (approved.domListSelectors ?? []).map((d) => ({
      ...d,
      fields: d.fields.map((f) => ({ ...f })),
    })),
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
  // Audit #1003: extend the MAIN-world page bridge to the newly approved
  // hosts — including tabs already open on them — before the MCP is told it
  // is ready, so its first CSRF/GraphQL call finds the bridge in place.
  await syncMainWorldBridgeFromTrust(state.trust, { injectIntoOpenTabs: true });

  if (approved.kind === 'pair') {
    // 0.6.0+: replay the post-approval session setup for EVERY mcpId in the
    // entry. Each process had its own hello nonce (for ECDH uniqueness), and
    // since 3.0.0 its own session EPHEMERAL too; they share only the identity
    // and the approval outcome — so the derivation and the ReadyFrame are
    // driven independently for each, from that process's own stored pair.
    //
    // `approved.identityX25519Pub` is deliberately NOT read here any more: it
    // was the MCP's half of the ECDH under v3, and reaching for it again is
    // the v3 derivation reinstated under a v4 signature.
    const mcpIdsToUnblock = approved.mcpIds ?? [];
    for (const mcpId of mcpIdsToUnblock) {
      const sessionNonceB64 = approved.sessionNonces?.[mcpId];
      if (!sessionNonceB64) {
        console.warn(`[fetchproxy] onApproval: missing sessionNonce for mcpId ${mcpId}; skipping`);
        continue;
      }
      // 3.0.0 (protocol 4): the MCP's session ephemeral, stored beside the
      // nonce when the hello arrived. Skipped with the same warn as a missing
      // nonce — every pending record already in `chrome.storage.local` when
      // the extension is reloaded has no value here, and the MCP hellos again.
      // NOT falling back to `identityX25519Pub`, which is the v3 derivation
      // reinstated under a v4 signature: the key would be one the MCP cannot
      // compute, so the session would look established and every frame fail.
      const mcpSessionPubB64 = approved.sessionPubs?.[mcpId];
      if (!mcpSessionPubB64) {
        console.warn(`[fetchproxy] onApproval: missing sessionPub for mcpId ${mcpId}; skipping`);
        continue;
      }
      // The bridge this MCP said hello on, and the nonce it said it on. Both
      // gone means the link dropped between the prompt and the click: there is
      // nothing to answer, and the MCP will hello again on reconnect.
      const link = linkForMcp(mcpId);
      if (!link || !link.sessionNonce) {
        console.warn(`[fetchproxy] onApproval: no live bridge for mcpId ${mcpId}; skipping`);
        continue;
      }
      const sessionNonce = fromB64(sessionNonceB64);
      const mcpSessionPub = fromB64(mcpSessionPubB64);
      // Each process gets its own fresh ephemeral keypair so the resulting
      // session keys are independent.
      //
      // 3.0.0: against the STORED ephemeral and salted with the transcript,
      // exactly as the auto-trust path derives. These are two code paths
      // deriving one thing and they have drifted before.
      const ephemeral = await generateX25519();
      const shared = await ecdhX25519(ephemeral.privateKey, mcpSessionPub);
      const sessionKey = await hkdfSha256(
        shared,
        await transcriptHash(
          sessionNonce,
          link.sessionNonce,
          mcpSessionPub,
          ephemeral.publicKey,
        ),
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
      const sessionSig = await signWithExtensionIdentity(
        state.extIdentity,
        readySignaturePayload(
          sessionNonce,
          link.sessionNonce,
          ephemeral.publicKey,
          mcpSessionPub,
        ),
      );
      const ready: ReadyFrame = {
        type: 'ready',
        mcpId,
        extensionSessionPub: toB64(ephemeral.publicKey),
        // The STORED pub, which is what Rule C's other end needs: an MCP that
        // has re-minted since the prompt discards this instead of reading it
        // as a forgery.
        mcpSessionPub: mcpSessionPubB64,
        sessionSig: toB64(sessionSig),
      };
      sendOnLink(link, JSON.stringify(ready));
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
    const got = await area.get(PENDING_PAIR_KEY);
    const remaining = mergePending(got[PENDING_PAIR_KEY]);
    delete remaining[approved.key];
    if (Object.keys(remaining).length === 0) {
      await area.remove(PENDING_PAIR_KEY);
      // Badge clears only when the queue is fully drained — other queued
      // identities still need a visible "!" so the user knows to come back.
      clearPairPendingBadge();
    } else {
      await area.set({ [PENDING_PAIR_KEY]: remaining });
    }
  });
  await area.remove(APPROVED_PAIR_KEY);
}

/** Part 2: dismiss a scope-update entry without writing trust. */

export async function onScopeUpdateDismiss(key: string, identityHash: string, dismissedScopeHash: string): Promise<void> {
  const area = pendingArea();
  if (!area) return;
  // Record the dismissed scopeHash so we don't re-queue it for this identity.
  // The dismissed-hash SET must outlive a browser restart, so it cannot live
  // in storage.session with the queue; it lives in the vault, where — unlike
  // storage.local — no content script can plant a dismissal (#252).
  await withPendingPairLock(async () => {
    const pendingGot = await area.get(PENDING_PAIR_KEY);
    // Remove from pending.
    const remaining = mergePending(pendingGot[PENDING_PAIR_KEY]);
    delete remaining[key];
    if (Object.keys(remaining).length === 0) {
      await area.remove(PENDING_PAIR_KEY);
      clearPairPendingBadge();
    } else {
      await area.set({ [PENDING_PAIR_KEY]: remaining });
    }
    // Persist dismissed hash: Record<identityHash, string[]>
    await recordDismissedScopeHash(identityHash, dismissedScopeHash);
  });
  await area.remove(DISMISS_SCOPE_UPDATE_KEY);
}
