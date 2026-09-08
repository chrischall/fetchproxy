/**
 * `onServerHello` — the handshake reaction, moved verbatim out of
 * `background.ts`.
 *
 * It now takes the LINK the hello arrived on, and that argument is the
 * security-relevant part rather than plumbing. Two things come off it:
 *
 * - the `mcpId` is bound to this link before anything else happens, and a
 *   hello claiming an id another live link already holds is dropped here
 *   (`links.ts` rule 2). Nothing downstream can re-point that binding;
 * - the ready signature is made over THIS link's per-connection nonce and
 *   sent back on THIS link's socket. A global nonce would sign one bridge's
 *   ready with another bridge's handshake, which the MCP would reject — as it
 *   should.
 *
 * This is the widest fan-out module in the split: it reaches the pure
 * decision function (`hello.ts`), the per-session scope maps, the pending
 * records, the pending-pair store, the badge, tab creation, and the
 * protocol crypto. It is nonetheless a leaf with respect to the transport —
 * it does NOT import `socket.ts`. Its only outbound need is `ws.send`, and
 * it reaches that through the link's own socket, so `socket.ts` →
 * `server-hello.ts` stays a one-way edge.
 *
 * `link.sessionNonce` and `link.ws` are deliberately re-read at their original
 * lines rather than captured at the guard: both are reassigned by a reconnect,
 * and caching them would sign a ReadyFrame with a stale nonce or write it to a
 * dead socket.
 */

import {
  ed25519Sign,
  sha256,
  toB64,
  fromB64,
  toHex,
  readySignaturePayload,
  type HelloFrameFromServer,
  type ReadyFrame,
} from '@fetchproxy/protocol';

import type { ChromeApi } from '../chrome-api.js';
import { ensureDomainTab } from '../ensure-domain-tab.js';
import { scopeHash } from '../lib/scope.js';

import { state } from './state.js';
import { bindMcpToLink, sendOnLink, unbindMcp, type Link } from './links.js';
import { handleServerHello } from './hello.js';
import { setPairPendingBadge } from './badge.js';
import {
  applyNeedsPairRecord,
  type PendingPairRecord,
  type PendingScopeUpdateRecord,
} from './pending-records.js';
import {
  PENDING_PAIR_KEY,
  DISMISSED_SCOPE_KEY,
  mergePending,
  withPendingPairLock,
} from './pending-pair-store.js';
import {
  mcpDomains,
  mcpIdentityHash,
  applyGrantedScopeToSession,
  broadcastConnectionsChanged,
} from './session-scope.js';

declare const chrome: ChromeApi;

/**
 * Tell the server WHY its hello was refused, when it said it can hear that
 * (`accepts`). Gated because `validateFrame` on a server older than 2.6.0
 * throws `unknown frame type` and the caller closes the socket — so sending
 * this unconditionally would turn a diagnosable refusal into a dropped
 * connection, which is strictly worse than the silence it replaces.
 *
 * Best-effort and fire-and-forget: this is a diagnostic. It grants nothing
 * and carries no authority, and a refusal that cannot be delivered still has
 * to leave the session unestablished.
 */
function tellServerWhy(link: Link, hello: HelloFrameFromServer, reason: string): void {
  if (!hello.accepts?.includes('hello-rejected')) return;
  try {
    sendOnLink(link, JSON.stringify({ type: 'hello-rejected', mcpId: hello.mcpId, reason }));
  } catch (e) {
    console.warn('[fetchproxy] hello-rejected send failed:', e);
  }
}

export async function onServerHello(link: Link, hello: HelloFrameFromServer): Promise<void> {
  if (!state.trust || !state.sessions || !state.extIdentity || !link.sessionNonce) return;
  // Bind before deciding anything. An mcpId another live link already holds is
  // not this link's to speak for, and the refusal has to happen before a
  // session key, a scope grant or a pair prompt exists for it.
  if (!bindMcpToLink(hello.mcpId, link)) {
    console.warn(
      `[fetchproxy] dropped hello for ${hello.mcpId} on ${link.label}: that id is already bound to another bridge`,
    );
    tellServerWhy(link, hello, 'that mcpId is already bound to another bridge');
    return;
  }
  const result = await handleServerHello(hello, {
    trust: state.trust,
    extensionIdentityX25519Pub: state.extIdentity.x25519Pub,
  });
  if (result.kind === 'reject') {
    // Give the binding back. It was taken before the decision — deliberately,
    // so a second link cannot claim the id mid-decision — but a REFUSED id is
    // one this extension is not speaking for, and holding it until the link
    // drops would let a hello flood grow the table without bound and would
    // block a legitimate re-hello of the same id behind a rejection.
    unbindMcp(hello.mcpId, link);
    console.warn(`[fetchproxy] rejected hello for ${hello.mcpId}: ${result.reason}`);
    tellServerWhy(link, hello, result.reason);
    return;
  }
  if (result.kind === 'auto-trust') {
    // Store GRANTED (intersection) scope in the mcp* maps. `result` carries the
    // already-intersected scope (granted = approved ∩ declared), so applying it
    // verbatim never escalates beyond approval.
    state.sessions.set(result.mcpId, result.sessionKey);
    mcpDomains.set(result.mcpId, [...result.domains]);
    applyGrantedScopeToSession(result.mcpId, result);
    // Part 3: track identity hash per session for connected-status dot.
    mcpIdentityHash.set(result.mcpId, toHex(await sha256(fromB64(hello.identityX25519Pub))));
    broadcastConnectionsChanged();
    for (const d of result.domains) {
      void ensureDomainTab(d).catch(() => {
        /* fire-and-forget */
      });
    }
    // 0.4.0: ready frame carries the binding signature so the MCP
    // host can verify before proceeding. 2.0.0: it covers the ephemeral
    // pub too, so the key the session is derived from is the one we signed.
    const sessionSig = await ed25519Sign(
      state.extIdentity.ed25519Priv,
      readySignaturePayload(
        result.mcpSessionNonce,
        link.sessionNonce,
        result.extensionSessionPub,
      ),
    );
    const ready: ReadyFrame = {
      type: 'ready',
      mcpId: result.mcpId,
      extensionSessionPub: toB64(result.extensionSessionPub),
      sessionSig: toB64(sessionSig),
    };
    sendOnLink(link, JSON.stringify(ready));

    // Part 2: if the MCP declared more than approved, queue a non-blocking
    // scope-update offer. The user can Grant (update trust) or dismiss.
    if (result.pendingScopeUpdate) {
      const su = result.pendingScopeUpdate;
      // Compute the declared-scope hash to key the entry.
      const declaredScopeForHash = {
        capabilities: su.declaredCapabilities,
        cookieKeys: su.declaredCookieKeys,
        localStorageKeys: su.declaredLocalStorageKeys,
        sessionStorageKeys: su.declaredSessionStorageKeys,
        captureHeaders: su.declaredCaptureHeaders,
        indexedDbScopes: su.declaredIndexedDbScopes,
        domSelectors: su.declaredDomSelectors,
        graphqlOps: su.declaredGraphqlOps,
        localStoragePointers: su.declaredLocalStoragePointers,
        sessionStoragePointers: su.declaredSessionStoragePointers,
      };
      const declaredHash = await scopeHash(declaredScopeForHash);
      const suKey = `${su.identityHash}:${declaredHash}`;
      await withPendingPairLock(async () => {
        // Check dismiss suppression: skip queuing if this identity dismissed
        // this exact declared scope hash before.
        const dismissedGot = await chrome.storage.local.get(DISMISSED_SCOPE_KEY);
        const dismissed = (dismissedGot[DISMISSED_SCOPE_KEY] ?? {}) as Record<string, string[]>;
        const dismissedForIdentity = dismissed[su.identityHash] ?? [];
        if (dismissedForIdentity.includes(declaredHash)) {
          // Suppressed: user dismissed this scope, don't re-queue.
          return;
        }
        const got = await chrome.storage.local.get(PENDING_PAIR_KEY);
        const existing = mergePending(got[PENDING_PAIR_KEY]);
        const currentEntry = existing[suKey];
        if (currentEntry) {
          // Dedup: add mcpId to the existing entry.
          if (!currentEntry.mcpIds.includes(result.mcpId)) {
            currentEntry.mcpIds.push(result.mcpId);
          }
        } else {
          const suRecord: PendingScopeUpdateRecord = {
            key: suKey,
            kind: 'scope-update',
            identityHash: su.identityHash,
            serverName: hello.serverName,
            version: hello.version,
            mcpIds: [result.mcpId],
            domains: [...hello.domains],
            capabilities: [...su.declaredCapabilities],
            cookieKeys: [...su.declaredCookieKeys],
            localStorageKeys: [...su.declaredLocalStorageKeys],
            sessionStorageKeys: [...su.declaredSessionStorageKeys],
            captureHeaders: su.declaredCaptureHeaders.map((d) => ({ ...d })),
            indexedDbScopes: su.declaredIndexedDbScopes.map((d) => ({
              origin: d.origin,
              database: d.database,
              store: d.store,
              keys: [...d.keys],
            })),
            domSelectors: su.declaredDomSelectors.map((d) => ({ ...d })),
            graphqlOps: su.declaredGraphqlOps.map((d) => ({ ...d })),
            localStoragePointers: su.declaredLocalStoragePointers.map((d) => ({ ...d })),
            sessionStoragePointers: su.declaredSessionStoragePointers.map((d) => ({ ...d })),
            identityX25519Pub: hello.identityX25519Pub,
            identityEd25519Pub: hello.identityEd25519Pub,
            previousScope: {
              capabilities: [...su.approvedCapabilities],
              cookieKeys: [...su.approvedCookieKeys],
              localStorageKeys: [...su.approvedLocalStorageKeys],
              sessionStorageKeys: [...su.approvedSessionStorageKeys],
              captureHeaders: su.approvedCaptureHeaders.map((d) => ({ ...d })),
              indexedDbScopes: su.approvedIndexedDbScopes.map((d) => ({
                origin: d.origin,
                database: d.database,
                store: d.store,
                keys: [...d.keys],
              })),
              domSelectors: su.approvedDomSelectors.map((d) => ({ ...d })),
              graphqlOps: su.approvedGraphqlOps.map((d) => ({ ...d })),
              localStoragePointers: su.approvedLocalStoragePointers.map((d) => ({ ...d })),
              sessionStoragePointers: su.approvedSessionStoragePointers.map((d) => ({ ...d })),
            },
          };
          existing[suKey] = suRecord;
        }
        await chrome.storage.local.set({ [PENDING_PAIR_KEY]: existing });
      });
      setPairPendingBadge();
    }
    return;
  }
  // needs-pair: queue for popup.
  // 0.6.0+: compute the composite key (identityHash + scopeHash) so that
  // concurrent processes sharing the same identity and scope collapse into a
  // single approval prompt rather than flooding the user with N identical
  // dialogs. The scope object is reconstructed from the result fields.
  const declaredScopeForHash = {
    capabilities: [...result.capabilities],
    cookieKeys: [...result.cookieKeys],
    localStorageKeys: [...result.localStorageKeys],
    sessionStorageKeys: [...result.sessionStorageKeys],
    captureHeaders: [...result.captureHeaders],
    indexedDbScopes: [...result.indexedDbScopes],
    domSelectors: [...result.domSelectors],
    graphqlOps: [...result.graphqlOps],
    localStoragePointers: [...result.localStoragePointers],
    sessionStoragePointers: [...result.sessionStoragePointers],
  };
  const pendingKey = `${result.identityHash}:${await scopeHash(declaredScopeForHash)}`;
  const sessionNonceB64 = toB64(result.sessionNonce);
  // 0.6.0+: store pending pairs as a dict keyed by `${identityHash}:${scopeHash}`.
  // `applyNeedsPairRecord` handles all three cases: existing pair (dedup),
  // no entry (create), and existing scope-update (supersede — trust is gone).
  // The read-modify-write is wrapped in `withPendingPairLock` so concurrent
  // peer hellos can't race the get/set pair.
  const newPendingRecord: PendingPairRecord = {
    key: pendingKey,
    kind: 'pair',
    identityHash: result.identityHash,
    serverName: result.serverName,
    version: result.version,
    mcpIds: [result.mcpId],
    sessionNonces: { [result.mcpId]: sessionNonceB64 },
    domains: [...result.domains],
    capabilities: [...result.capabilities],
    cookieKeys: [...result.cookieKeys],
    localStorageKeys: [...result.localStorageKeys],
    sessionStorageKeys: [...result.sessionStorageKeys],
    captureHeaders: [...result.captureHeaders],
    indexedDbScopes: [...result.indexedDbScopes],
    domSelectors: [...result.domSelectors],
    graphqlOps: [...result.graphqlOps],
    localStoragePointers: [...result.localStoragePointers],
    sessionStoragePointers: [...result.sessionStoragePointers],
    ...(result.previousScope ? { previousScope: result.previousScope } : {}),
    pairCode: result.pairCode,
    identityX25519Pub: result.identityX25519Pub,
    identityEd25519Pub: result.identityEd25519Pub,
  };
  await withPendingPairLock(async () => {
    const got = await chrome.storage.local.get(PENDING_PAIR_KEY);
    const existing = mergePending(got[PENDING_PAIR_KEY]);
    applyNeedsPairRecord(existing, pendingKey, newPendingRecord);
    await chrome.storage.local.set({ [PENDING_PAIR_KEY]: existing });
  });
  // 0.4.2: surface the pending pair without making the user discover
  // it manually — paint the action-icon badge and best-effort try to
  // open the popup. Both no-op in environments that don't expose
  // chrome.action (unit tests, older Chrome).
  setPairPendingBadge();
  // 0.5.2+: notify the MCP-side server (host or peer) that the user has
  // been asked to approve. The MCP can then include `pairCode` in tool
  // errors so the chat shows the same XXX-XXX the popup is displaying.
  // We send one pair-pending notification per mcpId — each process's MCP
  // host needs to know its own pairing is pending. Best-effort: if the WS
  // dropped between the hello and here, the next reconnect triggers a fresh
  // pair-pending.
  //
  // Sent from `result.pairCode`, NOT re-read from storage. It used to fetch
  // back the record it had just written purely to get a value already in
  // scope, and a miss for any reason produced no frame and no log — while the
  // popup went on showing the code. `pendingKey` is
  // `${identityHash}:${scopeHash}`, so anything at that key carries this same
  // identity and therefore this same code; a stored one can only be equal, or
  // STALE if it was written under a previous extension identity. Reading it
  // back was pure downside, and it is the class of silent failure behind
  // chrischall/mcp-host#639, where four attempts each showed a code on screen
  // and reported `pairCode: null` to the MCP.
  try {
    const delivered = sendOnLink(
      link,
      JSON.stringify({
        type: 'pair-pending',
        mcpId: result.mcpId,
        pairCode: result.pairCode,
      }),
    );
    if (!delivered) {
      // `sendOnLink` answers false on a socket that is not OPEN, and the
      // caller used to discard that. An undelivered code left no trace
      // anywhere, so the MCP's timeout — whose hint blames a missing sign-in
      // — was the only thing anyone had to go on. Say it instead: this is the
      // one line that separates "the extension never asked" from "the user
      // never approved".
      console.warn(
        `[fetchproxy] pair-pending for ${result.mcpId} not delivered on ${link.label}: link not open. ` +
          `The pair code is in the popup; the MCP will report a timeout until it reconnects.`,
      );
    }
  } catch (e) {
    console.warn(`[fetchproxy] pair-pending send failed for ${result.mcpId}:`, e);
  }
}
