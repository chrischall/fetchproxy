/**
 * Background service worker for fetchproxy 0.2.0.
 *
 * Connects to one host MCP at ws://127.0.0.1:37149. The host multiplexes
 * all peer MCPs through that one pipe. Each MCP↔extension session has its
 * own AES-256-GCM session key derived via ECDH at handshake.
 *
 * 0.2.0 change: trust and the per-request allowlist key off `domains[]`
 * (a non-empty array) rather than a singular `domain`.
 *
 * handleServerHello (pure function below) is the security-critical decision
 * point: verify signature, look up trust, decide auto-trust vs pair-prompt vs
 * reject. The WS plumbing below routes frames to/from it and the popup.
 */

import {
  ed25519Verify,
  ed25519Sign,
  ecdhX25519,
  hkdfSha256,
  derivePairCodeFromIds,
  sha256,
  generateX25519,
  sealInnerFrame,
  openEncryptedFrame,
  validateFrame,
  toB64,
  fromB64,
  toHex,
  concatBytes,
  matchesDeclaredKey,
  undeclaredKeys,
  PROTOCOL_VERSION,
  HKDF_SESSION_INFO,
  type Capability,
  type CaptureHeaderDecl,
  type GraphqlOpDeclaration,
  type IndexedDbScopeDecl,
  type DomSelectorDecl,
  type StoragePointerDecl,
  type Frame,
  type HelloFrameFromServer,
  type HelloFrameFromExtension,
  type ReadyFrame,
  type InnerFrame,
  type InnerRequest,
  type InnerRequestFetch,
  type InnerRequestReadCookies,
  type InnerRequestWriteCookies,
  type WriteCookieDecl,
  type InnerRequestReadLocalStorage,
  type InnerRequestReadSessionStorage,
  type InnerRequestCaptureRequestHeader,
  type InnerRequestCaptureRedirect,
  type InnerRequestReadIndexedDb,
  type InnerRequestReadDom,
  type InnerRequestGraphqlQuery,
  type InnerRequestDownload,
  type DownloadResult,
  type EncryptedFrame,
} from '@fetchproxy/protocol';
import { TrustStore } from './trust-store.js';
import { SessionKeys } from './session-keys.js';
import { ensureDomainTab } from './ensure-domain-tab.js';
import {
  isUrlAllowedForAnyDomain,
  isTabUrlMatch,
  isTabUrlOnOrigin,
  cookieUrlFor,
} from './lib/url-match.js';
import { normalisePendingPair } from './lib/pending-pair.js';
import {
  scopeHash,
  intersectScope,
  isScopeSubset,
} from './lib/scope.js';
import { loadOrCreateExtensionIdentity, type ExtensionIdentity } from './extension-identity.js';
import { startKeepalive } from './keepalive.js';

// -------------------------------------------------------------------
// 1. Pure decision function (handleServerHello)
// -------------------------------------------------------------------

export interface HandleHelloDeps {
  trust: TrustStore;
  /**
   * 0.4.0+: the extension's long-term X25519 identity pub. Used to
   * derive the joint pair code (`SHA256(mcpPub || extPub)`) so the
   * popup and the MCP terminal both compute the same code. Required.
   */
  extensionIdentityX25519Pub: Uint8Array;
}

export type HandleHelloResult =
  | { kind: 'reject'; reason: string }
  | {
      kind: 'needs-pair';
      pairCode: string;
      identityHash: string;
      mcpId: string;
      serverName: string;
      domains: string[];
      capabilities: string[];
      cookieKeys: string[];
      localStorageKeys: string[];
      sessionStorageKeys: string[];
      captureHeaders: { host: string; path?: string; headerName: string }[];
      indexedDbScopes: IndexedDbScopeDecl[];
      domSelectors: DomSelectorDecl[];
      graphqlOps: GraphqlOpDeclaration[];
      localStoragePointers: StoragePointerDecl[];
      sessionStoragePointers: StoragePointerDecl[];
      version: string;
      identityX25519Pub: string;
      identityEd25519Pub: string;
      sessionNonce: Uint8Array;
      /**
       * 0.4.0+: the previously approved scope, when this is a re-pair
       * (a trust record exists but the scope changed). Used by the
       * popup to render an "update" diff rather than a fresh pair.
       * Absent on a brand-new pair.
       */
      previousScope?: {
        capabilities: string[];
        cookieKeys: string[];
        localStorageKeys: string[];
        sessionStorageKeys: string[];
        captureHeaders: { host: string; path?: string; headerName: string }[];
        indexedDbScopes: IndexedDbScopeDecl[];
        domSelectors: DomSelectorDecl[];
        graphqlOps: GraphqlOpDeclaration[];
        localStoragePointers: StoragePointerDecl[];
        sessionStoragePointers: StoragePointerDecl[];
      };
    }
  | {
      kind: 'auto-trust';
      mcpId: string;
      domains: string[];
      /**
       * The GRANTED (intersection of approved and declared) capabilities.
       * When declared ⊆ approved, this equals declared. When declared
       * grows beyond approved, this equals approved ∩ declared (a subset
       * of declared). The request handler MUST enforce these, not declared.
       */
      capabilities: string[];
      cookieKeys: string[];
      localStorageKeys: string[];
      sessionStorageKeys: string[];
      captureHeaders: { host: string; path?: string; headerName: string }[];
      indexedDbScopes: IndexedDbScopeDecl[];
      domSelectors: DomSelectorDecl[];
      graphqlOps: GraphqlOpDeclaration[];
      localStoragePointers: StoragePointerDecl[];
      sessionStoragePointers: StoragePointerDecl[];
      sessionKey: Uint8Array;
      extensionSessionPub: Uint8Array;
      /**
       * 0.4.0+: signing nonce (the MCP-side hello nonce). The caller
       * uses this together with the extension's per-WS nonce to
       * produce a `ReadyFrame.sessionSig`.
       */
      mcpSessionNonce: Uint8Array;
      /**
       * Part 2 (scope-growth): present when declared scope exceeds
       * approved scope. The caller should queue a non-blocking
       * `scope-update` offer so the user can Grant the wider scope
       * at their leisure. Absent when declared ⊆ approved.
       */
      pendingScopeUpdate?: {
        identityHash: string;
        declaredCapabilities: string[];
        declaredCookieKeys: string[];
        declaredLocalStorageKeys: string[];
        declaredSessionStorageKeys: string[];
        declaredCaptureHeaders: { host: string; path?: string; headerName: string }[];
        declaredIndexedDbScopes: IndexedDbScopeDecl[];
        declaredDomSelectors: DomSelectorDecl[];
        declaredGraphqlOps: GraphqlOpDeclaration[];
        declaredLocalStoragePointers: StoragePointerDecl[];
        declaredSessionStoragePointers: StoragePointerDecl[];
        approvedCapabilities: string[];
        approvedCookieKeys: string[];
        approvedLocalStorageKeys: string[];
        approvedSessionStorageKeys: string[];
        approvedCaptureHeaders: { host: string; path?: string; headerName: string }[];
        approvedIndexedDbScopes: IndexedDbScopeDecl[];
        approvedDomSelectors: DomSelectorDecl[];
        approvedGraphqlOps: GraphqlOpDeclaration[];
        approvedLocalStoragePointers: StoragePointerDecl[];
        approvedSessionStoragePointers: StoragePointerDecl[];
      };
    };

const enc = new TextEncoder();

/**
 * Order-insensitive equality for two domain lists. The trust record's
 * `domains` and the server hello's `domains` must declare the same set
 * (the user approved THIS set); a permutation is fine.
 */
function sameDomainSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const sa = [...a].map((s) => s.toLowerCase()).sort();
  const sb = [...b].map((s) => s.toLowerCase()).sort();
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
}

/** Default capability set when the server hello doesn't carry one. */
const DEFAULT_CAPABILITIES: readonly Capability[] = ['fetch'];

function effectiveCapabilities(hello: HelloFrameFromServer): Capability[] {
  return hello.capabilities && hello.capabilities.length > 0
    ? [...hello.capabilities]
    : [...DEFAULT_CAPABILITIES];
}

interface DeclaredScope {
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: { host: string; path?: string; headerName: string }[];
  indexedDbScopes: IndexedDbScopeDecl[];
  domSelectors: DomSelectorDecl[];
  graphqlOps: GraphqlOpDeclaration[];
  localStoragePointers: StoragePointerDecl[];
  sessionStoragePointers: StoragePointerDecl[];
}

function declaredScope(hello: HelloFrameFromServer): DeclaredScope {
  return {
    cookieKeys: [...(hello.cookieKeys ?? [])],
    localStorageKeys: [...(hello.localStorageKeys ?? [])],
    sessionStorageKeys: [...(hello.sessionStorageKeys ?? [])],
    captureHeaders: (hello.captureHeaders ?? []).map((d) => ({
      host: d.host,
      ...(d.path !== undefined ? { path: d.path } : {}),
      headerName: d.headerName,
    })),
    indexedDbScopes: (hello.indexedDbScopes ?? []).map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    })),
    domSelectors: (hello.domSelectors ?? []).map((d) => ({ ...d })),
    graphqlOps: (hello.graphqlOps ?? []).map((d) => ({
      name: d.name,
      operationName: d.operationName,
    })),
    localStoragePointers: (hello.localStoragePointers ?? []).map((d) => ({
      key: d.key,
      jsonPointer: d.jsonPointer,
    })),
    sessionStoragePointers: (hello.sessionStoragePointers ?? []).map((d) => ({
      key: d.key,
      jsonPointer: d.jsonPointer,
    })),
  };
}

export async function handleServerHello(
  hello: HelloFrameFromServer,
  deps: HandleHelloDeps,
): Promise<HandleHelloResult> {
  const identityX25519Pub = fromB64(hello.identityX25519Pub);
  const identityEd25519Pub = fromB64(hello.identityEd25519Pub);
  const sessionNonce = fromB64(hello.sessionNonce);
  const sessionSig = fromB64(hello.sessionSig);

  // 1. Verify signature.
  let sigOk = false;
  try {
    sigOk = await ed25519Verify(
      identityEd25519Pub,
      concatBytes(enc.encode(hello.mcpId), sessionNonce),
      sessionSig,
    );
  } catch {
    return { kind: 'reject', reason: 'sessionSig verification threw' };
  }
  if (!sigOk) return { kind: 'reject', reason: 'sessionSig invalid' };

  // 2. Look up trust.
  const hash = toHex(await sha256(identityX25519Pub));
  const record = await deps.trust.get(hash);
  const capabilities = effectiveCapabilities(hello);

  const scope = declaredScope(hello);

  if (record) {
    if (
      record.serverName !== hello.serverName ||
      !sameDomainSet(record.domains, hello.domains)
    ) {
      return { kind: 'reject', reason: 'serverName/domains mismatch with trust record' };
    }
    // 0.4.0: if the stored trust record's extension identity differs
    // from this extension's current identity, force re-pair. This
    // catches a wholesale extension reinstall as well as legacy 0.3.0
    // records (no extensionIdentityX25519Pub field, normalised to '').
    const recordedExtPubB64 = record.extensionIdentityX25519Pub ?? '';
    if (recordedExtPubB64 !== toB64(deps.extensionIdentityX25519Pub)) {
      // Fall through to needs-pair path.
    } else {
      // Part 2 (scope-growth): instead of blocking on any scope change,
      // compute the intersection of approved and declared scope. If
      // declared ⊆ approved, serve declared as-is (no change to the user).
      // If declared GROWS beyond approved, serve the intersection (approved
      // ∩ declared) so the MCP keeps working, and queue a non-blocking
      // `scope-update` offer so the user can grant the wider scope later.
      // Only changes to domains/serverName still force needs-pair (above).
      const approvedScope = {
        capabilities: [...record.capabilities],
        cookieKeys: [...(record.cookieKeys ?? [])],
        localStorageKeys: [...(record.localStorageKeys ?? [])],
        sessionStorageKeys: [...(record.sessionStorageKeys ?? [])],
        captureHeaders: (record.captureHeaders ?? []).map((d) => ({ ...d })),
        indexedDbScopes: (record.indexedDbScopes ?? []).map((d) => ({
          origin: d.origin,
          database: d.database,
          store: d.store,
          keys: [...d.keys],
        })),
        domSelectors: (record.domSelectors ?? []).map((d) => ({ ...d })),
        graphqlOps: (record.graphqlOps ?? []).map((d) => ({ ...d })),
        localStoragePointers: (record.localStoragePointers ?? []).map((d) => ({ ...d })),
        sessionStoragePointers: (record.sessionStoragePointers ?? []).map((d) => ({ ...d })),
      };
      const declaredScopeObj = { capabilities, ...scope };
      const granted = intersectScope(approvedScope, declaredScopeObj);
      const scopeGrew = !isScopeSubset(declaredScopeObj, approvedScope);
      // Derive session key with fresh ephemeral keypair.
      const ephemeral = await generateX25519();
      const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
      const sessionKey = await hkdfSha256(
        shared,
        sessionNonce,
        enc.encode(HKDF_SESSION_INFO),
        32,
      );
      return {
        kind: 'auto-trust',
        mcpId: hello.mcpId,
        domains: [...hello.domains],
        // GRANTED scope (intersection): never exceeds approved scope.
        capabilities: [...granted.capabilities],
        cookieKeys: [...granted.cookieKeys],
        localStorageKeys: [...granted.localStorageKeys],
        sessionStorageKeys: [...granted.sessionStorageKeys],
        captureHeaders: [...granted.captureHeaders],
        indexedDbScopes: [...granted.indexedDbScopes],
        domSelectors: [...granted.domSelectors],
        graphqlOps: [...granted.graphqlOps],
        localStoragePointers: [...granted.localStoragePointers],
        sessionStoragePointers: [...granted.sessionStoragePointers],
        sessionKey,
        extensionSessionPub: ephemeral.publicKey,
        mcpSessionNonce: sessionNonce,
        // Signal the caller to queue a scope-update offer only when growth occurred.
        ...(scopeGrew ? {
          pendingScopeUpdate: {
            identityHash: hash,
            declaredCapabilities: [...capabilities],
            declaredCookieKeys: [...scope.cookieKeys],
            declaredLocalStorageKeys: [...scope.localStorageKeys],
            declaredSessionStorageKeys: [...scope.sessionStorageKeys],
            declaredCaptureHeaders: scope.captureHeaders.map((d) => ({ ...d })),
            declaredIndexedDbScopes: scope.indexedDbScopes.map((d) => ({
              origin: d.origin,
              database: d.database,
              store: d.store,
              keys: [...d.keys],
            })),
            declaredDomSelectors: scope.domSelectors.map((d) => ({ ...d })),
            declaredGraphqlOps: scope.graphqlOps.map((d) => ({ ...d })),
            declaredLocalStoragePointers: scope.localStoragePointers.map((d) => ({ ...d })),
            declaredSessionStoragePointers: scope.sessionStoragePointers.map((d) => ({ ...d })),
            approvedCapabilities: [...approvedScope.capabilities],
            approvedCookieKeys: [...approvedScope.cookieKeys],
            approvedLocalStorageKeys: [...approvedScope.localStorageKeys],
            approvedSessionStorageKeys: [...approvedScope.sessionStorageKeys],
            approvedCaptureHeaders: approvedScope.captureHeaders.map((d) => ({ ...d })),
            approvedIndexedDbScopes: approvedScope.indexedDbScopes.map((d) => ({
              origin: d.origin,
              database: d.database,
              store: d.store,
              keys: [...d.keys],
            })),
            approvedDomSelectors: approvedScope.domSelectors.map((d) => ({ ...d })),
            approvedGraphqlOps: approvedScope.graphqlOps.map((d) => ({ ...d })),
            approvedLocalStoragePointers: approvedScope.localStoragePointers.map((d) => ({ ...d })),
            approvedSessionStoragePointers: approvedScope.sessionStoragePointers.map((d) => ({ ...d })),
          },
        } : {}),
      };
    }
  }

  // 3. Need pairing.
  const pairCode = await derivePairCodeFromIds(
    identityX25519Pub,
    deps.extensionIdentityX25519Pub,
  );
  return {
    kind: 'needs-pair',
    pairCode,
    identityHash: hash,
    mcpId: hello.mcpId,
    serverName: hello.serverName,
    domains: [...hello.domains],
    capabilities,
    ...scope,
    version: hello.version,
    identityX25519Pub: hello.identityX25519Pub,
    identityEd25519Pub: hello.identityEd25519Pub,
    sessionNonce,
  };
}

// -------------------------------------------------------------------
// 2. WS plumbing
// -------------------------------------------------------------------

const HOST_PORT = 37149;
const HOST_URL = `ws://127.0.0.1:${HOST_PORT}`;
const RECONNECT_BACKOFF_MS = [500, 1000, 2000, 5000, 10_000];
const PENDING_PAIR_KEY = 'pendingPair';
const APPROVED_PAIR_KEY = 'approvedPair';

declare const chrome: {
  runtime: {
    getManifest: () => { version: string };
    /**
     * Part 3: broadcast a message to all extension pages (e.g. open
     * popups). Used to notify the popup that the connected-session set
     * changed so it can re-render the status dots.
     */
    sendMessage?: (msg: unknown) => void;
    onMessage?: {
      addListener: (
        cb: (
          msg: unknown,
          _sender: unknown,
          sendResponse: (r: unknown) => void,
        ) => boolean | void,
      ) => void;
    };
  };
  storage: {
    local: {
      get: (k: string | string[]) => Promise<Record<string, unknown>>;
      set: (kv: Record<string, unknown>) => Promise<void>;
      remove: (k: string) => Promise<void>;
      onChanged: {
        addListener: (
          cb: (changes: Record<string, { newValue?: unknown; oldValue?: unknown }>) => void,
        ) => void;
      };
    };
  };
  tabs: {
    query: (q: { url?: string | string[] }) => Promise<{ id?: number; url?: string }[]>;
    create: (props: { url: string }) => Promise<{ id?: number; url?: string }>;
    sendMessage: (tabId: number, message: unknown) => Promise<unknown>;
  };
  cookies?: {
    get: (details: { url: string; name: string }) => Promise<ChromeCookie | null>;
    /**
     * 1.12.0+: needed by `write_cookies`. Attribute fields are optional
     * because a correct overwrite copies them off the existing cookie —
     * `domain` in particular must be OMITTED for a host-only cookie, which is
     * why the writer spreads it conditionally rather than passing undefined.
     */
    set: (details: {
      url: string;
      name: string;
      value: string;
      domain?: string;
      path?: string;
      secure?: boolean;
      httpOnly?: boolean;
      sameSite?: string;
      expirationDate?: number;
      storeId?: string;
    }) => Promise<unknown>;
  };
  webRequest?: {
    onBeforeSendHeaders: {
      addListener: (
        cb: (details: {
          requestId: string;
          url: string;
          method: string;
          requestHeaders?: { name: string; value?: string }[];
        }) => void,
        filter: { urls: string[] },
        extraInfoSpec?: string[],
      ) => void;
      removeListener: (cb: unknown) => void;
    };
    onBeforeRedirect: {
      addListener: (
        cb: (details: {
          requestId: string;
          url: string;
          method: string;
          redirectUrl: string;
        }) => void,
        filter: { urls: string[] },
      ) => void;
      removeListener: (cb: unknown) => void;
    };
  };
  downloads?: {
    download: (options: {
      url: string;
      filename?: string;
      conflictAction?: 'uniquify' | 'overwrite' | 'prompt';
      saveAs?: boolean;
    }) => Promise<number>;
    search: (query: { id: number }) => Promise<
      {
        id: number;
        filename: string;
        fileSize: number;
        state: 'in_progress' | 'interrupted' | 'complete';
        mime?: string;
        finalUrl?: string;
        error?: string;
      }[]
    >;
    erase: (query: { id: number }) => Promise<number[]>;
    onChanged: {
      addListener: (
        cb: (delta: { id: number; state?: { current: string }; error?: { current: string } }) => void,
      ) => void;
      removeListener: (cb: unknown) => void;
    };
  };
  alarms: typeof globalThis.chrome.alarms;
  action?: {
    setBadgeText: (details: { text: string }) => Promise<void> | void;
    setBadgeBackgroundColor: (details: { color: string }) => Promise<void> | void;
    openPopup?: () => Promise<void>;
  };
};

// -------------------------------------------------------------------
// 0.4.2: action badge + auto-popup attempt
//
// The pair flow used to surface only when the user manually opened
// the extension popup — easy to miss. Now we paint a red "!" badge
// on the toolbar icon whenever a pending pair is queued, and
// (best-effort) try `chrome.action.openPopup()` to surface it
// without the user having to click. The badge clears once the
// pending pair is removed (approved, dismissed, or trust landed).
//
// `openPopup()` is restricted: generally requires a recent user
// gesture and only available in Chrome 127+ from MV3 background.
// We swallow exceptions so unsupported environments still get the
// badge — the badge alone is enough to make the pending pair
// visible.
// -------------------------------------------------------------------

const BADGE_PAIR_PENDING_TEXT = '!';
const BADGE_PAIR_PENDING_COLOR = '#dc2626';
const BADGE_CONNECTED_COLOR = '#22c55e';
const BADGE_ACTIVE_COLOR = '#15803d';
const BADGE_DISCONNECTED_COLOR = '#f59e0b';

type ConnectionStatus = 'connected' | 'disconnected' | 'error';
let currentConnectionStatus: ConnectionStatus = 'disconnected';
let pairPendingActive = false;
let activityTimer: ReturnType<typeof setTimeout> | null = null;

function getAction(): {
  setBadgeText: (d: { text: string }) => Promise<void> | void;
  setBadgeBackgroundColor?: (d: { color: string }) => Promise<void> | void;
  openPopup?: () => Promise<void>;
} | null {
  const c = (globalThis as { chrome?: { action?: unknown } }).chrome;
  const action = c?.action as {
    setBadgeText: (d: { text: string }) => Promise<void> | void;
    setBadgeBackgroundColor?: (d: { color: string }) => Promise<void> | void;
    openPopup?: () => Promise<void>;
  } | undefined;
  if (!action || typeof action.setBadgeText !== 'function') return null;
  return action;
}

function setBadge(text: string, color: string): void {
  const action = getAction();
  if (!action) return;
  try {
    void action.setBadgeText({ text });
    if (typeof action.setBadgeBackgroundColor === 'function') {
      void action.setBadgeBackgroundColor({ color });
    }
  } catch (e) {
    console.warn('[fetchproxy] setBadge:', e);
  }
}

function syncBadge(): void {
  if (pairPendingActive) {
    setBadge(BADGE_PAIR_PENDING_TEXT, BADGE_PAIR_PENDING_COLOR);
    return;
  }
  switch (currentConnectionStatus) {
    case 'connected':
      setBadge(' ', BADGE_CONNECTED_COLOR);
      break;
    case 'disconnected':
      setBadge(' ', BADGE_DISCONNECTED_COLOR);
      break;
    case 'error':
      setBadge(' ', BADGE_PAIR_PENDING_COLOR);
      break;
  }
}

function setConnectionStatus(status: ConnectionStatus): void {
  currentConnectionStatus = status;
  syncBadge();
}

function flashActivity(): void {
  if (pairPendingActive) return;
  if (activityTimer) clearTimeout(activityTimer);
  setBadge(' ', BADGE_ACTIVE_COLOR);
  activityTimer = setTimeout(() => {
    activityTimer = null;
    syncBadge();
  }, 300);
}

function setPairPendingBadge(): void {
  pairPendingActive = true;
  setBadge(BADGE_PAIR_PENDING_TEXT, BADGE_PAIR_PENDING_COLOR);
  const action = getAction();
  if (!action) return;
  // Best-effort auto-open. Chrome 127+ MV3 allows openPopup() from
  // background in some contexts; otherwise it throws either sync
  // or async — both swallowed so the badge alone still wins.
  if (typeof action.openPopup === 'function') {
    try {
      void action.openPopup().catch(() => {
        /* expected in older Chrome / no-gesture contexts */
      });
    } catch {
      /* sync throw — older Chrome */
    }
  }
}

function clearPairPendingBadge(): void {
  pairPendingActive = false;
  syncBadge();
}

/**
 * Shared fields for all pending record kinds.
 * keyed by `${identityHash}:${scopeHash}` in `chrome.storage.local`.
 */
interface PendingRecordBase {
  /** `${identityHash}:${scopeHash}` — dict key. */
  key: string;
  identityHash: string;
  serverName: string;
  version: string;
  /** All MCP process IDs associated with this entry. */
  mcpIds: string[];
  domains: string[];
  identityX25519Pub: string;
  identityEd25519Pub: string;
}

/**
 * 0.6.0+: pending PAIR record. The MCP is not yet connected — the user
 * must approve before any session is established.
 *
 * Replacing the old `mcpId`-keyed shape so that concurrent processes sharing
 * the same identity + scope collapse into a single user-visible approval prompt.
 * The `mcpIds` array tracks every process waiting on this entry; `sessionNonces`
 * maps each process's nonce so the approval handler can drive per-process ECDH.
 */
interface PendingPairRecord extends PendingRecordBase {
  kind: 'pair';
  /**
   * Per-process hello nonce (b64). Used in session-key derivation after
   * approval. Each process sends its own hello with its own nonce.
   */
  sessionNonces: Record<string, string>;
  capabilities: string[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: { host: string; path?: string; headerName: string }[];
  /** 0.4.0+: declared IndexedDB scopes the user is being asked to approve. */
  indexedDbScopes: IndexedDbScopeDecl[];
  /** 1.4.0+: declared DOM selectors the user is being asked to approve. */
  domSelectors: DomSelectorDecl[];
  /** 1.x+: declared GraphQL operations the user is being asked to approve. */
  graphqlOps: GraphqlOpDeclaration[];
  /** 0.4.0+: declared storage-pointer extractions. */
  localStoragePointers: StoragePointerDecl[];
  sessionStoragePointers: StoragePointerDecl[];
  /**
   * 0.4.0+: previously approved scope (only present on re-pair).
   * Popup renders the diff vs the new scope.
   */
  previousScope?: {
    capabilities: string[];
    cookieKeys: string[];
    localStorageKeys: string[];
    sessionStorageKeys: string[];
    captureHeaders: { host: string; path?: string; headerName: string }[];
    indexedDbScopes: IndexedDbScopeDecl[];
    domSelectors: DomSelectorDecl[];
    graphqlOps: GraphqlOpDeclaration[];
    localStoragePointers: StoragePointerDecl[];
    sessionStoragePointers: StoragePointerDecl[];
  };
  pairCode: string;
}

/**
 * Part 2: non-blocking scope-update record. The MCP is already connected
 * (session live, granted = approved ∩ declared). This offers the user a
 * chance to widen the approved scope to cover the new declaration.
 *
 * [Grant] → trust.put with declared scope; no session restart needed.
 * [Keep as is] → dismiss: remove this entry, record the dismissed scopeHash
 *   so the same declared scope does not re-queue until it changes again.
 */
interface PendingScopeUpdateRecord extends PendingRecordBase {
  kind: 'scope-update';
  /** The FULL declared scope (what the MCP now wants). */
  capabilities: string[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: { host: string; path?: string; headerName: string }[];
  indexedDbScopes: IndexedDbScopeDecl[];
  domSelectors: DomSelectorDecl[];
  graphqlOps: GraphqlOpDeclaration[];
  localStoragePointers: StoragePointerDecl[];
  sessionStoragePointers: StoragePointerDecl[];
  /** The previously approved scope shown as the diff baseline. */
  previousScope: {
    capabilities: string[];
    cookieKeys: string[];
    localStorageKeys: string[];
    sessionStorageKeys: string[];
    captureHeaders: { host: string; path?: string; headerName: string }[];
    indexedDbScopes: IndexedDbScopeDecl[];
    domSelectors: DomSelectorDecl[];
    graphqlOps: GraphqlOpDeclaration[];
    localStoragePointers: StoragePointerDecl[];
    sessionStoragePointers: StoragePointerDecl[];
  };
}

export type AnyPendingRecord = PendingPairRecord | PendingScopeUpdateRecord;

/**
 * Apply a needs-pair record to a pending dict.
 *
 * Three cases:
 *  1. Key is occupied by another `pair` entry → collapse (dedup mcpId).
 *  2. Key is unoccupied → create a new `pair` entry.
 *  3. Key is occupied by a `scope-update` entry → the needs-pair supersedes it:
 *     trust is gone, so the scope-update offer is moot. Replace with a `pair`
 *     entry, unioning the mcpIds so every waiting process gets unblocked.
 *
 * Exported for unit testing; production callers use `onServerHello`.
 *
 * @internal
 */
export function applyNeedsPairRecord(
  existing: Record<string, AnyPendingRecord>,
  pendingKey: string,
  newRecord: PendingPairRecord,
): void {
  const currentEntry = existing[pendingKey];
  if (currentEntry && currentEntry.kind === 'pair') {
    // Case 1: Collapse — add this mcpId to the waiting set (dedup).
    const mcpId = newRecord.mcpIds[0]!;
    const nonce = newRecord.sessionNonces[mcpId]!;
    if (!currentEntry.mcpIds.includes(mcpId)) {
      currentEntry.mcpIds.push(mcpId);
    }
    currentEntry.sessionNonces[mcpId] = nonce;
  } else if (!currentEntry) {
    // Case 2: New entry.
    existing[pendingKey] = newRecord;
  } else {
    // Case 3: A scope-update sits at this key. The needs-pair supersedes it —
    // trust has been revoked, so the non-blocking scope-update offer is moot.
    // Replace with the pair record, unioning the mcpIds so every process
    // waiting on this identity (including those that drove the scope-update)
    // gets a prompt on the next approval.
    const inherited = currentEntry.mcpIds.filter((id) => !newRecord.mcpIds.includes(id));
    const mergedRecord: PendingPairRecord = {
      ...newRecord,
      mcpIds: [...inherited, ...newRecord.mcpIds],
    };
    // Carry over any session nonces already recorded for the inherited mcpIds.
    // (scope-update records don't have sessionNonces, so nothing to copy —
    // the inherited mcpIds will just be missing nonces, which is safe: the
    // approval handler skips mcpIds with missing nonces gracefully.)
    existing[pendingKey] = mergedRecord;
  }
}

let ws: WebSocket | null = null;
let reconnectAttempt = 0;
let trust: TrustStore | null = null;
let sessions: SessionKeys | null = null;
// 0.4.0+: the extension's long-term identity. Loaded once on boot via
// `loadOrCreateExtensionIdentity`, then threaded into every hello +
// every ready-frame signature. Generated on first run, persisted in
// chrome.storage.local across MV3 service-worker restarts.
let extIdentity: ExtensionIdentity | null = null;
// 0.4.0+: per-WS-connection nonce the extension sends in its hello.
// The MCP host's session signature on the corresponding ReadyFrame
// commits to (mcpNonce || extNonce), so a relay can neither replay
// nor substitute a different identity without producing a visibly
// different pair code.
let currentExtSessionNonce: Uint8Array | null = null;
// Track each mcpId's declared domain set so the request handler can enforce
// the allowlist. 0.2.0+: this is a Map<mcpId, string[]> rather than the
// 0.1.x Map<mcpId, string> — every URL must match SOME entry to be allowed.
const mcpDomains = new Map<string, string[]>();
// Track each mcpId's declared capability set so the request handler can
// reject verbs the MCP didn't ask for at pair time. 0.2.0+: defaults to
// ['fetch'] when the hello omits the field.
const mcpCapabilities = new Map<string, string[]>();
// 0.3.0+: per-mcpId declared scope tables. Each verb checks its inbound
// request against the matching table, so a misdeclared MCP can't escalate
// to keys / headers it didn't ask for at pair time.
const mcpCookieKeys = new Map<string, string[]>();
const mcpLocalStorageKeys = new Map<string, string[]>();
const mcpSessionStorageKeys = new Map<string, string[]>();
const mcpCaptureHeaders = new Map<string, { host: string; path?: string; headerName: string }[]>();
// 0.4.0+: per-mcpId declared IndexedDB scopes. The request handler
// gates `read_indexed_db` on subset-match against this table.
const mcpIndexedDbScopes = new Map<string, IndexedDbScopeDecl[]>();
// 1.4.0+: per-mcpId declared DOM selectors. The request handler gates
// `read_dom` on the declared name set against this table.
const mcpDomSelectors = new Map<string, DomSelectorDecl[]>();
// 1.x+: per-mcpId declared GraphQL operations. The request handler gates
// `graphql_query` on the declared name set (name -> operationName) against
// this table.
const mcpGraphqlOps = new Map<string, GraphqlOpDeclaration[]>();
// 0.4.0+: per-mcpId declared storage pointer decls. Storage-read
// handlers gate per-request pointer fields on these.
const mcpLocalStoragePointers = new Map<string, { key: string; jsonPointer: string }[]>();
const mcpSessionStoragePointers = new Map<string, { key: string; jsonPointer: string }[]>();
// Part 3: per-mcpId identity hash — set when a session is established
// (auto-trust or post-approval), cleared on session teardown. Used to
// expose the set of currently-connected identity hashes to the popup.
const mcpIdentityHash = new Map<string, string>();

export function connectedIdentityHashes(): Set<string> {
  return new Set(
    [...mcpIdentityHash.values()].filter((h): h is string => !!h),
  );
}

/**
 * The per-mcpId scope tables that gate inbound request verbs — a snapshot of
 * the `mcp*` maps the request handler consults. Computed from an approved
 * record and applied to a LIVE session so a granted scope-update takes effect
 * immediately, with no reconnect.
 */
export interface GrantedSessionScope {
  capabilities: string[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: { host: string; path?: string; headerName: string }[];
  indexedDbScopes: IndexedDbScopeDecl[];
  domSelectors: DomSelectorDecl[];
  graphqlOps: GraphqlOpDeclaration[];
  localStoragePointers: StoragePointerDecl[];
  sessionStoragePointers: StoragePointerDecl[];
}

/**
 * Build the granted scope tables from an approved record. Capabilities default
 * to `['fetch']` (defensive — older popup state could omit them). Deep-copies
 * arrays so later mutation of the record can't alias the live maps.
 */
export function grantedScopeFromApproval(
  approved: AnyPendingRecord,
): GrantedSessionScope {
  return {
    capabilities:
      approved.capabilities && approved.capabilities.length > 0
        ? [...approved.capabilities]
        : ['fetch'],
    cookieKeys: [...(approved.cookieKeys ?? [])],
    localStorageKeys: [...(approved.localStorageKeys ?? [])],
    sessionStorageKeys: [...(approved.sessionStorageKeys ?? [])],
    captureHeaders: (approved.captureHeaders ?? []).map((d) => ({ ...d })),
    indexedDbScopes: (approved.indexedDbScopes ?? []).map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    })),
    domSelectors: (approved.domSelectors ?? []).map((d) => ({ ...d })),
    graphqlOps: (approved.graphqlOps ?? []).map((d) => ({ ...d })),
    localStoragePointers: (approved.localStoragePointers ?? []).map((d) => ({ ...d })),
    sessionStoragePointers: (approved.sessionStoragePointers ?? []).map((d) => ({ ...d })),
  };
}

/**
 * Write a granted scope onto the live per-mcpId maps the request handler reads.
 * Idempotent; overwrites any prior scope for `mcpId`. Used both at
 * session establishment (post-pair) and when a scope-update is granted on an
 * already-connected session — the latter is what makes a widened grant take
 * effect without a reconnect.
 */
export function applyGrantedScopeToSession(
  mcpId: string,
  scope: GrantedSessionScope,
): void {
  mcpCapabilities.set(mcpId, [...scope.capabilities]);
  mcpCookieKeys.set(mcpId, [...scope.cookieKeys]);
  mcpLocalStorageKeys.set(mcpId, [...scope.localStorageKeys]);
  mcpSessionStorageKeys.set(mcpId, [...scope.sessionStorageKeys]);
  mcpCaptureHeaders.set(mcpId, scope.captureHeaders.map((d) => ({ ...d })));
  mcpIndexedDbScopes.set(
    mcpId,
    scope.indexedDbScopes.map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    })),
  );
  mcpDomSelectors.set(mcpId, scope.domSelectors.map((d) => ({ ...d })));
  mcpGraphqlOps.set(mcpId, scope.graphqlOps.map((d) => ({ ...d })));
  mcpLocalStoragePointers.set(mcpId, scope.localStoragePointers.map((d) => ({ ...d })));
  mcpSessionStoragePointers.set(mcpId, scope.sessionStoragePointers.map((d) => ({ ...d })));
}

/**
 * Read back the live granted scope for `mcpId`, or `undefined` if no session
 * scope is recorded. Exported for tests + diagnostics.
 */
export function sessionScopeSnapshot(mcpId: string): GrantedSessionScope | undefined {
  const capabilities = mcpCapabilities.get(mcpId);
  if (!capabilities) return undefined;
  return {
    capabilities: [...capabilities],
    cookieKeys: [...(mcpCookieKeys.get(mcpId) ?? [])],
    localStorageKeys: [...(mcpLocalStorageKeys.get(mcpId) ?? [])],
    sessionStorageKeys: [...(mcpSessionStorageKeys.get(mcpId) ?? [])],
    captureHeaders: (mcpCaptureHeaders.get(mcpId) ?? []).map((d) => ({ ...d })),
    indexedDbScopes: (mcpIndexedDbScopes.get(mcpId) ?? []).map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    })),
    domSelectors: (mcpDomSelectors.get(mcpId) ?? []).map((d) => ({ ...d })),
    graphqlOps: (mcpGraphqlOps.get(mcpId) ?? []).map((d) => ({ ...d })),
    localStoragePointers: (mcpLocalStoragePointers.get(mcpId) ?? []).map((d) => ({ ...d })),
    sessionStoragePointers: (mcpSessionStoragePointers.get(mcpId) ?? []).map((d) => ({ ...d })),
  };
}

/**
 * Compute the live-scope applications for a granted approval. Only
 * `scope-update` records target already-connected sessions (a `pair` approval
 * establishes its sessions separately, with rekey + ReadyFrame). Filters to the
 * subset of the record's mcpIds that are currently live, so a session that
 * disconnected between the offer and the grant is skipped.
 */
export function liveScopeApplications(
  approved: AnyPendingRecord,
  isLive: (mcpId: string) => boolean,
): { mcpId: string; scope: GrantedSessionScope }[] {
  if (approved.kind !== 'scope-update') return [];
  const scope = grantedScopeFromApproval(approved);
  return (approved.mcpIds ?? [])
    .filter((mcpId) => isLive(mcpId))
    .map((mcpId) => ({ mcpId, scope }));
}

/** Part 3: notify any open popup that the connected-session set changed. */
function broadcastConnectionsChanged(): void {
  const c = (globalThis as { chrome?: { runtime?: { sendMessage?: (m: unknown) => void } } }).chrome;
  try {
    c?.runtime?.sendMessage?.({ type: 'connections-changed' });
  } catch {
    // No listeners (popup closed) — ignore the error Chrome throws.
  }
}

function connect(): void {
  if (!trust || !sessions || !extIdentity) return;
  if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) return;
  ws = new WebSocket(HOST_URL);
  ws.addEventListener('open', () => {
    if (!extIdentity) return;
    reconnectAttempt = 0;
    setConnectionStatus('connected');
    // Fresh per-WS nonce. The corresponding ready-frame signature
    // commits to (mcpHelloNonce || this nonce), so each WS connect
    // gets a fresh handshake — replaying a captured ready frame
    // against a future connection fails.
    const sessionNonce = new Uint8Array(32);
    (globalThis.crypto as Crypto).getRandomValues(sessionNonce);
    currentExtSessionNonce = sessionNonce;
    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: PROTOCOL_VERSION,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: chrome.runtime.getManifest().version,
      identityX25519Pub: toB64(extIdentity.x25519Pub),
      identityEd25519Pub: toB64(extIdentity.ed25519Pub),
      sessionNonce: toB64(sessionNonce),
    };
    ws!.send(JSON.stringify(extHello));
  });
  ws.addEventListener('message', (ev: MessageEvent) => {
    void onMessage(ev.data as string).catch((e) => console.error('[fetchproxy] onMessage:', e));
  });
  ws.addEventListener('close', () => {
    setConnectionStatus('disconnected');
    sessions?.clear();
    mcpDomains.clear();
    mcpCapabilities.clear();
    mcpCookieKeys.clear();
    mcpLocalStorageKeys.clear();
    mcpSessionStorageKeys.clear();
    mcpCaptureHeaders.clear();
    mcpIndexedDbScopes.clear();
    mcpDomSelectors.clear();
    mcpGraphqlOps.clear();
    mcpLocalStoragePointers.clear();
    mcpSessionStoragePointers.clear();
    // Part 3: clear identity hash map on teardown.
    mcpIdentityHash.clear();
    broadcastConnectionsChanged();
    scheduleReconnect();
  });
  ws.addEventListener('error', () => {
    /* close will follow */
  });
}

function scheduleReconnect(): void {
  const ms = RECONNECT_BACKOFF_MS[Math.min(reconnectAttempt, RECONNECT_BACKOFF_MS.length - 1)]!;
  reconnectAttempt++;
  setTimeout(connect, ms);
}

async function onMessage(data: string): Promise<void> {
  if (!trust) return;
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

async function onServerHello(hello: HelloFrameFromServer): Promise<void> {
  if (!trust || !sessions || !extIdentity || !currentExtSessionNonce) return;
  const result = await handleServerHello(hello, {
    trust,
    extensionIdentityX25519Pub: extIdentity.x25519Pub,
  });
  if (result.kind === 'reject') {
    console.warn(`[fetchproxy] rejected hello for ${hello.mcpId}: ${result.reason}`);
    return;
  }
  if (result.kind === 'auto-trust') {
    // Store GRANTED (intersection) scope in the mcp* maps. `result` carries the
    // already-intersected scope (granted = approved ∩ declared), so applying it
    // verbatim never escalates beyond approval.
    sessions.set(result.mcpId, result.sessionKey);
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
    // host can verify before proceeding.
    const sessionSig = await ed25519Sign(
      extIdentity.ed25519Priv,
      concatBytes(result.mcpSessionNonce, currentExtSessionNonce),
    );
    const ready: ReadyFrame = {
      type: 'ready',
      mcpId: result.mcpId,
      extensionSessionPub: toB64(result.extensionSessionPub),
      sessionSig: toB64(sessionSig),
    };
    ws?.send(JSON.stringify(ready));

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
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      // Look up the (possibly just-updated) entry to get the pairCode.
      const got = await chrome.storage.local.get(PENDING_PAIR_KEY);
      const dict = mergePending(got[PENDING_PAIR_KEY]);
      const entry = dict[pendingKey];
      if (entry && entry.kind === 'pair') {
        ws.send(
          JSON.stringify({
            type: 'pair-pending',
            mcpId: result.mcpId,
            pairCode: entry.pairCode,
          }),
        );
      }
    } catch (e) {
      console.warn('[fetchproxy] pair-pending send failed:', e);
    }
  }
}

/**
 * Local alias bound to this file's `AnyPendingRecord`. The shared
 * helper in `./lib/pending-pair.ts` is generic so the popup can use it
 * against its own structurally-compatible interface without a circular
 * dependency on this file's exact type.
 */
function mergePending(stored: unknown): Record<string, AnyPendingRecord> {
  return normalisePendingPair<AnyPendingRecord>(stored);
}

/**
 * 0.5.2+: serialise reads-then-writes of the pendingPair storage key.
 *
 * Two `onServerHello` invocations from concurrent peer hellos (or an
 * `onApproval` interleaving with an `onServerHello`) would otherwise race
 * the `get → set` pair and one of the entries would silently disappear:
 * both reads see the same starting state, both writes resolve to that
 * state plus their own entry, and whichever set lands second wins. The
 * window is narrow on a real SW (event-loop microtasks), but `await`
 * boundaries are exactly where Chrome can interleave other callbacks.
 *
 * `pendingPairLock` is a tail-promise chain: every mutation appends a
 * function that runs after the previous one resolves, so the read and
 * the write for a single logical update happen back-to-back without any
 * other mutation slipping between. Errors are swallowed on the chain
 * itself (logged at the call site) so one failure can't permanently
 * jam the queue.
 */
let pendingPairLock: Promise<unknown> = Promise.resolve();

function withPendingPairLock<T>(fn: () => Promise<T>): Promise<T> {
  const next = pendingPairLock.then(fn, fn);
  pendingPairLock = next.catch(() => undefined);
  return next;
}

async function onEncryptedFrame(frame: EncryptedFrame): Promise<void> {
  if (!sessions) return;
  const entry = sessions.get(frame.mcpId);
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

async function sendInner(mcpId: string, inner: InnerFrame): Promise<void> {
  if (!sessions) return;
  const entry = sessions.get(mcpId);
  if (!entry || !ws || ws.readyState !== WebSocket.OPEN) return;
  const sealed = await sealInnerFrame(entry.sessionKey, mcpId, entry.nextOutboundSeq(), inner);
  ws.send(JSON.stringify(sealed));
}

/** The subset of `chrome.cookies.Cookie` the writer reads back off an
 *  existing cookie in order to overwrite it in place rather than shadow it. */
export interface ChromeCookie {
  name: string;
  value: string;
  domain: string;
  hostOnly: boolean;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  expirationDate?: number;
  storeId?: string;
}

async function handleRequest(mcpId: string, req: InnerRequest): Promise<void> {
  const domains = mcpDomains.get(mcpId);
  if (!domains || domains.length === 0) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      error: 'no domains for mcpId',
    });
    return;
  }
  const capabilities = mcpCapabilities.get(mcpId) ?? ['fetch'];
  // The `graphql_query` verb is the one op whose wire string differs from its
  // capability string — it is governed by the `graphql` capability. Every
  // other op's capability equals its op name.
  const requiredCapability = req.op === 'graphql_query' ? 'graphql' : req.op;
  if (!capabilities.includes(requiredCapability)) {
    // Capability gate. The MCP didn't ask for this verb at pair time —
    // refuse with an op-echoing error so the server-side awaiter can
    // surface a clear message rather than blame the transport.
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: req.op,
      error: `capability ${JSON.stringify(requiredCapability)} not granted (declared: [${capabilities.join(', ')}])`,
    });
    return;
  }
  if (req.op === 'fetch') {
    await handleFetchRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'read_cookies') {
    await handleReadCookiesRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'write_cookies') {
    await handleWriteCookiesRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'read_local_storage') {
    await handleReadStorageRequest(mcpId, req, domains, 'local');
    return;
  }
  if (req.op === 'read_session_storage') {
    await handleReadStorageRequest(mcpId, req, domains, 'session');
    return;
  }
  if (req.op === 'capture_request_header') {
    await handleCaptureRequestHeaderRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'capture_redirect') {
    await handleCaptureRedirectRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'read_indexed_db') {
    await handleReadIndexedDbRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'read_dom') {
    await handleReadDomRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'graphql_query') {
    await handleGraphqlQueryRequest(mcpId, req, domains);
    return;
  }
  if (req.op === 'download') {
    await handleDownloadRequest(mcpId, req, domains);
    return;
  }
}

async function handleFetchRequest(
  mcpId: string,
  req: InnerRequestFetch,
  domains: string[],
): Promise<void> {
  if (!isUrlAllowedForAnyDomain(req.init.url, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      error: `url ${req.init.url} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  // 0.5.2+: iterate ALL matching tabs instead of `.find()`-ing the first
  // one. Chrome doesn't retroactively inject content scripts into pages
  // that were already loaded when the extension was (re)installed —
  // those tabs match the URL but `sendMessage` to them throws "Receiving
  // end does not exist". Before this loop, the first such pre-reload tab
  // returned by `chrome.tabs.query` would shadow any subsequent
  // freshly-loaded tab that DOES have the content script, and every
  // fetch failed even though a working tab existed.
  const result = await sendToFirstResponsiveTab(
    (tabUrl) => isTabUrlMatch(tabUrl, req.init.tabUrl),
    (tabUrl) => ({
      kind: 'fetchproxy-fetch',
      init: { ...req.init, tabUrl },
    }),
    req.init.tabUrl,
  );
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      error: `tab fetch failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as
    | { ok: true; status: number; url: string; body: string }
    | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'fetch',
      status: resp.status,
      url: resp.url,
      body: resp.body,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      error: resp.error,
    });
  }
}

/**
 * 0.5.2+: walk every tab whose URL passes `matcher`, send the built
 * message via `chrome.tabs.sendMessage`, and return the first response.
 *
 * Three terminal states:
 *
 *   - `{ kind: 'response', response, tabUrl }` — a tab's content script
 *     replied (the body is the content script's typed payload, opaque
 *     to this helper; caller knows the shape).
 *   - `{ kind: 'no-tab', error }` — either no tab matched, or every
 *     matched tab threw "Receiving end does not exist" (i.e., none of
 *     them have a loaded content script — the caller's `tabUrl` is
 *     surfaced in the error so the user knows which page to refresh).
 *   - `{ kind: 'throw', error }` — one of the matched tabs threw a
 *     non-receiving-end error. Surfaced verbatim so the caller can
 *     wrap it in a verb-specific error message; iteration stops at the
 *     first such throw since it likely indicates a real fault rather
 *     than a missing content script.
 *
 * `buildMessage` is called per-tab so the message can carry the matched
 * tab's resolved URL (useful for verbs that need to canonicalise their
 * tabUrl against the actual tab). The caller controls the matcher so
 * each verb can choose between strict-prefix (`isTabUrlMatch`) and
 * host-or-subdomain (`isTabUrlOnOrigin`) semantics.
 */
export type SendToFirstResponsiveTabResult =
  | { kind: 'response'; response: unknown; tabUrl: string }
  | { kind: 'no-tab'; error: string }
  | { kind: 'throw'; error: string };

// Exported for unit testing; not surfaced from `./index.ts` because
// production callers (extension-chrome, extension-safari) have no
// reason to invoke it directly — the handlers in this file are the
// only callsites.
export async function sendToFirstResponsiveTab(
  matcher: (tabUrl: string) => boolean,
  buildMessage: (matchedTabUrl: string) => unknown,
  tabUrlForError: string,
): Promise<SendToFirstResponsiveTabResult> {
  const tabs = await chrome.tabs.query({});
  // Fold the ID check into the filter so `matches.length` accurately
  // reflects the count of tabs we'll actually try — without this, a tab
  // with `undefined` id would inflate the count and the error message
  // would claim "N URL matches, none responded" when one of those N
  // was never even attempted.
  const matches = tabs.filter(
    (t) => typeof t.id === 'number' && t.url && matcher(t.url),
  );
  if (matches.length === 0) {
    return { kind: 'no-tab', error: `no tab matching ${tabUrlForError}` };
  }
  // "Receiving end does not exist" surfaces when a tab matches the URL
  // but has no content script (typically post-reload pages that pre-date
  // the current extension install). Skip those and try the next match —
  // self-heals the common "extension reloaded, old tabs still open" case
  // without the user having to refresh every pre-reload tab.
  let lastNoListener: string | null = null;
  for (const match of matches) {
    // `match.id` is guaranteed `number` by the filter above, but the
    // chrome typings still type it as `number | undefined` so we use a
    // non-null narrowing here. The filter is the authority.
    const id = match.id as number;
    const tabUrl = match.url ?? tabUrlForError;
    try {
      const response = await chrome.tabs.sendMessage(id, buildMessage(tabUrl));
      return { kind: 'response', response, tabUrl };
    } catch (e) {
      const msg = String(e);
      if (msg.includes('Receiving end does not exist')) {
        lastNoListener = msg;
        continue;
      }
      return { kind: 'throw', error: msg };
    }
  }
  return {
    kind: 'no-tab',
    error:
      `no tab matching ${tabUrlForError} has the fetchproxy content script loaded ` +
      `(${matches.length} URL match${matches.length === 1 ? '' : 'es'}, none responded). ` +
      `Refresh the page in your browser to inject the content script, then retry.` +
      (lastNoListener ? ` Last error: ${lastNoListener}` : ''),
  };
}

async function handleReadCookiesRequest(
  mcpId: string,
  req: InnerRequestReadCookies,
  domains: string[],
): Promise<void> {
  // Two shapes: legacy 0.2.0 `{ tabUrl }` (returns raw document.cookie via
  // content script) vs new 0.3.0 `{ origin, keys }` (returns a values map
  // via chrome.cookies.get, which is HttpOnly-visible). Narrow on which
  // field is present — the validator already guaranteed it's one or the
  // other, not both.
  if ('tabUrl' in req.init) {
    await handleReadCookiesLegacy(mcpId, req.id, req.init.tabUrl, domains);
    return;
  }
  const cookieKeys = mcpCookieKeys.get(mcpId) ?? [];
  await handleReadCookiesV3(
    mcpId,
    req.id,
    req.init.origin,
    req.init.keys,
    domains,
    cookieKeys,
    req.init.path,
  );
}

async function handleReadCookiesLegacy(
  mcpId: string,
  id: number,
  tabUrl: string,
  domains: string[],
): Promise<void> {
  if (!isUrlAllowedForAnyDomain(tabUrl, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: `tabUrl ${tabUrl} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  // 0.5.2+: multi-tab fallback via `sendToFirstResponsiveTab` — see the
  // helper's doc for the per-tab iteration rationale (in short: a
  // pre-reload tab can shadow a fresh one if we only `.find()` the
  // first match).
  const result = await sendToFirstResponsiveTab(
    (t) => isTabUrlMatch(t, tabUrl),
    () => ({ kind: 'fetchproxy-read-cookies' }),
    tabUrl,
  );
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: `tab read_cookies failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as { ok: true; cookies: string } | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: true,
      op: 'read_cookies',
      cookies: resp.cookies,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: resp.error,
    });
  }
}

async function handleReadCookiesV3(
  mcpId: string,
  id: number,
  origin: string,
  keys: string[],
  domains: string[],
  declaredCookieKeys: string[],
  path?: string,
): Promise<void> {
  // Origin must be in declared domain set. Checked on the BARE origin, before
  // any path is appended — the gate is about which host we may read, and a
  // path must never be able to influence that decision.
  if (!isUrlAllowedForAnyDomain(origin, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: `origin ${origin} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  // Every requested key must be in the declared cookieKeys set. This is
  // gate #2 (the server-side has its own gate #1) — defense in depth.
  // 0.4.0: declared keys may include trailing-* glob patterns; route
  // through the shared `matchesDeclaredKey` helper so the extension
  // and server agree on what counts as "in the declared set".
  const undeclared = undeclaredKeys(keys, declaredCookieKeys);
  if (undeclared.length > 0) {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: `cookie keys not in declared set: ${undeclared.join(', ')}`,
    });
    return;
  }
  if (!chrome.cookies) {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: 'chrome.cookies API not available (extension missing the "cookies" permission?)',
    });
    return;
  }
  // Probe each requested key through chrome.cookies.get. This is the HttpOnly-
  // visible path — that's the whole reason 0.3.0 exists. Missing keys are
  // omitted from the response (no nulls), matching the contract.
  const values: Record<string, string> = {};
  for (const key of keys) {
    try {
      const got = await chrome.cookies.get({ url: cookieUrlFor(origin, path), name: key });
      if (got && typeof got.value === 'string') {
        values[key] = got.value;
      }
    } catch {
      // ignore individual cookie failure; missing key just stays absent
    }
  }
  await sendInner(mcpId, {
    type: 'response',
    id,
    ok: true,
    op: 'read_cookies',
    values,
  });
}

/**
 * The gate half of `write_cookies`, factored out (mirrors
 * `resolveReadDomRequest`) so the security decisions are unit-testable without
 * the module's live WS/session state.
 *
 * Refuses the WHOLE request rather than filtering it down: a rotation applied
 * to some of its cookies leaves the session in a state neither side expects,
 * which is worse than not writing at all.
 */
export function resolveWriteCookiesRequest(
  req: InnerRequestWriteCookies,
  domains: string[],
  declaredCookieKeys: string[],
): { ok: true } | { ok: false; error: string } {
  // Decided on the BARE origin, before any path is appended — the gate is
  // about which host we may write, and a path must never influence it.
  if (!isUrlAllowedForAnyDomain(req.init.origin, domains)) {
    return {
      ok: false,
      error: `origin ${req.init.origin} not in domains [${domains.join(', ')}]`,
    };
  }
  // Gate #2. Writes can never reach a cookie the MCP was not already trusted
  // to read, so granting `write_cookies` cannot widen WHICH cookies are in
  // play — only what may be done to the ones the user already approved.
  const undeclared = undeclaredKeys(
    req.init.cookies.map((c) => c.name),
    declaredCookieKeys,
  );
  if (undeclared.length > 0) {
    return { ok: false, error: `cookie keys not in declared set: ${undeclared.join(', ')}` };
  }
  return { ok: true };
}

/**
 * Build the `chrome.cookies.set` payload that OVERWRITES `existing` rather
 * than shadowing it.
 *
 * Passing only `{url, name, value}` looks like it works and quietly creates a
 * SECOND cookie: Chrome derives a host-only, non-HttpOnly, default-path cookie
 * from the URL, which does not replace a `Domain=`-scoped or HttpOnly
 * original. The site keeps reading the stale one — precisely the silent
 * failure this verb exists to prevent. So every attribute is copied off the
 * cookie being replaced.
 *
 * Two fields must be OMITTED rather than passed as undefined:
 *   - `domain` on a host-only cookie, which Chrome would otherwise read as a
 *     request to widen it into a domain cookie;
 *   - `expirationDate` on a session cookie, which would otherwise turn a
 *     persistent cookie into a session one.
 */
export function cookieSetDetailsFor(
  url: string,
  decl: WriteCookieDecl,
  existing: ChromeCookie,
): {
  url: string; name: string; value: string; domain?: string; path?: string;
  secure?: boolean; httpOnly?: boolean; sameSite?: string; expirationDate?: number;
  storeId?: string;
} {
  return {
    url,
    name: decl.name,
    value: decl.value,
    ...(existing.hostOnly ? {} : { domain: existing.domain }),
    path: existing.path,
    secure: existing.secure,
    httpOnly: existing.httpOnly,
    sameSite: existing.sameSite,
    ...(existing.expirationDate === undefined ? {} : { expirationDate: existing.expirationDate }),
    storeId: existing.storeId,
  };
}

/**
 * 1.12.0+: overwrite the value of cookies the MCP is already trusted to read.
 *
 * The only write path in the bridge. It exists because sites that ROTATE a
 * credential cookie otherwise sign the user out of their own browser: the MCP
 * refreshes, the site issues a new value, and the copy in the cookie jar is
 * dead. Reading cannot repair that.
 *
 * Three gates, in order, all refusing the WHOLE request rather than applying
 * part of it — a half-written rotation is worse than a failed one:
 *
 *  1. origin must be in the declared domain set (checked on the bare origin,
 *     before any path, so a path can never influence the decision);
 *  2. every name must be in the declared `cookieKeys` — writes cannot reach a
 *     cookie the user did not already approve for reading;
 *  3. every named cookie must already EXIST. This verb refreshes a value in
 *     place; it does not author new cookies. Refusing here is what keeps a
 *     write capability from becoming a cookie-injection primitive.
 *
 * The existing cookie's attributes are copied onto the write. Passing only
 * `{url, name, value}` would look like it worked and quietly create a SECOND
 * cookie — Chrome derives a host-only, non-HttpOnly, default-path cookie from
 * the URL, which does not replace a `Domain=`-scoped or HttpOnly original. The
 * site would keep reading the stale one, which is exactly the silent failure
 * this verb exists to prevent. `hostOnly` decides whether `domain` may be sent
 * at all: Chrome rejects `domain` on a host-only cookie.
 */
async function handleWriteCookiesRequest(
  mcpId: string,
  req: InnerRequestWriteCookies,
  domains: string[],
): Promise<void> {
  const { origin, path, cookies } = req.init;
  const fail = async (error: string): Promise<void> => {
    await sendInner(mcpId, { type: 'response', id: req.id, ok: false, op: 'write_cookies', error });
  };
  const gate = resolveWriteCookiesRequest(req, domains, mcpCookieKeys.get(mcpId) ?? []);
  if (!gate.ok) {
    await fail(gate.error);
    return;
  }
  if (!chrome.cookies) {
    await fail('chrome.cookies API not available (extension missing the "cookies" permission?)');
    return;
  }
  const url = cookieUrlFor(origin, path);
  // Resolve every target first, so an absent cookie aborts before anything is
  // written rather than halfway through.
  const targets: { decl: WriteCookieDecl; existing: ChromeCookie }[] = [];
  const missing: string[] = [];
  for (const decl of cookies) {
    let existing: ChromeCookie | null = null;
    try {
      existing = await chrome.cookies.get({ url, name: decl.name });
    } catch {
      existing = null;
    }
    if (existing) targets.push({ decl, existing });
    else missing.push(decl.name);
  }
  if (missing.length > 0) {
    await fail(
      `cookies not present to overwrite: ${missing.join(', ')} — write_cookies refreshes an ` +
        'existing value, it does not create cookies',
    );
    return;
  }
  const written: string[] = [];
  for (const { decl, existing } of targets) {
    try {
      await chrome.cookies.set(cookieSetDetailsFor(url, decl, existing));
      written.push(decl.name);
    } catch (e) {
      await fail(`failed to write cookie ${decl.name}: ${String(e)}`);
      return;
    }
  }
  await sendInner(mcpId, {
    type: 'response',
    id: req.id,
    ok: true,
    op: 'write_cookies',
    written,
  });
}

async function handleReadStorageRequest(
  mcpId: string,
  req: InnerRequestReadLocalStorage | InnerRequestReadSessionStorage,
  domains: string[],
  bucket: 'local' | 'session',
): Promise<void> {
  const op = req.op;
  // Pick the right declared-keys table by capability.
  const declaredKeys =
    bucket === 'local'
      ? (mcpLocalStorageKeys.get(mcpId) ?? [])
      : (mcpSessionStorageKeys.get(mcpId) ?? []);
  const declaredPointers =
    bucket === 'local'
      ? (mcpLocalStoragePointers.get(mcpId) ?? [])
      : (mcpSessionStoragePointers.get(mcpId) ?? []);
  if (!isUrlAllowedForAnyDomain(req.init.origin, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op,
      error: `origin ${req.init.origin} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  // 0.4.0: declared keys may include trailing-* glob patterns.
  const undeclared = undeclaredKeys(req.init.keys, declaredKeys);
  if (undeclared.length > 0) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op,
      error: `${bucket}Storage keys not in declared set: ${undeclared.join(', ')}`,
    });
    return;
  }
  // 0.4.0: per-request pointers must each match a declared pair.
  if (req.init.pointers) {
    for (const [outputKey, p] of Object.entries(req.init.pointers)) {
      const match = declaredPointers.find(
        (d) => d.key === p.storageKey && d.jsonPointer === p.jsonPointer,
      );
      if (!match) {
        await sendInner(mcpId, {
          type: 'response',
          id: req.id,
          ok: false,
          op,
          error: `${bucket}Storage pointer (${p.storageKey}, ${p.jsonPointer}) not in declared set [outputKey=${outputKey}]`,
        });
        return;
      }
    }
  }
  // 0.4.1+: match by host-or-subdomain rather than strict prefix.
  // Apex origins (e.g. `https://hbportal.co`) routinely come from
  // multi-vendor MCPs whose real tabs live on a vendor subdomain.
  //
  // 0.5.2+: multi-tab fallback via `sendToFirstResponsiveTab` so a
  // pre-reload tab doesn't shadow a freshly-loaded one with the content
  // script — see the helper's doc.
  const result = await sendToFirstResponsiveTab(
    (t) => isTabUrlOnOrigin(t, req.init.origin),
    () => ({
      kind: bucket === 'local' ? 'fetchproxy-read-local-storage' : 'fetchproxy-read-session-storage',
      keys: [...req.init.keys],
      pointers: req.init.pointers,
    }),
    `origin ${req.init.origin}`,
  );
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op,
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op,
      error: `tab ${op} failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as
    | { ok: true; values: Record<string, string> }
    | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op,
      values: resp.values,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op,
      error: resp.error,
    });
  }
}

/**
 * extraInfoSpec for the capture_request_header webRequest listener.
 * `'extraHeaders'` is REQUIRED: Chrome MV3 strips `Cookie` (and other
 * sensitive headers like `Authorization`) from `onBeforeSendHeaders`
 * details unless it is present — without it, a capture for `cookie` can
 * never match and times out. Exported so a regression test pins it.
 */
export const CAPTURE_EXTRA_INFO_SPEC = ['requestHeaders', 'extraHeaders'] as const;

async function handleCaptureRequestHeaderRequest(
  mcpId: string,
  req: InnerRequestCaptureRequestHeader,
  domains: string[],
): Promise<void> {
  const declared = mcpCaptureHeaders.get(mcpId) ?? [];
  const reqPath = req.init.path ?? '/*';
  const declaredMatch = declared.find(
    (d) =>
      d.host === req.init.host &&
      (d.path ?? '/*') === reqPath &&
      d.headerName === req.init.headerName,
  );
  if (!declaredMatch) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_request_header',
      error: `(host, path, headerName) not in declared captureHeaders`,
    });
    return;
  }
  // The capture host must be a declared domain or a subdomain of one.
  const host = req.init.host;
  if (!isUrlAllowedForAnyDomain(`https://${host}/`, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_request_header',
      error: `capture host ${host} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  if (!chrome.webRequest) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_request_header',
      error: 'chrome.webRequest API not available (extension missing the "webRequest" permission?)',
    });
    return;
  }
  const timeoutMs = req.init.timeoutMs ?? 30_000;
  const wantedHeader = req.init.headerName.toLowerCase();
  let resolved = false;
  const listener = (details: {
    requestHeaders?: { name: string; value?: string }[];
  }): void => {
    if (resolved) return;
    const hdr = details.requestHeaders?.find((h) => h.name.toLowerCase() === wantedHeader);
    if (!hdr || typeof hdr.value !== 'string') return;
    resolved = true;
    try {
      chrome.webRequest!.onBeforeSendHeaders.removeListener(listener);
    } catch {
      // ignore
    }
    void sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'capture_request_header',
      value: hdr.value,
    });
  };
  try {
    chrome.webRequest.onBeforeSendHeaders.addListener(
      listener,
      { urls: [`https://${req.init.host}${req.init.path ?? '/*'}`] },
      [...CAPTURE_EXTRA_INFO_SPEC],
    );
  } catch (e) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_request_header',
      error: `webRequest listener registration failed: ${String(e)}`,
    });
    return;
  }
  setTimeout(() => {
    if (resolved) return;
    resolved = true;
    try {
      chrome.webRequest!.onBeforeSendHeaders.removeListener(listener);
    } catch {
      // ignore
    }
    void sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_request_header',
      error: 'timeout',
    });
  }, timeoutMs);
}

/**
 * Snapshot the redirect target URL of the next request the browser makes
 * to `(host, path?)`, via `chrome.webRequest.onBeforeRedirect`. Single-
 * shot, mirrors `handleCaptureRequestHeaderRequest` but lighter: there's
 * no declared-scope plumbing — the only gate is that `host` is one of the
 * MCP's declared `domains` (equals-or-subdomain). Unlike
 * `onBeforeSendHeaders`, `onBeforeRedirect` needs no `extraInfoSpec`.
 */
async function handleCaptureRedirectRequest(
  mcpId: string,
  req: InnerRequestCaptureRedirect,
  domains: string[],
): Promise<void> {
  // The watched host must be a declared domain or a subdomain of one.
  const host = req.init.host;
  if (!isUrlAllowedForAnyDomain(`https://${host}/`, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_redirect',
      error: `capture host ${host} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  if (!chrome.webRequest) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_redirect',
      error: 'chrome.webRequest API not available (extension missing the "webRequest" permission?)',
    });
    return;
  }
  const timeoutMs = req.init.timeoutMs ?? 30_000;
  let resolved = false;
  const listener = (details: { redirectUrl: string }): void => {
    if (resolved) return;
    if (typeof details.redirectUrl !== 'string' || details.redirectUrl.length === 0) return;
    resolved = true;
    try {
      chrome.webRequest!.onBeforeRedirect.removeListener(listener);
    } catch {
      // ignore
    }
    void sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'capture_redirect',
      value: details.redirectUrl,
    });
  };
  try {
    chrome.webRequest.onBeforeRedirect.addListener(listener, {
      urls: [`https://${req.init.host}${req.init.path ?? '/*'}`],
    });
  } catch (e) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_redirect',
      error: `webRequest listener registration failed: ${String(e)}`,
    });
    return;
  }
  setTimeout(() => {
    if (resolved) return;
    resolved = true;
    try {
      chrome.webRequest!.onBeforeRedirect.removeListener(listener);
    } catch {
      // ignore
    }
    void sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_redirect',
      error: 'timeout',
    });
  }, timeoutMs);
}

/**
 * Map a completed `chrome.downloads` item to a `download` response value.
 * `mime` / `finalUrl` are omitted when absent so the wire stays minimal (the
 * protocol validator treats both as optional). Exported for unit testing —
 * the surrounding async orchestration is exercised live, like other handlers.
 */
export function downloadValueFromItem(item: {
  filename: string;
  fileSize: number;
  mime?: string;
  finalUrl?: string;
}): DownloadResult {
  return {
    path: item.filename,
    // Chrome's `DownloadItem.fileSize` is documented to be `-1` when the
    // size is unknown (e.g. the server never sent Content-Length). The
    // `download` response validator requires a non-negative integer — an
    // unclamped -1 would throw `ProtocolError` server-side, and since that
    // throw happens inside host.ts's single message-handler try/catch, it
    // closes the WHOLE extension WebSocket (every MCP on the concentrator),
    // not just this request. Clamp instead of failing the whole download:
    // the file genuinely saved, only its size is unreported.
    bytes: item.fileSize < 0 ? 0 : item.fileSize,
    ...(item.mime ? { mime: item.mime } : {}),
    ...(item.finalUrl ? { finalUrl: item.finalUrl } : {}),
  };
}

/**
 * Download `url` via `chrome.downloads` — the BROWSER fetches it with the
 * user's real cookies + TLS/JA3 fingerprint, so it clears a Cloudflare
 * bot-challenge a page-level `fetch()` (cors) cannot, and follows the
 * cross-origin redirect to the final file. Resolves the saved local file
 * path + size (the bridge is loopback-only, so the MCP reads the same disk).
 * Only the `url` host needs to be a declared `domain`; chrome.downloads
 * follows redirects (e.g. to a presigned subdomain) on its own.
 */
async function handleDownloadRequest(
  mcpId: string,
  req: InnerRequestDownload,
  domains: string[],
): Promise<void> {
  if (!isUrlAllowedForAnyDomain(req.init.url, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'download',
      error: `download url host not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  if (!chrome.downloads) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'download',
      error: 'chrome.downloads API not available (extension missing the "downloads" permission?)',
    });
    return;
  }
  const downloads = chrome.downloads;
  const timeoutMs = req.init.timeoutMs ?? 120_000;
  let done = false;
  let downloadId: number | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const cleanup = (): void => {
    try {
      downloads.onChanged.removeListener(onChanged);
    } catch {
      // ignore
    }
    if (timer !== undefined) clearTimeout(timer);
  };
  const fail = (error: string): void => {
    if (done) return;
    done = true;
    cleanup();
    void sendInner(mcpId, { type: 'response', id: req.id, ok: false, op: 'download', error });
  };
  const succeed = async (): Promise<void> => {
    if (done || downloadId === undefined) return;
    // Claim ownership BEFORE the first await: both the onChanged 'complete'
    // path and the post-download() race-guard can call succeed() while a prior
    // call is still awaiting search(), so set `done` synchronously to guarantee
    // exactly one response frame per request. The error paths below send
    // directly (fail() would no-op now that `done` is set).
    const id = downloadId;
    done = true;
    cleanup();
    let items;
    try {
      items = await downloads.search({ id });
    } catch (e) {
      void sendInner(mcpId, {
        type: 'response',
        id: req.id,
        ok: false,
        op: 'download',
        error: `download search failed: ${String(e)}`,
      });
      return;
    }
    const item = items[0];
    if (!item) {
      void sendInner(mcpId, {
        type: 'response',
        id: req.id,
        ok: false,
        op: 'download',
        error: 'download completed but its record was not found',
      });
      return;
    }
    // Erase only the download RECORD — the file stays for the MCP to move.
    void downloads.erase({ id }).catch(() => {
      // best-effort record cleanup
    });
    void sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'download',
      value: downloadValueFromItem(item),
    });
  };
  const onChanged = (delta: {
    id: number;
    state?: { current: string };
    error?: { current: string };
  }): void => {
    if (downloadId === undefined || delta.id !== downloadId) return;
    if (delta.error?.current) {
      fail(`download interrupted: ${delta.error.current}`);
      return;
    }
    if (delta.state?.current === 'complete') {
      void succeed();
    } else if (delta.state?.current === 'interrupted') {
      fail('download interrupted');
    }
  };

  // Listener BEFORE the download so a fast completion isn't missed.
  downloads.onChanged.addListener(onChanged);
  timer = setTimeout(() => fail('timeout'), timeoutMs);

  try {
    downloadId = await downloads.download({
      url: req.init.url,
      ...(req.init.filename ? { filename: req.init.filename } : {}),
      conflictAction: 'uniquify',
      saveAs: false,
    });
  } catch (e) {
    fail(`download could not be started: ${String(e)}`);
    return;
  }
  // Race guard: a tiny file may finish before `download()` even resolved, so
  // the onChanged 'complete' delta could have fired while downloadId was unset.
  try {
    const [item] = await downloads.search({ id: downloadId });
    if (item?.state === 'complete') {
      void succeed();
    } else if (item?.state === 'interrupted') {
      fail(`download interrupted: ${item.error ?? 'unknown'}`);
    }
  } catch {
    // onChanged will still deliver the terminal state.
  }
}

async function handleReadIndexedDbRequest(
  mcpId: string,
  req: InnerRequestReadIndexedDb,
  domains: string[],
): Promise<void> {
  const declared = mcpIndexedDbScopes.get(mcpId) ?? [];
  if (!isUrlAllowedForAnyDomain(req.init.origin, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: `origin ${req.init.origin} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  // Find a matching scope: same origin, database, store. Then check
  // requested keys ⊆ declared keys.
  const scope = declared.find(
    (d) =>
      d.origin === req.init.origin &&
      d.database === req.init.database &&
      d.store === req.init.store,
  );
  if (!scope) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: `(origin, database, store) not in declared indexedDbScopes`,
    });
    return;
  }
  const declaredSet = new Set(scope.keys);
  const undeclared = req.init.keys.filter((k) => !declaredSet.has(k));
  if (undeclared.length > 0) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: `IndexedDB keys not in declared set: ${undeclared.join(', ')}`,
    });
    return;
  }
  const tabUrl = `${req.init.origin}/`;
  // 0.5.2+: multi-tab fallback via `sendToFirstResponsiveTab` — see the
  // helper's doc. Same rationale as the fetch path: a pre-reload tab
  // (no content script) can shadow a fresh one, and the user shouldn't
  // have to refresh every page after every extension update.
  const result = await sendToFirstResponsiveTab(
    (t) => isTabUrlMatch(t, tabUrl),
    () => ({
      kind: 'fetchproxy-read-indexed-db',
      database: req.init.database,
      store: req.init.store,
      keys: [...req.init.keys],
    }),
    tabUrl,
  );
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: `tab read_indexed_db failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as
    | { ok: true; values: Record<string, unknown> }
    | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'read_indexed_db',
      values: resp.values,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: resp.error,
    });
  }
}

/**
 * Pure gate for a `read_dom` request. Mirrors the origin + declared-set
 * checks inlined in `handleReadIndexedDbRequest`, but factored out so the
 * gating logic is unit-testable without the module's live WS/session state.
 *
 * Returns the resolved DomSelectorDecls (in the request's `names` order) to
 * forward to the tab, or an `error` string (origin not allowed, or names not
 * in the declared set) to echo back to the MCP.
 */
export function resolveReadDomRequest(
  req: InnerRequestReadDom,
  declared: DomSelectorDecl[],
  domains: string[],
): { ok: true; selectors: DomSelectorDecl[] } | { ok: false; error: string } {
  if (!isUrlAllowedForAnyDomain(req.init.origin, domains)) {
    return {
      ok: false,
      error: `origin ${req.init.origin} not in domains [${domains.join(', ')}]`,
    };
  }
  const byName = new Map(declared.map((d) => [d.name, d]));
  const undeclared = req.init.names.filter((n) => !byName.has(n));
  if (undeclared.length > 0) {
    return {
      ok: false,
      error: `read_dom names not in declared set: ${undeclared.join(', ')}`,
    };
  }
  const selectors = req.init.names.map((n) => ({ ...byName.get(n)! }));
  return { ok: true, selectors };
}

/**
 * Tab-match predicate for a `read_dom` request. Host-or-subdomain
 * (`isTabUrlOnOrigin`), not strict-prefix (`isTabUrlMatch`) — a declared
 * apex origin (e.g. `https://example.com`) must still match a vendor
 * subdomain tab (e.g. `https://app.example.com/...`), the same rationale
 * that landed `isTabUrlOnOrigin` for the read_local_storage /
 * read_session_storage handlers. Factored out (mirrors
 * `resolveReadDomRequest`) so the choice of matcher is unit-testable
 * without the module's live WS/session state.
 */
export function readDomTabMatcher(origin: string): (tabUrl: string) => boolean {
  return (tabUrl: string) => isTabUrlOnOrigin(tabUrl, origin);
}

async function handleReadDomRequest(
  mcpId: string,
  req: InnerRequestReadDom,
  domains: string[],
): Promise<void> {
  const declared = mcpDomSelectors.get(mcpId) ?? [];
  const gate = resolveReadDomRequest(req, declared, domains);
  if (!gate.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_dom',
      error: gate.error,
    });
    return;
  }
  const tabUrl = `${req.init.origin}/`;
  // 0.5.2+: multi-tab fallback via `sendToFirstResponsiveTab` — see the
  // helper's doc. Same rationale as the read_indexed_db path: a pre-reload
  // tab (no content script) can shadow a fresh one, and the user shouldn't
  // have to refresh every page after every extension update.
  //
  // Host-or-subdomain match (`readDomTabMatcher`/`isTabUrlOnOrigin`), not
  // strict-prefix (`isTabUrlMatch`) — see that helper's doc. A declared
  // apex origin routinely has its real tab on a vendor subdomain.
  const result = await sendToFirstResponsiveTab(
    readDomTabMatcher(req.init.origin),
    () => ({
      kind: 'fetchproxy-read-dom',
      selectors: gate.selectors.map((d) => ({ ...d })),
    }),
    tabUrl,
  );
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_dom',
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_dom',
      error: `tab read_dom failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as
    | { ok: true; values: Record<string, string> }
    | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'read_dom',
      values: resp.values,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_dom',
      error: resp.error,
    });
  }
}

/**
 * Pure gate for a `graphql_query` request. Mirrors `resolveReadDomRequest`,
 * but factored out so the gating logic is unit-testable without the module's
 * live WS/session state.
 *
 * Three checks, in order:
 *   1. the `'graphql'` capability is present for this mcpId,
 *   2. `req.init.name` resolves to a declared `graphqlOps[]` entry, and
 *   3. when a coarse `tabUrl` hint is supplied, it is on a declared domain
 *      (host-or-subdomain). When omitted, the extension picks a tab on ANY
 *      declared domain, so the domain restriction is enforced by the tab
 *      matcher (`graphqlTabMatcher`) instead.
 *
 * Returns the resolved `operationName` (the DocumentNode handle the page
 * owns) to forward to the tab, or an `error` string to echo back to the MCP.
 */
export function resolveGraphqlQueryRequest(
  req: InnerRequestGraphqlQuery,
  capabilities: string[],
  declared: GraphqlOpDeclaration[],
  domains: string[],
): { ok: true; operationName: string } | { ok: false; error: string } {
  if (!capabilities.includes('graphql')) {
    return {
      ok: false,
      error: `capability "graphql" not granted (declared: [${capabilities.join(', ')}])`,
    };
  }
  const byName = new Map(declared.map((d) => [d.name, d]));
  const match = byName.get(req.init.name);
  if (!match) {
    return {
      ok: false,
      error: `graphql_query name not in declared graphqlOps: ${req.init.name}`,
    };
  }
  if (req.init.tabUrl !== undefined && !isUrlAllowedForAnyDomain(req.init.tabUrl, domains)) {
    return {
      ok: false,
      error: `tabUrl ${req.init.tabUrl} not in domains [${domains.join(', ')}]`,
    };
  }
  return { ok: true, operationName: match.operationName };
}

/**
 * Tab-match predicate for a `graphql_query` request. Host-or-subdomain
 * (`isTabUrlOnOrigin`), mirroring `readDomTabMatcher`. When the MCP supplied a
 * coarse `tabUrl` hint, match tabs on that host (or a subdomain of it). When it
 * didn't, match any tab on a declared domain — the query runs through whatever
 * tab's Apollo client already owns the operation. Factored out so the choice of
 * matcher is unit-testable without the module's live WS/session state.
 */
export function graphqlTabMatcher(
  tabUrl: string | undefined,
  domains: string[],
): (candidateTabUrl: string) => boolean {
  if (tabUrl !== undefined) {
    return (candidateTabUrl: string) => isTabUrlOnOrigin(candidateTabUrl, tabUrl);
  }
  return (candidateTabUrl: string) => isUrlAllowedForAnyDomain(candidateTabUrl, domains);
}

async function handleGraphqlQueryRequest(
  mcpId: string,
  req: InnerRequestGraphqlQuery,
  domains: string[],
): Promise<void> {
  const declared = mcpGraphqlOps.get(mcpId) ?? [];
  const capabilities = mcpCapabilities.get(mcpId) ?? ['fetch'];
  const gate = resolveGraphqlQueryRequest(req, capabilities, declared, domains);
  if (!gate.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'graphql_query',
      error: gate.error,
    });
    return;
  }
  const tabUrlForError = req.init.tabUrl ?? `domains [${domains.join(', ')}]`;
  // 0.5.2+: multi-tab fallback via `sendToFirstResponsiveTab` — see the
  // helper's doc. Host-or-subdomain match (`graphqlTabMatcher`), not strict
  // prefix, for the same reason the read_dom path uses it. The relay carries
  // the extension-resolved `operationName` (never the raw declared `name`);
  // the MAIN-world Apollo bridge reuses the page's cached DocumentNode for it.
  const result = await sendToFirstResponsiveTab(
    graphqlTabMatcher(req.init.tabUrl, domains),
    (matchedTabUrl) => ({
      kind: 'fetchproxy-graphql-query',
      init: {
        operationName: gate.operationName,
        variables: req.init.variables,
        tabUrl: matchedTabUrl,
      },
    }),
    tabUrlForError,
  );
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'graphql_query',
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'graphql_query',
      error: `tab graphql_query failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as
    | { ok: true; data: unknown }
    | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'graphql_query',
      data: resp.data,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'graphql_query',
      error: resp.error,
    });
  }
}

async function onApproval(approved: AnyPendingRecord): Promise<void> {
  if (!trust || !sessions || !extIdentity || !currentExtSessionNonce) return;
  // Persist trust. Default to ['fetch'] when older popup state somehow
  // omits the field — defensive, the popup always populates it in 0.2.0+.
  const approvedCapabilities =
    approved.capabilities && approved.capabilities.length > 0
      ? [...approved.capabilities]
      : ['fetch'];
  // Trust is keyed by identityHash — write it once for the entire group of
  // waiting processes (all share the same identity and scope).
  await trust.put(approved.identityHash, {
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
    extensionIdentityX25519Pub: toB64(extIdentity.x25519Pub),
    extensionIdentityEd25519Pub: toB64(extIdentity.ed25519Pub),
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
      sessions.set(mcpId, sessionKey);
      mcpDomains.set(mcpId, [...approved.domains]);
      applyGrantedScopeToSession(mcpId, grantedScopeFromApproval(approved));
      // Part 3: track identity hash per approved session.
      mcpIdentityHash.set(mcpId, approved.identityHash);
      broadcastConnectionsChanged();
      // 0.4.0: sign over (mcpHelloNonce || extHello.sessionNonce). The
      // MCP host verifies this against the extension's claimed Ed25519
      // pub and gates session-key derivation on it.
      const sessionSig = await ed25519Sign(
        extIdentity.ed25519Priv,
        concatBytes(sessionNonce, currentExtSessionNonce!),
      );
      const ready: ReadyFrame = {
        type: 'ready',
        mcpId,
        extensionSessionPub: toB64(ephemeral.publicKey),
        sessionSig: toB64(sessionSig),
      };
      ws?.send(JSON.stringify(ready));
    }
    // Ensure domain tabs for the approved domains (once for the group).
    for (const d of approved.domains) {
      void ensureDomainTab(d).catch(() => {
        /* noop */
      });
    }
  }
  if (approved.kind === 'scope-update' && sessions) {
    // trust.put (above) persists the wider scope for future hellos. But the
    // session is already live — so refresh the in-memory scope maps the request
    // handler reads, for each still-connected mcpId of this identity. The grant
    // then takes effect immediately, with NO reconnect. Sessions are already
    // keyed, so there's no ECDH/ReadyFrame to redo (unlike the pair branch).
    const sess = sessions;
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
const DISMISSED_SCOPE_KEY = 'dismissedScopeHashes';

async function onScopeUpdateDismiss(key: string, identityHash: string, dismissedScopeHash: string): Promise<void> {
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

// Boot: only run in a real MV3 service worker context. Skipped under vitest
// (no chrome.runtime.getManifest, no chrome.storage.local.onChanged).
function maybeBoot(): void {
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
  trust = new TrustStore(chrome.runtime.getManifest().version);
  sessions = new SessionKeys();
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
      extIdentity = id;
      connect();
    })
    .catch((e) => console.error('[fetchproxy] extension identity boot:', e));
}

maybeBoot();
