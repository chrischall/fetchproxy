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
  type IndexedDbScopeDecl,
  type StoragePointerDecl,
  type Frame,
  type HelloFrameFromServer,
  type HelloFrameFromExtension,
  type ReadyFrame,
  type InnerFrame,
  type InnerRequest,
  type InnerRequestFetch,
  type InnerRequestReadCookies,
  type InnerRequestReadLocalStorage,
  type InnerRequestReadSessionStorage,
  type InnerRequestCaptureRequestHeader,
  type InnerRequestReadIndexedDb,
  type EncryptedFrame,
} from '@fetchproxy/protocol';
import { TrustStore } from './trust-store.js';
import { SessionKeys } from './session-keys.js';
import { ensureDomainTab } from './ensure-domain-tab.js';
import { isUrlAllowedForAnyDomain, isTabUrlMatch, isTabUrlOnOrigin } from './lib/url-match.js';
import { normalisePendingPair } from './lib/pending-pair.js';
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
      captureHeaders: { urlPattern: string; headerName: string }[];
      indexedDbScopes: IndexedDbScopeDecl[];
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
        captureHeaders: { urlPattern: string; headerName: string }[];
        indexedDbScopes: IndexedDbScopeDecl[];
        localStoragePointers: StoragePointerDecl[];
        sessionStoragePointers: StoragePointerDecl[];
      };
    }
  | {
      kind: 'auto-trust';
      mcpId: string;
      domains: string[];
      capabilities: string[];
      cookieKeys: string[];
      localStorageKeys: string[];
      sessionStorageKeys: string[];
      captureHeaders: { urlPattern: string; headerName: string }[];
      indexedDbScopes: IndexedDbScopeDecl[];
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

/**
 * Order-insensitive equality for two capability lists. A capability
 * upgrade (e.g. fetch → fetch+read_cookies) is conservative: we want
 * the user to re-approve when the MCP asks for more access.
 */
function sameCapabilitySet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const sa = [...a].sort();
  const sb = [...b].sort();
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
  captureHeaders: { urlPattern: string; headerName: string }[];
  indexedDbScopes: IndexedDbScopeDecl[];
  localStoragePointers: StoragePointerDecl[];
  sessionStoragePointers: StoragePointerDecl[];
}

function declaredScope(hello: HelloFrameFromServer): DeclaredScope {
  return {
    cookieKeys: [...(hello.cookieKeys ?? [])],
    localStorageKeys: [...(hello.localStorageKeys ?? [])],
    sessionStorageKeys: [...(hello.sessionStorageKeys ?? [])],
    captureHeaders: (hello.captureHeaders ?? []).map((d) => ({
      urlPattern: d.urlPattern,
      headerName: d.headerName,
    })),
    indexedDbScopes: (hello.indexedDbScopes ?? []).map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
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

function sameScopeArrays(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const sa = [...a].sort();
  const sb = [...b].sort();
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
}

function sameCaptureHeaders(
  a: readonly { urlPattern: string; headerName: string }[],
  b: readonly { urlPattern: string; headerName: string }[],
): boolean {
  if (a.length !== b.length) return false;
  const norm = (
    arr: readonly { urlPattern: string; headerName: string }[],
  ): string[] => arr.map((d) => `${d.urlPattern}\x00${d.headerName}`).sort();
  const sa = norm(a);
  const sb = norm(b);
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
}

function sameIndexedDbScopes(
  a: readonly IndexedDbScopeDecl[],
  b: readonly IndexedDbScopeDecl[],
): boolean {
  if (a.length !== b.length) return false;
  const norm = (arr: readonly IndexedDbScopeDecl[]): string[] =>
    arr
      .map(
        (d) =>
          `${d.origin}\x00${d.database}\x00${d.store}\x00${[...d.keys].sort().join(',')}`,
      )
      .sort();
  const sa = norm(a);
  const sb = norm(b);
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
}

function sameStoragePointers(
  a: readonly StoragePointerDecl[],
  b: readonly StoragePointerDecl[],
): boolean {
  if (a.length !== b.length) return false;
  const norm = (arr: readonly StoragePointerDecl[]): string[] =>
    arr.map((d) => `${d.key}\x00${d.jsonPointer}`).sort();
  const sa = norm(a);
  const sb = norm(b);
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
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
      // Conservative: any change in declared scope (capabilities or any of
      // the 0.3.0 scope arrays) triggers re-pair. The user approved a
      // specific scope; we won't widen it silently.
      const scopeChanged =
        !sameCapabilitySet(record.capabilities, capabilities) ||
        !sameScopeArrays(record.cookieKeys, scope.cookieKeys) ||
        !sameScopeArrays(record.localStorageKeys, scope.localStorageKeys) ||
        !sameScopeArrays(record.sessionStorageKeys, scope.sessionStorageKeys) ||
        !sameCaptureHeaders(record.captureHeaders, scope.captureHeaders) ||
        !sameIndexedDbScopes(record.indexedDbScopes ?? [], scope.indexedDbScopes) ||
        !sameStoragePointers(record.localStoragePointers ?? [], scope.localStoragePointers) ||
        !sameStoragePointers(record.sessionStoragePointers ?? [], scope.sessionStoragePointers);
      if (scopeChanged) {
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
          // 0.4.0: snapshot the previously approved scope so the popup
          // can render an "update" diff. The user sees what was added
          // vs what was already approved.
          previousScope: {
            capabilities: [...record.capabilities],
            cookieKeys: [...record.cookieKeys],
            localStorageKeys: [...record.localStorageKeys],
            sessionStorageKeys: [...record.sessionStorageKeys],
            captureHeaders: record.captureHeaders.map((d) => ({ ...d })),
            indexedDbScopes: (record.indexedDbScopes ?? []).map((d) => ({
              origin: d.origin,
              database: d.database,
              store: d.store,
              keys: [...d.keys],
            })),
            localStoragePointers: (record.localStoragePointers ?? []).map((d) => ({
              ...d,
            })),
            sessionStoragePointers: (record.sessionStoragePointers ?? []).map((d) => ({
              ...d,
            })),
          },
        };
      }
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
        capabilities,
        ...scope,
        sessionKey,
        extensionSessionPub: ephemeral.publicKey,
        mcpSessionNonce: sessionNonce,
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
  runtime: { getManifest: () => { version: string } };
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
    get: (
      details: { url: string; name: string },
    ) => Promise<{ name: string; value: string } | null>;
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

// Track which mcpId's hello is queued for the popup.
interface PendingPairRecord {
  mcpId: string;
  serverName: string;
  version: string;
  domains: string[];
  capabilities: string[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: { urlPattern: string; headerName: string }[];
  /** 0.4.0+: declared IndexedDB scopes the user is being asked to approve. */
  indexedDbScopes: IndexedDbScopeDecl[];
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
    captureHeaders: { urlPattern: string; headerName: string }[];
    indexedDbScopes: IndexedDbScopeDecl[];
    localStoragePointers: StoragePointerDecl[];
    sessionStoragePointers: StoragePointerDecl[];
  };
  pairCode: string;
  identityHash: string;
  identityX25519Pub: string;
  identityEd25519Pub: string;
  sessionNonceB64: string;
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
const mcpCaptureHeaders = new Map<string, { urlPattern: string; headerName: string }[]>();
// 0.4.0+: per-mcpId declared IndexedDB scopes. The request handler
// gates `read_indexed_db` on subset-match against this table.
const mcpIndexedDbScopes = new Map<string, IndexedDbScopeDecl[]>();
// 0.4.0+: per-mcpId declared storage pointer decls. Storage-read
// handlers gate per-request pointer fields on these.
const mcpLocalStoragePointers = new Map<string, { key: string; jsonPointer: string }[]>();
const mcpSessionStoragePointers = new Map<string, { key: string; jsonPointer: string }[]>();

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
    mcpLocalStoragePointers.clear();
    mcpSessionStoragePointers.clear();
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
    sessions.set(result.mcpId, result.sessionKey);
    mcpDomains.set(result.mcpId, [...result.domains]);
    mcpCapabilities.set(result.mcpId, [...result.capabilities]);
    mcpCookieKeys.set(result.mcpId, [...result.cookieKeys]);
    mcpLocalStorageKeys.set(result.mcpId, [...result.localStorageKeys]);
    mcpSessionStorageKeys.set(result.mcpId, [...result.sessionStorageKeys]);
    mcpCaptureHeaders.set(result.mcpId, [...result.captureHeaders]);
    mcpIndexedDbScopes.set(result.mcpId, [...result.indexedDbScopes]);
    mcpLocalStoragePointers.set(result.mcpId, [...result.localStoragePointers]);
    mcpSessionStoragePointers.set(result.mcpId, [...result.sessionStoragePointers]);
    // TODO: open tabs for ALL declared domains. For 0.2.0 we open one
    // (the first declared) — multi-domain MCPs (HoneyBook spans two
    // hosts) ought to surface a tab for each, but a single open tab is
    // the minimum to make the first fetch succeed.
    const firstDomain = result.domains[0];
    if (firstDomain !== undefined) {
      void ensureDomainTab(firstDomain).catch(() => {
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
    return;
  }
  // needs-pair: queue for popup.
  const pending: PendingPairRecord = {
    mcpId: result.mcpId,
    serverName: result.serverName,
    version: result.version,
    domains: [...result.domains],
    capabilities: [...result.capabilities],
    cookieKeys: [...result.cookieKeys],
    localStorageKeys: [...result.localStorageKeys],
    sessionStorageKeys: [...result.sessionStorageKeys],
    captureHeaders: [...result.captureHeaders],
    indexedDbScopes: [...result.indexedDbScopes],
    localStoragePointers: [...result.localStoragePointers],
    sessionStoragePointers: [...result.sessionStoragePointers],
    ...(result.previousScope ? { previousScope: result.previousScope } : {}),
    pairCode: result.pairCode,
    identityHash: result.identityHash,
    identityX25519Pub: result.identityX25519Pub,
    identityEd25519Pub: result.identityEd25519Pub,
    sessionNonceB64: toB64(result.sessionNonce),
  };
  // 0.5.2+: store pending pairs as a dict keyed by mcpId so multiple
  // simultaneous unpaired MCPs queue up cleanly. Pre-0.5.2 wrote a single
  // PendingPairRecord under this key, which meant the second MCP's hello
  // silently clobbered the first MCP's pending entry — the user could only
  // ever pair one at a time. Reading tolerates both shapes (`mergePending`
  // below) so an in-flight legacy record from a pre-upgrade SW survives the
  // version bump. The read-modify-write is wrapped in `withPendingPairLock`
  // so concurrent peer hellos can't race each other across the await.
  await withPendingPairLock(async () => {
    const got = await chrome.storage.local.get(PENDING_PAIR_KEY);
    const existing = mergePending(got[PENDING_PAIR_KEY]);
    existing[pending.mcpId] = pending;
    await chrome.storage.local.set({ [PENDING_PAIR_KEY]: existing });
  });
  // 0.4.2: surface the pending pair without making the user discover
  // it manually — paint the action-icon badge and best-effort try to
  // open the popup. Both no-op in environments that don't expose
  // chrome.action (unit tests, older Chrome).
  setPairPendingBadge();
  // 0.5.2+: notify the MCP-side server (host or peer) that the user has
  // been asked to approve. The MCP can then include `pending.pairCode`
  // in tool errors so the chat shows the same XXX-XXX the popup is
  // displaying — the whole point of the joint pair code is the user
  // comparing it across two channels, which doesn't work if only the
  // popup has it. Best-effort: if the WS dropped between the hello and
  // here, the next reconnect's hello triggers a fresh pair-pending.
  if (ws && ws.readyState === WebSocket.OPEN) {
    try {
      ws.send(
        JSON.stringify({
          type: 'pair-pending',
          mcpId: pending.mcpId,
          pairCode: pending.pairCode,
        }),
      );
    } catch (e) {
      console.warn('[fetchproxy] pair-pending send failed:', e);
    }
  }
}

/**
 * Local alias bound to this file's `PendingPairRecord`. The shared
 * helper in `./lib/pending-pair.ts` is generic so the popup can use it
 * against its own structurally-compatible interface without a circular
 * dependency on this file's exact type.
 */
function mergePending(stored: unknown): Record<string, PendingPairRecord> {
  return normalisePendingPair<PendingPairRecord>(stored);
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
  if (!capabilities.includes(req.op)) {
    // Capability gate. The MCP didn't ask for this verb at pair time —
    // refuse with an op-echoing error so the server-side awaiter can
    // surface a clear message rather than blame the transport.
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: req.op,
      error: `capability ${JSON.stringify(req.op)} not granted (declared: [${capabilities.join(', ')}])`,
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
  if (req.op === 'read_indexed_db') {
    await handleReadIndexedDbRequest(mcpId, req, domains);
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
  // Find a tab matching tabUrl prefix
  const tabs = await chrome.tabs.query({});
  const match = tabs.find((t) => t.url && isTabUrlMatch(t.url, req.init.tabUrl));
  if (!match || typeof match.id !== 'number') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      error: `no tab matching ${req.init.tabUrl}`,
    });
    return;
  }
  try {
    const resp = (await chrome.tabs.sendMessage(match.id, {
      kind: 'fetchproxy-fetch',
      init: { ...req.init, tabUrl: match.url ?? req.init.tabUrl },
    })) as { ok: true; status: number; url: string; body: string } | { ok: false; error: string };
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
  } catch (e) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      error: `tab fetch failed: ${String(e)}`,
    });
  }
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
  const tabs = await chrome.tabs.query({});
  const match = tabs.find((t) => t.url && isTabUrlMatch(t.url, tabUrl));
  if (!match || typeof match.id !== 'number') {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: `no tab matching ${tabUrl}`,
    });
    return;
  }
  try {
    const resp = (await chrome.tabs.sendMessage(match.id, {
      kind: 'fetchproxy-read-cookies',
    })) as { ok: true; cookies: string } | { ok: false; error: string };
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
  } catch (e) {
    await sendInner(mcpId, {
      type: 'response',
      id,
      ok: false,
      op: 'read_cookies',
      error: `tab read_cookies failed: ${String(e)}`,
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
): Promise<void> {
  // Origin must be in declared domain set.
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
      const got = await chrome.cookies.get({ url: origin, name: key });
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
  const tabs = await chrome.tabs.query({});
  const match = tabs.find((t) => t.url && isTabUrlOnOrigin(t.url, req.init.origin));
  if (!match || typeof match.id !== 'number') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op,
      error: `no tab matching origin ${req.init.origin}`,
    });
    return;
  }
  try {
    const resp = (await chrome.tabs.sendMessage(match.id, {
      kind: bucket === 'local' ? 'fetchproxy-read-local-storage' : 'fetchproxy-read-session-storage',
      keys: [...req.init.keys],
      pointers: req.init.pointers,
    })) as { ok: true; values: Record<string, string> } | { ok: false; error: string };
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
  } catch (e) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op,
      error: `tab ${op} failed: ${String(e)}`,
    });
  }
}

async function handleCaptureRequestHeaderRequest(
  mcpId: string,
  req: InnerRequestCaptureRequestHeader,
  domains: string[],
): Promise<void> {
  const declared = mcpCaptureHeaders.get(mcpId) ?? [];
  const declaredMatch = declared.find(
    (d) => d.urlPattern === req.init.urlPattern && d.headerName === req.init.headerName,
  );
  if (!declaredMatch) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_request_header',
      error: `(urlPattern, headerName) not in declared captureHeaders`,
    });
    return;
  }
  // urlPattern's host must be a declared domain. The validator already
  // canonicalised the URL shape so we can just URL-parse the prefix.
  const host = (() => {
    try {
      return new URL(req.init.urlPattern.replace(/\*+/g, 'placeholder')).hostname;
    } catch {
      return '';
    }
  })();
  if (!host || !isUrlAllowedForAnyDomain(`https://${host}/`, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'capture_request_header',
      error: `urlPattern host ${host} not in domains [${domains.join(', ')}]`,
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
      { urls: [req.init.urlPattern] },
      ['requestHeaders'],
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
  const tabs = await chrome.tabs.query({});
  const match = tabs.find((t) => t.url && isTabUrlMatch(t.url, tabUrl));
  if (!match || typeof match.id !== 'number') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: `no tab matching ${tabUrl}`,
    });
    return;
  }
  try {
    const resp = (await chrome.tabs.sendMessage(match.id, {
      kind: 'fetchproxy-read-indexed-db',
      database: req.init.database,
      store: req.init.store,
      keys: [...req.init.keys],
    })) as { ok: true; values: Record<string, unknown> } | { ok: false; error: string };
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
  } catch (e) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: `tab read_indexed_db failed: ${String(e)}`,
    });
  }
}

async function onApproval(approved: PendingPairRecord): Promise<void> {
  if (!trust || !sessions || !extIdentity || !currentExtSessionNonce) return;
  // Persist trust. Default to ['fetch'] when older popup state somehow
  // omits the field — defensive, the popup always populates it in 0.2.0+.
  const approvedCapabilities =
    approved.capabilities && approved.capabilities.length > 0
      ? [...approved.capabilities]
      : ['fetch'];
  await trust.put(approved.identityHash, {
    serverName: approved.serverName,
    domains: [...approved.domains],
    capabilities: approvedCapabilities,
    cookieKeys: [...(approved.cookieKeys ?? [])],
    localStorageKeys: [...(approved.localStorageKeys ?? [])],
    sessionStorageKeys: [...(approved.sessionStorageKeys ?? [])],
    captureHeaders: (approved.captureHeaders ?? []).map((d) => ({
      urlPattern: d.urlPattern,
      headerName: d.headerName,
    })),
    indexedDbScopes: (approved.indexedDbScopes ?? []).map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
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
  // Derive session key.
  const identityPub = fromB64(approved.identityX25519Pub);
  const sessionNonce = fromB64(approved.sessionNonceB64);
  const ephemeral = await generateX25519();
  const shared = await ecdhX25519(ephemeral.privateKey, identityPub);
  const sessionKey = await hkdfSha256(
    shared,
    sessionNonce,
    enc.encode(HKDF_SESSION_INFO),
    32,
  );
  sessions.set(approved.mcpId, sessionKey);
  mcpDomains.set(approved.mcpId, [...approved.domains]);
  mcpCapabilities.set(approved.mcpId, approvedCapabilities);
  mcpCookieKeys.set(approved.mcpId, [...(approved.cookieKeys ?? [])]);
  mcpLocalStorageKeys.set(approved.mcpId, [...(approved.localStorageKeys ?? [])]);
  mcpSessionStorageKeys.set(approved.mcpId, [...(approved.sessionStorageKeys ?? [])]);
  mcpCaptureHeaders.set(approved.mcpId, (approved.captureHeaders ?? []).map((d) => ({ ...d })));
  mcpIndexedDbScopes.set(
    approved.mcpId,
    (approved.indexedDbScopes ?? []).map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    })),
  );
  mcpLocalStoragePointers.set(
    approved.mcpId,
    (approved.localStoragePointers ?? []).map((d) => ({ ...d })),
  );
  mcpSessionStoragePointers.set(
    approved.mcpId,
    (approved.sessionStoragePointers ?? []).map((d) => ({ ...d })),
  );
  // TODO: open tabs for ALL declared domains. See auto-trust path above.
  const firstDomain = approved.domains[0];
  if (firstDomain !== undefined) {
    void ensureDomainTab(firstDomain).catch(() => {
      /* noop */
    });
  }
  // 0.4.0: sign over (mcpHelloNonce || extHello.sessionNonce). The
  // MCP host verifies this against the extension's claimed Ed25519
  // pub and gates session-key derivation on it.
  const sessionSig = await ed25519Sign(
    extIdentity.ed25519Priv,
    concatBytes(sessionNonce, currentExtSessionNonce),
  );
  const ready: ReadyFrame = {
    type: 'ready',
    mcpId: approved.mcpId,
    extensionSessionPub: toB64(ephemeral.publicKey),
    sessionSig: toB64(sessionSig),
  };
  ws?.send(JSON.stringify(ready));
  // 0.5.2+: clear popup state for this approved mcpId ONLY. Previously
  // (when pendingPair was a single record) a blanket remove was correct;
  // now pendingPair is a dict keyed by mcpId and other unapproved MCPs
  // may still be queued under their own keys, so we need a read-modify-
  // write that touches just `approved.mcpId`. The popup's onApprove
  // handler does the same dance on its side; both paths run for any
  // single approval (popup writes approvedPair → this listener fires →
  // we clean up here), so the operation must be idempotent for the
  // entry we're removing. The RMW shares `withPendingPairLock` with
  // `onServerHello` so a hello arriving mid-approval can't race the
  // get/set pair.
  await withPendingPairLock(async () => {
    const got = await chrome.storage.local.get(PENDING_PAIR_KEY);
    const remaining = mergePending(got[PENDING_PAIR_KEY]);
    delete remaining[approved.mcpId];
    if (Object.keys(remaining).length === 0) {
      await chrome.storage.local.remove(PENDING_PAIR_KEY);
      // Badge clears only when the queue is fully drained — other queued
      // MCPs still need a visible "!" so the user knows to come back.
      clearPairPendingBadge();
    } else {
      await chrome.storage.local.set({ [PENDING_PAIR_KEY]: remaining });
    }
  });
  await chrome.storage.local.remove(APPROVED_PAIR_KEY);
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
  chrome.storage.local.onChanged.addListener((changes) => {
    const approved = changes[APPROVED_PAIR_KEY]?.newValue as PendingPairRecord | undefined;
    if (approved) {
      void onApproval(approved).catch((e) => console.error('[fetchproxy] approval:', e));
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
