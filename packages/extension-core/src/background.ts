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
  ecdhX25519,
  hkdfSha256,
  derivePairCode,
  sha256,
  generateX25519,
  sealInnerFrame,
  openEncryptedFrame,
  validateFrame,
  PROTOCOL_VERSION,
  type Frame,
  type HelloFrameFromServer,
  type HelloFrameFromExtension,
  type ReadyFrame,
  type InnerFrame,
  type InnerRequest,
  type EncryptedFrame,
} from '@fetchproxy/protocol';
import { TrustStore } from './trust-store.js';
import { SessionKeys } from './session-keys.js';
import { ensureDomainTab } from './ensure-domain-tab.js';
import { isUrlAllowedForAnyDomain, isTabUrlMatch } from './lib/url-match.js';

// -------------------------------------------------------------------
// 1. Pure decision function (handleServerHello)
// -------------------------------------------------------------------

export interface HandleHelloDeps {
  trust: TrustStore;
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
      version: string;
      identityX25519Pub: string;
      identityEd25519Pub: string;
      sessionNonce: Uint8Array;
    }
  | {
      kind: 'auto-trust';
      mcpId: string;
      domains: string[];
      sessionKey: Uint8Array;
      extensionSessionPub: Uint8Array;
    };

const enc = new TextEncoder();

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function fromB64(s: string): Uint8Array {
  // btoa/atob portable in MV3 service workers and Node
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toB64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i] as number);
  return btoa(s);
}

function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += (bytes[i] as number).toString(16).padStart(2, '0');
  return s;
}

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
      concat(enc.encode(hello.mcpId), sessionNonce),
      sessionSig,
    );
  } catch {
    return { kind: 'reject', reason: 'sessionSig verification threw' };
  }
  if (!sigOk) return { kind: 'reject', reason: 'sessionSig invalid' };

  // 2. Look up trust.
  const hash = toHex(await sha256(identityX25519Pub));
  const record = await deps.trust.get(hash);

  if (record) {
    if (
      record.serverName !== hello.serverName ||
      !sameDomainSet(record.domains, hello.domains)
    ) {
      return { kind: 'reject', reason: 'serverName/domains mismatch with trust record' };
    }
    // Derive session key with fresh ephemeral keypair.
    const ephemeral = await generateX25519();
    const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
    const sessionKey = await hkdfSha256(
      shared,
      sessionNonce,
      enc.encode('fetchproxy/0.1.0/session'),
      32,
    );
    return {
      kind: 'auto-trust',
      mcpId: hello.mcpId,
      domains: [...hello.domains],
      sessionKey,
      extensionSessionPub: ephemeral.publicKey,
    };
  }

  // 3. Need pairing.
  const pairCode = await derivePairCode(identityX25519Pub);
  return {
    kind: 'needs-pair',
    pairCode,
    identityHash: hash,
    mcpId: hello.mcpId,
    serverName: hello.serverName,
    domains: [...hello.domains],
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
};

// Track which mcpId's hello is queued for the popup.
interface PendingPairRecord {
  mcpId: string;
  serverName: string;
  version: string;
  domains: string[];
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
// Track each mcpId's declared domain set so the request handler can enforce
// the allowlist. 0.2.0+: this is a Map<mcpId, string[]> rather than the
// 0.1.x Map<mcpId, string> — every URL must match SOME entry to be allowed.
const mcpDomains = new Map<string, string[]>();

function connect(): void {
  if (!trust || !sessions) return;
  if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) return;
  ws = new WebSocket(HOST_URL);
  ws.addEventListener('open', () => {
    reconnectAttempt = 0;
    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: PROTOCOL_VERSION,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: chrome.runtime.getManifest().version,
    };
    ws!.send(JSON.stringify(extHello));
  });
  ws.addEventListener('message', (ev: MessageEvent) => {
    void onMessage(ev.data as string).catch((e) => console.error('[fetchproxy] onMessage:', e));
  });
  ws.addEventListener('close', () => {
    sessions?.clear();
    mcpDomains.clear();
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
  if (!trust || !sessions) return;
  const result = await handleServerHello(hello, { trust });
  if (result.kind === 'reject') {
    console.warn(`[fetchproxy] rejected hello for ${hello.mcpId}: ${result.reason}`);
    return;
  }
  if (result.kind === 'auto-trust') {
    sessions.set(result.mcpId, result.sessionKey);
    mcpDomains.set(result.mcpId, [...result.domains]);
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
    const ready: ReadyFrame = {
      type: 'ready',
      mcpId: result.mcpId,
      extensionSessionPub: toB64(result.extensionSessionPub),
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
    pairCode: result.pairCode,
    identityHash: result.identityHash,
    identityX25519Pub: result.identityX25519Pub,
    identityEd25519Pub: result.identityEd25519Pub,
    sessionNonceB64: toB64(result.sessionNonce),
  };
  await chrome.storage.local.set({ [PENDING_PAIR_KEY]: pending });
}

async function onEncryptedFrame(frame: EncryptedFrame): Promise<void> {
  if (!sessions) return;
  const entry = sessions.get(frame.mcpId);
  if (!entry) return;
  if (!entry.acceptInboundSeq(frame.seq)) return;
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
  if (!isUrlAllowedForAnyDomain(req.init.url, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
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
        status: resp.status,
        url: resp.url,
        body: resp.body,
      });
    } else {
      await sendInner(mcpId, { type: 'response', id: req.id, ok: false, error: resp.error });
    }
  } catch (e) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      error: `tab fetch failed: ${String(e)}`,
    });
  }
}

async function onApproval(approved: PendingPairRecord): Promise<void> {
  if (!trust || !sessions) return;
  // Persist trust.
  await trust.put(approved.identityHash, {
    serverName: approved.serverName,
    domains: [...approved.domains],
    identityX25519Pub: approved.identityX25519Pub,
    identityEd25519Pub: approved.identityEd25519Pub,
  });
  // Derive session key.
  const identityPub = fromB64(approved.identityX25519Pub);
  const sessionNonce = fromB64(approved.sessionNonceB64);
  const ephemeral = await generateX25519();
  const shared = await ecdhX25519(ephemeral.privateKey, identityPub);
  const sessionKey = await hkdfSha256(
    shared,
    sessionNonce,
    enc.encode('fetchproxy/0.1.0/session'),
    32,
  );
  sessions.set(approved.mcpId, sessionKey);
  mcpDomains.set(approved.mcpId, [...approved.domains]);
  // TODO: open tabs for ALL declared domains. See auto-trust path above.
  const firstDomain = approved.domains[0];
  if (firstDomain !== undefined) {
    void ensureDomainTab(firstDomain).catch(() => {
      /* noop */
    });
  }
  // Send ready.
  const ready: ReadyFrame = {
    type: 'ready',
    mcpId: approved.mcpId,
    extensionSessionPub: toB64(ephemeral.publicKey),
  };
  ws?.send(JSON.stringify(ready));
  // Clear popup state.
  await chrome.storage.local.remove(PENDING_PAIR_KEY);
  await chrome.storage.local.remove(APPROVED_PAIR_KEY);
}

// Boot: only run in a real MV3 service worker context. Skipped under vitest
// (no chrome.runtime.getManifest, no chrome.storage.local.onChanged).
function maybeBoot(): void {
  const c = (globalThis as { chrome?: unknown }).chrome as
    | {
        runtime?: { getManifest?: () => { version: string } };
        storage?: { local?: { onChanged?: { addListener?: unknown } } };
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
    if (!approved) return;
    void onApproval(approved).catch((e) => console.error('[fetchproxy] approval:', e));
  });
  connect();
}

maybeBoot();
