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
  toB64,
  fromB64,
  toHex,
  concatBytes,
  PROTOCOL_VERSION,
  type Capability,
  type Frame,
  type HelloFrameFromServer,
  type HelloFrameFromExtension,
  type ReadyFrame,
  type InnerFrame,
  type InnerRequest,
  type InnerRequestFetch,
  type InnerRequestReadCookies,
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
      capabilities: string[];
      version: string;
      identityX25519Pub: string;
      identityEd25519Pub: string;
      sessionNonce: Uint8Array;
    }
  | {
      kind: 'auto-trust';
      mcpId: string;
      domains: string[];
      capabilities: string[];
      sessionKey: Uint8Array;
      extensionSessionPub: Uint8Array;
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

  if (record) {
    if (
      record.serverName !== hello.serverName ||
      !sameDomainSet(record.domains, hello.domains)
    ) {
      return { kind: 'reject', reason: 'serverName/domains mismatch with trust record' };
    }
    if (!sameCapabilitySet(record.capabilities, capabilities)) {
      // Capability upgrade (or downgrade) since the last pair. Conservative:
      // drop trust + show the popup so the user can review what the MCP now
      // wants. The trust-store `.put()` will overwrite the old record once
      // they approve.
      const pairCode = await derivePairCode(identityX25519Pub);
      return {
        kind: 'needs-pair',
        pairCode,
        identityHash: hash,
        mcpId: hello.mcpId,
        serverName: hello.serverName,
        domains: [...hello.domains],
        capabilities,
        version: hello.version,
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
        sessionNonce,
      };
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
      capabilities,
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
    capabilities,
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
  capabilities: string[];
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
// Track each mcpId's declared capability set so the request handler can
// reject verbs the MCP didn't ask for at pair time. 0.2.0+: defaults to
// ['fetch'] when the hello omits the field.
const mcpCapabilities = new Map<string, string[]>();

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
    mcpCapabilities.clear();
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
    mcpCapabilities.set(result.mcpId, [...result.capabilities]);
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
    capabilities: [...result.capabilities],
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
  // The tabUrl must point at the declared domain set — same envelope as
  // fetch, just enforced through a synthesised URL instead of init.url
  // (which doesn't exist for read_cookies).
  if (!isUrlAllowedForAnyDomain(req.init.tabUrl, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_cookies',
      error: `tabUrl ${req.init.tabUrl} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  const tabs = await chrome.tabs.query({});
  const match = tabs.find((t) => t.url && isTabUrlMatch(t.url, req.init.tabUrl));
  if (!match || typeof match.id !== 'number') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_cookies',
      error: `no tab matching ${req.init.tabUrl}`,
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
        id: req.id,
        ok: true,
        op: 'read_cookies',
        cookies: resp.cookies,
      });
    } else {
      await sendInner(mcpId, {
        type: 'response',
        id: req.id,
        ok: false,
        op: 'read_cookies',
        error: resp.error,
      });
    }
  } catch (e) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_cookies',
      error: `tab read_cookies failed: ${String(e)}`,
    });
  }
}

async function onApproval(approved: PendingPairRecord): Promise<void> {
  if (!trust || !sessions) return;
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
  mcpCapabilities.set(approved.mcpId, approvedCapabilities);
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
