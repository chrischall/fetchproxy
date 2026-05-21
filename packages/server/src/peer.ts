import { WebSocket } from 'ws';
import {
  ecdhX25519,
  fromB64,
  hkdfSha256,
  openEncryptedFrame,
  sealInnerFrame,
  validateFrame,
  type Capability,
  type CaptureHeaderDecl,
  type IndexedDbScopeDecl,
  type InnerFrame,
} from '@fetchproxy/protocol';
import { buildServerHello } from './build-server-hello.js';
import { SessionState } from './session.js';
import type { Identity } from './identity.js';

export interface PeerOpts {
  host: string;
  port: number;
  identity: Identity;
  mcpId: string;
  serverName: string;
  version: string;
  domains: string[];
  /**
   * Inner-verb capabilities to declare on the peer's hello. Defaults
   * to `['fetch']` when omitted — keeps pre-capability callers compiling
   * and behaving identically on the wire.
   */
  capabilities?: Capability[];
  cookieKeys?: string[];
  localStorageKeys?: string[];
  sessionStorageKeys?: string[];
  captureHeaders?: CaptureHeaderDecl[];
  indexedDbScopes?: IndexedDbScopeDecl[];
}

/**
 * Public peer handle used by `FetchproxyServer` to send + receive
 * inner frames and to close the WebSocket. The bare WebSocket and the
 * session-key promise are NOT part of this surface — they live on
 * `InternalPeerHandle` below, which the peer's test suite reaches into
 * for handshake-level assertions but normal callers must not touch.
 */
export interface PeerHandle {
  sendInner: (inner: InnerFrame) => Promise<void>;
  onInner: (cb: (inner: InnerFrame) => void) => void;
  close: () => void;
}

/**
 * Internal-only extension of `PeerHandle`. Used by `peer.test.ts` to
 * verify the underlying WS handshake and (some day) by host-side code
 * that wants to assert on the derived session key. Not exported from
 * `@fetchproxy/server`'s public surface — anything that imports this
 * type is opting in to the internal contract.
 */
export interface InternalPeerHandle extends PeerHandle {
  ws: WebSocket;
  /** Resolves once the ready handshake has completed and sessionKey is derived. */
  session: Promise<SessionState>;
}

const enc = new TextEncoder();

export async function startPeer(opts: PeerOpts): Promise<InternalPeerHandle> {
  const ws = new WebSocket(`ws://${opts.host}:${opts.port}`);
  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });

  // Send our hello first thing. The session nonce inside is the salt
  // for the eventual ECDH-derived session key — recover it from the
  // frame on demand rather than threading a second variable through.
  const hello = await buildServerHello({
    identity: opts.identity,
    mcpId: opts.mcpId,
    serverName: opts.serverName,
    version: opts.version,
    domains: opts.domains,
    capabilities: opts.capabilities,
    cookieKeys: opts.cookieKeys,
    localStorageKeys: opts.localStorageKeys,
    sessionStorageKeys: opts.sessionStorageKeys,
    captureHeaders: opts.captureHeaders,
    indexedDbScopes: opts.indexedDbScopes,
  });
  const sessionNonce = fromB64(hello.sessionNonce);
  ws.send(JSON.stringify(hello));

  const innerListeners: ((inner: InnerFrame) => void)[] = [];
  let session: SessionState | null = null;

  const sessionPromise = new Promise<SessionState>((resolve, reject) => {
    const onMessage = async (data: WebSocket.RawData): Promise<void> => {
      try {
        const raw = JSON.parse(data.toString());
        const frame = validateFrame(raw);
        if (frame.type === 'ready' && frame.mcpId === opts.mcpId) {
          // Derive sessionKey.
          const extPub = fromB64(frame.extensionSessionPub);
          const shared = await ecdhX25519(opts.identity.x25519Priv, extPub);
          const sessionKey = await hkdfSha256(
            shared,
            sessionNonce,
            enc.encode('fetchproxy/0.1.0/session'),
            32,
          );
          session = new SessionState(sessionKey);
          resolve(session);
          return;
        }
        if (frame.type === 'frame' && frame.mcpId === opts.mcpId) {
          if (!session) return; // ignore encrypted frames before handshake
          if (!session.acceptInboundSeq(frame.seq)) return;
          const inner = await openEncryptedFrame(session.sessionKey, frame);
          innerListeners.forEach((cb) => cb(inner));
        }
      } catch (e) {
        reject(e instanceof Error ? e : new Error(String(e)));
      }
    };
    ws.on('message', onMessage);
    // If the host drops mid-handshake (e.g. host crashed before sending
    // ready, or our hello was rejected), unblock any pending sendInner so it
    // surfaces an error rather than hanging forever. Once `resolve` has
    // fired, subsequent `reject` calls are no-ops, so this is safe to wire
    // unconditionally.
    ws.once('close', () => {
      reject(new Error('peer WS closed before ready'));
    });
  });
  // Swallow unhandled-rejection noise when no caller has subscribed to
  // sessionPromise at the moment we reject. The rejection is still surfaced
  // to any later `await sessionPromise`.
  sessionPromise.catch(() => { /* noop */ });

  const handle: InternalPeerHandle = {
    ws,
    session: sessionPromise,
    sendInner: async (inner: InnerFrame) => {
      const s = await sessionPromise;
      const sealed = await sealInnerFrame(s.sessionKey, opts.mcpId, s.nextOutboundSeq(), inner);
      ws.send(JSON.stringify(sealed));
    },
    onInner: (cb) => {
      innerListeners.push(cb);
    },
    close: () => ws.close(),
  };
  return handle;
}
