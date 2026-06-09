import { WebSocket } from 'ws';
import {
  ecdhX25519,
  fromB64,
  hkdfSha256,
  HKDF_SESSION_INFO,
  openEncryptedFrame,
  sealInnerFrame,
  validateFrame,
  type Capability,
  type CaptureHeaderDecl,
  type IndexedDbScopeDecl,
  type StoragePointerDecl,
  type InnerFrame,
} from '@fetchproxy/protocol';
import { buildServerHello } from './build-server-hello.js';
import { SessionState } from './session.js';
import { awaitSessionReady } from './session-ready.js';
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
  localStoragePointers?: StoragePointerDecl[];
  sessionStoragePointers?: StoragePointerDecl[];
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
  /**
   * Subscribe to session renegotiation. Fires when a NEW ready frame
   * arrives for our mcpId after the first one — i.e. the extension
   * dropped (most commonly MV3 service-worker eviction) and reconnected,
   * causing the host to replay our hello and a fresh ephemeral keypair
   * to be derived on both ends. Any in-flight requests sent under the
   * old session key are now unreachable (the extension forgot them);
   * subscribers should reject their pending awaiters so callers fail
   * fast instead of hanging until the MCP-level timeout. The next
   * `sendInner` call will use the new session key automatically.
   */
  onRenegotiate: (cb: () => void) => void;
  /**
   * 0.5.2+: fires when the host forwards a `pair-pending` frame for our
   * mcpId — the extension queued us for the user to approve in the
   * popup and we won't get a ready frame (or a working session) until
   * they do. Cleared when a ready frame arrives.
   */
  onPendingPair: (cb: (pairCode: string) => void) => void;
  /** The most recent pair code received via pair-pending, or null if none. */
  pendingPairCode: () => string | null;
  /**
   * 0.13.0+: fires when the WebSocket to the host closes — most importantly
   * when the host process dies, stranding this peer. The owning
   * `FetchproxyServer` uses this to tear down the dead peer handle and
   * re-elect (becoming the new host if the port is now free). Fires on ANY
   * close, including our own `close()`; the peer is intent-agnostic, so the
   * owner decides what a close means.
   */
  onClose: (cb: () => void) => void;
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
    localStoragePointers: opts.localStoragePointers,
    sessionStoragePointers: opts.sessionStoragePointers,
  });
  const sessionNonce = fromB64(hello.sessionNonce);
  ws.send(JSON.stringify(hello));

  const innerListeners: ((inner: InnerFrame) => void)[] = [];
  const renegotiateListeners: (() => void)[] = [];
  const pendingPairListeners: ((code: string) => void)[] = [];
  const closeListeners: (() => void)[] = [];
  // `session` is the LATEST session derived from a ready frame. Every ready
  // frame for our mcpId replaces it — the extension can renegotiate at any
  // time (most commonly after MV3 service-worker eviction reconnects the
  // browser side and the host replays our hello). `sendInner` reads
  // `session` at call time, not at handshake time, so sealing always uses
  // the current key.
  let session: SessionState | null = null;
  // 0.5.2+: latest pair code the host has forwarded for our mcpId. Set on
  // pair-pending; cleared on the next ready (user approved). MCP-level
  // callers consult it to fail tool calls fast with an actionable error
  // instead of waiting on a session promise that never resolves.
  let pendingPairCode: string | null = null;

  // `sessionPromise` fires once: it gates the first `sendInner` until the
  // initial ready arrives. After that, renegotiations update `session` in
  // place without re-creating the promise.
  let resolveFirstReady!: (s: SessionState) => void;
  let rejectFirstReady!: (e: Error) => void;
  const sessionPromise = new Promise<SessionState>((resolve, reject) => {
    resolveFirstReady = resolve;
    rejectFirstReady = reject;
  });

  const onMessage = async (data: WebSocket.RawData): Promise<void> => {
    try {
      const raw = JSON.parse(data.toString());
      const frame = validateFrame(raw);
      if (frame.type === 'ready' && frame.mcpId === opts.mcpId) {
        // Derive a fresh sessionKey from this ready's ephemeral pub.
        const extPub = fromB64(frame.extensionSessionPub);
        const shared = await ecdhX25519(opts.identity.x25519Priv, extPub);
        const sessionKey = await hkdfSha256(
          shared,
          sessionNonce,
          enc.encode(HKDF_SESSION_INFO),
          32,
        );
        const isRenegotiation = session !== null;
        session = new SessionState(sessionKey);
        // 0.5.2+: ready means the user approved; the pair-pending hint is
        // no longer actionable. Clear so subsequent `pendingPairCode()`
        // queries don't return a stale code from before this approval.
        pendingPairCode = null;
        if (isRenegotiation) {
          // Extension reconnected and forgot the old session state. Any
          // request the caller sent under the old key is unreachable now —
          // notify the upstream caller (FetchproxyServer.rejectAllPending)
          // so its awaiters fail fast with "extension disconnected" rather
          // than hanging until the MCP-level timeout.
          renegotiateListeners.forEach((cb) => cb());
        } else {
          resolveFirstReady(session);
        }
        return;
      }
      // 0.5.2+: pair-pending notification forwarded by the host. Record so
      // the upstream caller can include the code in tool errors instead of
      // hanging on a session promise that will never resolve until the user
      // approves the popup.
      if (frame.type === 'pair-pending' && frame.mcpId === opts.mcpId) {
        pendingPairCode = frame.pairCode;
        pendingPairListeners.forEach((cb) => cb(frame.pairCode));
        return;
      }
      if (frame.type === 'frame' && frame.mcpId === opts.mcpId) {
        if (!session) return; // ignore encrypted frames before handshake
        if (!session.acceptInboundSeq(frame.seq)) return;
        try {
          const inner = await openEncryptedFrame(session.sessionKey, frame);
          innerListeners.forEach((cb) => cb(inner));
        } catch {
          // Decryption failure typically means a straggler frame from a
          // previous session (extension reconnected mid-flight). Drop it
          // silently — the next legitimate frame on the new key will land.
        }
      }
    } catch (e) {
      rejectFirstReady(e instanceof Error ? e : new Error(String(e)));
    }
  };
  ws.on('message', onMessage);
  // If the host drops mid-handshake (e.g. host crashed before sending
  // ready, or our hello was rejected), unblock any pending sendInner so it
  // surfaces an error rather than hanging forever. Once `resolveFirstReady`
  // has fired, subsequent `rejectFirstReady` calls are no-ops, so this is
  // safe to wire unconditionally.
  ws.once('close', () => {
    rejectFirstReady(new Error('peer WS closed before ready'));
    // 0.13.0+: notify the owner the host link dropped, so it can tear down
    // this stranded handle and re-elect. Fires after rejectFirstReady so a
    // pre-ready close still surfaces the original error to in-flight awaiters.
    closeListeners.forEach((cb) => cb());
  });
  // Swallow unhandled-rejection noise when no caller has subscribed to
  // sessionPromise at the moment we reject. The rejection is still surfaced
  // to any later `await sessionPromise`.
  sessionPromise.catch(() => { /* noop */ });

  const handle: InternalPeerHandle = {
    ws,
    session: sessionPromise,
    sendInner: async (inner: InnerFrame) => {
      // Wait for the FIRST ready; subsequent renegotiations swap `session`
      // in place, so we read it freshly here rather than reusing the
      // promise's resolved value (which is permanently the first session).
      // Bounded so a never-confirmed session surfaces a clear
      // FetchproxySessionNotReadyError instead of hanging indefinitely.
      await awaitSessionReady(sessionPromise, {
        mcpId: opts.mcpId,
        pendingPairCode: () => pendingPairCode,
      });
      // Invariant: `session` is non-null once `sessionPromise` has resolved
      // — the only assignment path is `session = new SessionState(...)` two
      // statements before `resolveFirstReady(session)`, and there is no
      // code path that sets `session` back to null. Renegotiation only
      // ever replaces it with another non-null SessionState. The non-null
      // assertion is load-bearing for TypeScript's narrowing but does not
      // encode runtime hope.
      const s = session!;
      const sealed = await sealInnerFrame(
        s.sessionKey,
        opts.mcpId,
        s.nextOutboundSeq(),
        inner,
      );
      ws.send(JSON.stringify(sealed));
    },
    onInner: (cb) => {
      innerListeners.push(cb);
    },
    onRenegotiate: (cb) => {
      renegotiateListeners.push(cb);
    },
    onPendingPair: (cb) => {
      pendingPairListeners.push(cb);
    },
    pendingPairCode: () => pendingPairCode,
    onClose: (cb) => {
      closeListeners.push(cb);
    },
    close: () => ws.close(),
  };
  return handle;
}
