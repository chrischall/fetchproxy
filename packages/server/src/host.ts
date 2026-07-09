import { Server as HttpServer } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import {
  ecdhX25519,
  ed25519Verify,
  concatBytes,
  fromB64,
  hkdfSha256,
  openEncryptedFrame,
  sealInnerFrame,
  validateFrame,
  derivePairCodeFromIds,
  HKDF_SESSION_INFO,
  type Capability,
  type CaptureHeaderDecl,
  type IndexedDbScopeDecl,
  type DomSelectorDecl,
  type StoragePointerDecl,
  type Frame,
  type HelloFrameFromServer,
  type HelloFrameFromExtension,
  type InnerFrame,
} from '@fetchproxy/protocol';
import { buildServerHello } from './build-server-hello.js';
import { SessionState } from './session.js';
import { awaitSessionReady } from './session-ready.js';
import type { Identity } from './identity.js';

// Reject WS upgrades from public origins (drive-by webpage defense).
// Browsers send Origin: <scheme>://<host>[:<port>] on WS upgrades from
// pages. Extensions send chrome-extension:// or null/missing. We allow:
// - Missing or null origin (extension)
// - chrome-extension://, safari-extension://, moz-extension://
// - http(s)://127.0.0.1 or localhost (dev tools / curl from same host)
// Everything else (including https://evil.com) is rejected.
const PUBLIC_ORIGIN_RE = /^https?:\/\/(?!(127\.0\.0\.1|localhost)(:|$))/i;

export interface HostOpts {
  httpServer: HttpServer;
  ownIdentity: Identity;
  ownMcpId: string;
  ownServerName: string;
  ownVersion: string;
  ownDomains: string[];
  /**
   * Inner-verb capabilities to declare on the server hello. Defaults
   * to `['fetch']` when omitted — keeps existing tests + callers that
   * pre-date the capability field compiling and behaving identically.
   */
  ownCapabilities?: Capability[];
  ownCookieKeys?: string[];
  ownLocalStorageKeys?: string[];
  ownSessionStorageKeys?: string[];
  ownCaptureHeaders?: CaptureHeaderDecl[];
  ownIndexedDbScopes?: IndexedDbScopeDecl[];
  ownLocalStoragePointers?: StoragePointerDecl[];
  ownSessionStoragePointers?: StoragePointerDecl[];
  ownDomSelectors?: DomSelectorDecl[];
  /**
   * 0.4.0+: invoked once on receipt of the extension hello with the
   * joint pair code `SHA256(mcpPub || extPub)`. The MCP can print this
   * for the user to verify against the popup. Optional — when the
   * host doesn't need to surface the code, omit it.
   */
  onPairCode?: (code: string) => void;
}

export interface HostHandle {
  close: () => Promise<void>;
  sendOwnInner: (inner: InnerFrame) => Promise<void>;
  onOwnInner: (cb: (inner: InnerFrame) => void) => void;
  onExtensionDisconnect: (cb: () => void) => void;
  /**
   * 0.5.2+: fires when the extension reports a pair-pending state for
   * the host's own mcpId (user must approve in popup before tools work).
   * Multiple subscribers supported; called once per pair-pending frame.
   */
  onPendingPair: (cb: (pairCode: string) => void) => void;
  /** The most recent pair code received via pair-pending, or null if none. */
  pendingPairCode: () => string | null;
}

interface PeerSlot {
  ws: WebSocket;
  helloFrame: HelloFrameFromServer;
}

const enc = new TextEncoder();

export async function startHost(opts: HostOpts): Promise<HostHandle> {
  const wss = new WebSocketServer({
    server: opts.httpServer,
    verifyClient: (info, cb) => {
      const origin = info.req.headers.origin;
      if (origin && PUBLIC_ORIGIN_RE.test(origin)) {
        cb(false, 403, 'origin not allowed');
        return;
      }
      cb(true);
    },
  });

  // Build own hello once at startup. The session nonce inside is what
  // the eventual ECDH session-key derivation will salt with, so we
  // recover it from the frame rather than threading it as a second
  // return value from the helper.
  const ownHello: HelloFrameFromServer = await buildServerHello({
    identity: opts.ownIdentity,
    mcpId: opts.ownMcpId,
    serverName: opts.ownServerName,
    version: opts.ownVersion,
    domains: opts.ownDomains,
    capabilities: opts.ownCapabilities,
    cookieKeys: opts.ownCookieKeys,
    localStorageKeys: opts.ownLocalStorageKeys,
    sessionStorageKeys: opts.ownSessionStorageKeys,
    captureHeaders: opts.ownCaptureHeaders,
    indexedDbScopes: opts.ownIndexedDbScopes,
    localStoragePointers: opts.ownLocalStoragePointers,
    sessionStoragePointers: opts.ownSessionStoragePointers,
    domSelectors: opts.ownDomSelectors,
  });
  const ownSessionNonce = fromB64(ownHello.sessionNonce);

  let extensionWs: WebSocket | null = null;
  const peers = new Map<string, PeerSlot>();
  const ownInnerListeners: ((inner: InnerFrame) => void)[] = [];
  const disconnectListeners: (() => void)[] = [];
  const pendingPairListeners: ((code: string) => void)[] = [];
  let ownSession: SessionState | null = null;
  // 0.5.2+: latest pair code the extension reported for our own mcpId via
  // a `pair-pending` frame. Cleared when our session derives (the user
  // approved) and on host close. Surface to MCP-level callers so they can
  // include it in tool errors instead of hanging on a missing session.
  let ownPendingPairCode: string | null = null;

  let resolveOwnSession!: (s: SessionState) => void;
  let rejectOwnSession!: (e: Error) => void;
  let ownSessionReady!: Promise<SessionState>;

  function resetSessionPromise(): void {
    ownSessionReady = new Promise<SessionState>((resolve, reject) => {
      resolveOwnSession = resolve;
      rejectOwnSession = reject;
    });
    ownSessionReady.catch(() => { /* noop */ });
  }
  resetSessionPromise();

  // 0.4.0: track the extension's hello so we can verify its ReadyFrame
  // signature against the claimed Ed25519 identity. One extension per
  // host instance; cleared on disconnect.
  let extensionHello: HelloFrameFromExtension | null = null;

  wss.on('connection', (ws) => {
    let identified: 'extension' | 'peer' | null = null;
    let peerMcpId: string | null = null;

    ws.on('message', async (data) => {
      try {
        let frame: Frame;
        try {
          const raw = JSON.parse(data.toString());
          frame = validateFrame(raw);
        } catch {
          ws.close(1002, 'protocol error');
          return;
        }

        // Hello dispatch.
        if (frame.type === 'hello' && frame.role === 'extension') {
          if (extensionWs) {
            ws.close(1008, 'extension already connected');
            return;
          }
          identified = 'extension';
          extensionWs = ws;
          extensionHello = frame;
          // 0.4.0: surface the joint pair code now that we know both
          // identities. The popup is derived from the same inputs in
          // the same order, so the two codes match iff there's no
          // MITM between this MCP and the real extension.
          if (opts.onPairCode) {
            try {
              const code = await derivePairCodeFromIds(
                opts.ownIdentity.x25519Pub,
                fromB64(frame.identityX25519Pub),
              );
              opts.onPairCode(code);
            } catch (e) {
              console.error('[fetchproxy] onPairCode threw:', e);
            }
          }
          // Send own hello first.
          ws.send(JSON.stringify(ownHello));
          // Then forward any peer hellos that arrived earlier.
          for (const slot of peers.values()) {
            ws.send(JSON.stringify(slot.helloFrame));
          }
          return;
        }
        if (frame.type === 'hello' && frame.role === 'server') {
          // FP-C: authenticate the peer hello BEFORE touching the routing
          // table. Peer registration was unauthenticated — any local process
          // could `peers.set` a foreign mcpId and overwrite a legit peer's
          // routing slot (cross-server DoS / mcpId squatting). The hello
          // already carries an Ed25519 identity + a signature over
          // `mcpId || sessionNonce`; verify it (proves the dialer holds the
          // private key it presents) before mapping the slot.
          const peerEdPub = fromB64(frame.identityEd25519Pub);
          const peerSigMsg = concatBytes(
            enc.encode(frame.mcpId),
            fromB64(frame.sessionNonce),
          );
          const peerSig = fromB64(frame.sessionSig);
          let peerSigOk = false;
          try {
            peerSigOk = await ed25519Verify(peerEdPub, peerSigMsg, peerSig);
          } catch {
            peerSigOk = false;
          }
          if (!peerSigOk) {
            console.warn(
              '[fetchproxy] peer hello signature invalid — refusing registration (possible squatter)',
            );
            ws.close(1008, 'peer hello signature invalid');
            return;
          }
          // Refuse a second LIVE connection that squats an already-mapped
          // mcpId under a DIFFERENT identity. A same-identity re-dial
          // (legitimate reconnect after a flaky drop) is allowed to take
          // over the slot — the stale socket's late close is guarded
          // (FP-B1) so it won't evict the live re-registration.
          const existing = peers.get(frame.mcpId);
          if (existing && existing.ws !== ws) {
            const existingEdPub = existing.helloFrame.identityEd25519Pub;
            if (existingEdPub !== frame.identityEd25519Pub) {
              console.warn(
                '[fetchproxy] peer mcpId already mapped to a different identity — refusing (mcpId squatting)',
              );
              ws.close(1008, 'mcpId already registered to another identity');
              return;
            }
          }
          identified = 'peer';
          peerMcpId = frame.mcpId;
          peers.set(frame.mcpId, { ws, helloFrame: frame });
          if (extensionWs) extensionWs.send(JSON.stringify(frame));
          return;
        }

        // Ready dispatch (extension → server).
        if (frame.type === 'ready') {
          if (frame.mcpId === opts.ownMcpId) {
            // 0.4.0 mutual auth: verify the extension's signature
            // over (mcpHelloNonce || extHelloNonce) against the
            // claimed Ed25519 identity in the extension hello. A
            // MITM-as-extension process can either substitute its own
            // identity (visibly different pair code) or relay the
            // real extension's bytes (signature won't verify because
            // the MCP nonce differs). Tear the WS down on mismatch.
            if (!extensionHello) {
              console.warn('[fetchproxy] ready before extension hello — closing');
              ws.close(1002, 'ready before extension hello');
              return;
            }
            const extEdPub = fromB64(extensionHello.identityEd25519Pub);
            const extNonce = fromB64(extensionHello.sessionNonce);
            const msg = concatBytes(ownSessionNonce, extNonce);
            const sig = fromB64(frame.sessionSig);
            let sigOk = false;
            try {
              sigOk = await ed25519Verify(extEdPub, msg, sig);
            } catch {
              sigOk = false;
            }
            if (!sigOk) {
              console.warn(
                '[fetchproxy] extension session signature invalid — closing (possible MITM)',
              );
              ws.close(1008, 'extension session signature invalid');
              return;
            }
            // Derive our own session key. The ECDH + HKDF calls are async
            // and yield to the event loop — the extension WS may close
            // during derivation. Guard afterward to avoid resolving the
            // session promise with a stale key.
            const extPub = fromB64(frame.extensionSessionPub);
            const shared = await ecdhX25519(opts.ownIdentity.x25519Priv, extPub);
            const key = await hkdfSha256(
              shared,
              ownSessionNonce,
              enc.encode(HKDF_SESSION_INFO),
              32,
            );
            if (extensionWs !== ws) return;
            ownSession = new SessionState(key);
            // 0.5.2+: receiving a ready means the user has approved (auto-
            // trust path) or just approved (popup path) — the pair-pending
            // hint is no longer actionable, so clear it.
            ownPendingPairCode = null;
            resolveOwnSession(ownSession);
          } else {
            const slot = peers.get(frame.mcpId);
            if (slot) slot.ws.send(JSON.stringify(frame));
          }
          return;
        }

        // Encrypted-frame dispatch.
        if (frame.type === 'frame') {
          if (identified === 'extension') {
            // Extension → server. Route by mcpId.
            if (frame.mcpId === opts.ownMcpId) {
              if (!ownSession) return;
              if (!ownSession.acceptInboundSeq(frame.seq)) return;
              const inner = await openEncryptedFrame(ownSession.sessionKey, frame);
              ownInnerListeners.forEach((cb) => cb(inner));
            } else {
              const slot = peers.get(frame.mcpId);
              if (slot) slot.ws.send(JSON.stringify(frame));
            }
          } else if (identified === 'peer') {
            // Peer → extension. Forward verbatim.
            if (extensionWs) extensionWs.send(JSON.stringify(frame));
          }
        }

        // 0.5.2+: pair-pending dispatch. Only the extension sends these
        // (one per MCP whose hello triggered a needs-pair queue). Route
        // by mcpId: own → record + fire onPairCode; peer → forward.
        if (frame.type === 'pair-pending' && identified === 'extension') {
          if (frame.mcpId === opts.ownMcpId) {
            ownPendingPairCode = frame.pairCode;
            pendingPairListeners.forEach((cb) => cb(frame.pairCode));
          } else {
            const slot = peers.get(frame.mcpId);
            if (slot) slot.ws.send(JSON.stringify(frame));
          }
        }
      } catch (e) {
        // Any throw from JSON.parse, crypto (ecdhX25519, hkdfSha256,
        // openEncryptedFrame), or downstream listeners would otherwise become
        // an unhandled rejection and crash Node 18+. Log and tear the socket
        // down so the peer can reconnect cleanly.
        // eslint-disable-next-line no-console
        console.error('[fetchproxy] host: message handler error:', e);
        try { ws.close(1011, 'internal error'); } catch { /* noop */ }
      }
    });

    ws.on('close', () => {
      if (identified === 'extension' && extensionWs === ws) {
        extensionWs = null;
        extensionHello = null;
        if (!ownSession) {
          rejectOwnSession(new Error('extension disconnected before ready'));
        }
        ownSession = null;
        resetSessionPromise();
        disconnectListeners.forEach((cb) => cb());
      }
      if (identified === 'peer' && peerMcpId) {
        // FP-B1: a peer whose WS dropped may have already re-dialed with the
        // same mcpId, replacing this slot via `peers.set`. Only delete if the
        // mapped slot is still THIS socket — otherwise a late, stale close
        // would evict the live (re-registered) peer and strand it until its
        // next reconnect.
        if (peers.get(peerMcpId)?.ws === ws) peers.delete(peerMcpId);
      }
    });
  });

  return {
    close: () =>
      new Promise<void>((resolve) => {
        // Forcibly terminate any still-attached clients (extension + peers) so
        // `wss.close()` can drain — by default `ws` only stops accepting new
        // connections and waits for existing ones to close on their own. In
        // production a host shutdown should drop its peers too.
        for (const client of wss.clients) {
          try {
            client.terminate();
          } catch {
            // ignore — best-effort cleanup
          }
        }
        // `wss.close()` only detaches the WS upgrade handler — it does NOT
        // close an externally-provided HTTP server (the one electRole bound
        // to the port). Close that too, or the port stays bound until process
        // exit: a leaked listener, and a blocker for a same-process
        // re-election after this host steps down (0.13.0+ peer re-host).
        wss.close(() => {
          opts.httpServer.close(() => resolve());
        });
      }),
    sendOwnInner: async (inner) => {
      // Wait for the extension's ready frame to land and the session key to be
      // derived — mirrors the peer's `sendInner` which awaits `sessionPromise`.
      // Bounded so a never-confirmed session (pending re-approval, signed out)
      // surfaces a clear FetchproxySessionNotReadyError instead of hanging.
      const session = await awaitSessionReady(ownSessionReady, {
        mcpId: opts.ownMcpId,
        pendingPairCode: () => ownPendingPairCode,
      });
      if (!extensionWs) throw new Error('host: no extension connected');
      const sealed = await sealInnerFrame(
        session.sessionKey,
        opts.ownMcpId,
        session.nextOutboundSeq(),
        inner,
      );
      extensionWs.send(JSON.stringify(sealed));
    },
    onOwnInner: (cb) => { ownInnerListeners.push(cb); },
    onExtensionDisconnect: (cb) => { disconnectListeners.push(cb); },
    onPendingPair: (cb) => { pendingPairListeners.push(cb); },
    pendingPairCode: () => ownPendingPairCode,
  };
}
