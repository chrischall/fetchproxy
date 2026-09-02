import { Server as HttpServer } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import {
  ecdhX25519,
  ed25519Verify,
  concatBytes,
  readySignaturePayload,
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
  type GraphqlOpDeclaration,
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
import { decideExtensionTrust, type ExtensionTrustPort } from './extension-trust.js';

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
  ownGraphqlOps?: GraphqlOpDeclaration[];
  /**
   * 0.4.0+: invoked once on receipt of the extension hello with the
   * joint pair code `SHA256(mcpPub || extPub)`. The MCP can print this
   * for the user to verify against the popup. Optional — when the
   * host doesn't need to surface the code, omit it.
   */
  onPairCode?: (code: string) => void;
  /**
   * 1.12.0+ (#208): where this MCP's pin on the extension's identity lives.
   *
   * REQUIRED, and deliberately not defaulted. A default would have to be the
   * file store under `$HOME`, which means every caller that forgot to think
   * about it — including a unit test — would either write into the user's real
   * identity directory or, worse, be handed a store that answers "no pin" and
   * so trusts anybody. Making it an argument means each caller states what its
   * trust store is.
   */
  extensionTrust: ExtensionTrustPort;
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
  /** 2.5.0: whether an extension socket is attached right now. */
  extensionConnected: () => boolean;
  /** 2.5.0: whether a session key exists — the extension's ready landed and verified. */
  sessionLinked: () => boolean;
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
    graphqlOps: opts.ownGraphqlOps,
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
  // 1.12.0 (#208): the socket that has claimed the extension slot but has not
  // finished being vetted. Held from the synchronous moment its hello arrives
  // until it either becomes `extensionWs` or is refused, so the check-and-set
  // around an awaited pin read cannot interleave with a second hello.
  let extensionClaim: WebSocket | null = null;

  wss.on('connection', (ws) => {
    let identified: 'extension' | 'peer' | null = null;
    let peerMcpId: string | null = null;
    // Set the instant this socket closes, so code resuming after an await can
    // tell "gone" from "still here" without depending on `readyState`
    // bookkeeping or on having been identified yet.
    let closed = false;
    // 1.12.0 (#208): THIS connection's identity is not yet in the trust store
    // (first contact, or an operator-allowed replacement) and should be written
    // there the moment its signature verifies. Per-connection by scope rather
    // than by discipline: a host-wide flag would outlive the socket that set
    // it, and "which connection was this decided for" is not something the
    // ready handler should have to reason about.
    let pinOnReady = false;

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
          if (extensionWs || extensionClaim) {
            ws.close(1008, 'extension already connected');
            return;
          }
          // Claim the slot SYNCHRONOUSLY, before the first await. Reading the
          // pin yields to the event loop, so a second extension hello arriving
          // in that window would otherwise pass the guard above — two
          // connections both believing they are the extension, with the later
          // one's `pinOnReady` deciding what gets written. The claim is
          // released on any refusal below and on close.
          extensionClaim = ws;
          // #208: is this the extension we paired with? Checked HERE, before
          // the connection becomes the extension slot, so a stranger never
          // reaches the session machinery at all. The pin is only WRITTEN
          // later, once the ready signature has proved the key — claiming an
          // identity must not be enough to become the pinned one.
          let pin: Awaited<ReturnType<ExtensionTrustPort['read']>>;
          try {
            pin = await opts.extensionTrust.read();
          } catch (e) {
            // An unreadable pin is the one state where carrying on would
            // quietly mean "trust anybody".
            console.error(`[fetchproxy] ${String(e)}`);
            if (extensionClaim === ws) extensionClaim = null;
            ws.close(1008, 'extension pin unreadable');
            return;
          }
          const outcome = decideExtensionTrust({
            pin,
            hello: frame,
            allowNew: opts.extensionTrust.allowNew,
            serverName: opts.ownServerName,
            location: opts.extensionTrust.location,
          });
          if (outcome.decision === 'refused') {
            console.warn(outcome.message);
            if (extensionClaim === ws) extensionClaim = null;
            ws.close(1008, 'extension identity is not the pinned one');
            return;
          }
          if (outcome.decision === 'replace') console.warn(outcome.message);
          // The read above yielded, so this socket may have gone while we were
          // in it. Taking the slot for a connection that is already closed is
          // worse than the race the claim closes: its close event has ALREADY
          // fired, so nothing would ever clear `extensionWs`, and every later
          // extension would be refused "already connected" until the process
          // restarts. Check liveness, not just identity.
          if (closed || ws.readyState !== WebSocket.OPEN) {
            // Only OUR claim. The close handler may already have released it
            // and a newer connection may hold it by now: clearing
            // unconditionally would drop that one, letting two sockets past
            // the guard and both reach `extensionWs` — the interleaving this
            // claim exists to prevent, reintroduced by its own cleanup.
            if (extensionClaim === ws) extensionClaim = null;
            return;
          }
          // Pin on first use, or replace a pin the operator chose to drop —
          // but only after the ready frame proves the key (see below).
          pinOnReady = outcome.decision !== 'pinned';
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
          // 1.12.0 (#208): relay this hello to every peer, so a peer can
          // authenticate the extension behind us instead of taking whatever
          // `ready` we hand it on trust. Peers before 1.12.0 ignore the frame.
          for (const slot of peers.values()) slot.ws.send(JSON.stringify(frame));
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
          // 1.12.0 (#208): a peer joining an already-connected extension needs
          // the same identity material a peer that was here first receives.
          if (extensionHello) ws.send(JSON.stringify(extensionHello));
          return;
        }

        // Ready dispatch (extension → server).
        if (frame.type === 'ready') {
          if (frame.mcpId === opts.ownMcpId) {
            // 0.4.0 mutual auth: verify the extension's signature
            // over (mcpHelloNonce || extHelloNonce) against the
            // claimed Ed25519 identity in the extension hello. This
            // stops a process BEING the extension without its key —
            // substituting its own identity shows up as a different
            // pair code, and forging a signature needs the key.
            //
            // 2.0.0: it also stops a relay that forwards the real
            // hellos and the real signature, because the payload now
            // covers `extensionSessionPub` — the value the ECDH
            // actually depends on. Under v2 it did not, and an even
            // earlier version of this comment claimed such a relay
            // fails "because the MCP nonce differs", which was only
            // ever true of a MITM that terminates our connection with a
            // hello of its own. See docs/SECURITY.md §T-host-MITM.
            // Tear the WS down on mismatch.
            if (!extensionHello) {
              console.warn('[fetchproxy] ready before extension hello — closing');
              ws.close(1002, 'ready before extension hello');
              return;
            }
            const extEdPub = fromB64(extensionHello.identityEd25519Pub);
            const extNonce = fromB64(extensionHello.sessionNonce);
            const msg = readySignaturePayload(
              ownSessionNonce,
              extNonce,
              fromB64(frame.extensionSessionPub),
            );
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
            // #208: the signature just proved this connection holds the key
            // it presented, which is the only moment at which committing to
            // it is meaningful. Written before the session derives so a pin
            // is never skipped by a later failure.
            if (pinOnReady) {
              pinOnReady = false;
              try {
                await opts.extensionTrust.write({
                  identityX25519Pub: extensionHello.identityX25519Pub,
                  identityEd25519Pub: extensionHello.identityEd25519Pub,
                  pinnedAt: Date.now(),
                });
              } catch (e) {
                // Don't take the session down over a failed write — the
                // handshake itself was sound. But say so: an MCP that cannot
                // persist its pin will trust on first use again next boot.
                console.error(`[fetchproxy] could not persist the extension pin: ${String(e)}`);
              }
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
      closed = true;
      if (extensionClaim === ws) extensionClaim = null;
      if (identified === 'extension' && extensionWs === ws) {
        extensionWs = null;
        extensionHello = null;
        if (!ownSession) {
          rejectOwnSession(new Error('extension disconnected before ready'));
        }
        ownSession = null;
        resetSessionPromise();
        disconnectListeners.forEach((cb) => cb());
        // 2.5.0: tell the peers that can take it. A peer before 2.5.0 would
        // refuse the frame type in its validator, so it is gated on what the
        // peer's hello advertised — those peers keep their last-known view.
        const notice = JSON.stringify({ type: 'extension-disconnected' });
        for (const slot of peers.values()) {
          if (slot.helloFrame.accepts?.includes('extension-disconnected')) {
            try { slot.ws.send(notice); } catch { /* peer already gone */ }
          }
        }
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
    extensionConnected: () => extensionWs !== null,
    sessionLinked: () => ownSession !== null,
  };
}
