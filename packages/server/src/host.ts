import { Server as HttpServer } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import {
  ecdhX25519,
  fromB64,
  hkdfSha256,
  openEncryptedFrame,
  sealInnerFrame,
  validateFrame,
  type Capability,
  type CaptureHeaderDecl,
  type Frame,
  type HelloFrameFromServer,
  type InnerFrame,
} from '@fetchproxy/protocol';
import { buildServerHello } from './build-server-hello.js';
import { SessionState } from './session.js';
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
}

export interface HostHandle {
  close: () => Promise<void>;
  sendOwnInner: (inner: InnerFrame) => Promise<void>;
  onOwnInner: (cb: (inner: InnerFrame) => void) => void;
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
  });
  const ownSessionNonce = fromB64(ownHello.sessionNonce);

  let extensionWs: WebSocket | null = null;
  const peers = new Map<string, PeerSlot>();
  const ownInnerListeners: ((inner: InnerFrame) => void)[] = [];
  let ownSession: SessionState | null = null;
  // Deferred promise that resolves the first time the extension's ready frame
  // arrives and we derive the session key. `sendOwnInner` awaits this so a
  // caller can issue fetch() without racing the handshake — the host's session
  // is set asynchronously from a WS message handler.
  let resolveOwnSession!: (s: SessionState) => void;
  let rejectOwnSession!: (e: Error) => void;
  const ownSessionReady: Promise<SessionState> = new Promise<SessionState>((resolve, reject) => {
    resolveOwnSession = resolve;
    rejectOwnSession = reject;
  });
  // Swallow unhandled-rejection noise when nobody is awaiting ownSessionReady
  // at the moment we reject (e.g. extension disconnects before any
  // sendOwnInner caller has subscribed). The rejection is still surfaced to
  // any later await.
  ownSessionReady.catch(() => { /* noop */ });

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
          // Send own hello first.
          ws.send(JSON.stringify(ownHello));
          // Then forward any peer hellos that arrived earlier.
          for (const slot of peers.values()) {
            ws.send(JSON.stringify(slot.helloFrame));
          }
          return;
        }
        if (frame.type === 'hello' && frame.role === 'server') {
          identified = 'peer';
          peerMcpId = frame.mcpId;
          peers.set(frame.mcpId, { ws, helloFrame: frame });
          if (extensionWs) extensionWs.send(JSON.stringify(frame));
          return;
        }

        // Ready dispatch (extension → server).
        if (frame.type === 'ready') {
          if (frame.mcpId === opts.ownMcpId) {
            // Derive our own session key.
            const extPub = fromB64(frame.extensionSessionPub);
            const shared = await ecdhX25519(opts.ownIdentity.x25519Priv, extPub);
            const key = await hkdfSha256(
              shared,
              ownSessionNonce,
              enc.encode('fetchproxy/0.1.0/session'),
              32,
            );
            if (!ownSession) {
              ownSession = new SessionState(key);
              resolveOwnSession(ownSession);
            }
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
        // If the extension dropped before we ever derived our own session key,
        // unblock any pending sendOwnInner awaiter with an actionable error
        // rather than letting them hang forever.
        if (!ownSession) {
          rejectOwnSession(new Error('extension disconnected before ready'));
        }
      }
      if (identified === 'peer' && peerMcpId) peers.delete(peerMcpId);
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
        wss.close(() => resolve());
      }),
    sendOwnInner: async (inner) => {
      // Wait for the extension's ready frame to land and the session key to be
      // derived — mirrors the peer's `sendInner` which awaits `sessionPromise`.
      const session = await ownSessionReady;
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
  };
}
