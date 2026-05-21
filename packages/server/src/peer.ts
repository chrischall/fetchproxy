import { WebSocket } from 'ws';
import {
  ed25519Sign,
  ecdhX25519,
  hkdfSha256,
  sealInnerFrame,
  openEncryptedFrame,
  validateFrame,
  toB64,
  concatBytes,
  PROTOCOL_VERSION,
  type Capability,
  type HelloFrameFromServer,
  type InnerFrame,
} from '@fetchproxy/protocol';
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
}

export interface PeerHandle {
  ws: WebSocket;
  /** Resolves once the ready handshake has completed and sessionKey is derived. */
  session: Promise<SessionState>;
  sendInner: (inner: InnerFrame) => Promise<void>;
  onInner: (cb: (inner: InnerFrame) => void) => void;
  close: () => void;
}

const enc = new TextEncoder();

export async function startPeer(opts: PeerOpts): Promise<PeerHandle> {
  const ws = new WebSocket(`ws://${opts.host}:${opts.port}`);
  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });

  // Generate fresh session nonce + signature.
  const sessionNonce = new Uint8Array(32);
  (globalThis.crypto as Crypto).getRandomValues(sessionNonce);
  const sigMsg = concatBytes(enc.encode(opts.mcpId), sessionNonce);
  const sessionSig = await ed25519Sign(opts.identity.ed25519Priv, sigMsg);

  // Send our hello first thing.
  const hello: HelloFrameFromServer = {
    type: 'hello',
    protocolVersion: PROTOCOL_VERSION,
    role: 'server',
    mcpId: opts.mcpId,
    serverName: opts.serverName,
    version: opts.version,
    domains: [...opts.domains],
    capabilities: [...(opts.capabilities ?? ['fetch'])],
    identityX25519Pub: toB64(opts.identity.x25519Pub),
    identityEd25519Pub: toB64(opts.identity.ed25519Pub),
    sessionNonce: toB64(sessionNonce),
    sessionSig: toB64(sessionSig),
  };
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
          const extPub = new Uint8Array(Buffer.from(frame.extensionSessionPub, 'base64'));
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

  const handle: PeerHandle = {
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
