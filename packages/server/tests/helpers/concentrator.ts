import { WebSocketServer, WebSocket } from 'ws';
import {
  ecdhX25519,
  ed25519Sign,
  generateEd25519,
  generateX25519,
  hkdfSha256,
  readySignaturePayload,
  transcriptHash,
  validateFrame,
  fromB64,
  toB64,
  HKDF_SESSION_INFO,
  PROTOCOL_VERSION,
  type HelloFrameFromExtension,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import type { ExtensionPin } from '../../src/extension-trust.js';
import { listenEphemeral, loopbackWss } from './ephemeral-port.js';

/**
 * A concentrator as a PEER sees it, plus the browser identity behind it —
 * because under v4 a peer that is never relayed an extension hello can derive
 * nothing at all, so the two are no longer separable in a test.
 *
 * The peer's "connection" is not a socket: its one socket goes to the host and
 * outlives every extension session, which arrive on it as relayed hellos and
 * `extension-disconnected` notices. So this helper's verbs are those EVENTS
 * rather than connects and closes.
 */
export interface FakeExtension {
  hello: HelloFrameFromExtension;
  sessionNonce: Uint8Array;
  ed25519Priv: Uint8Array;
  pin(pinnedAt?: number): ExtensionPin;
}

/**
 * A browser identity plus one connection's nonce.
 *
 * Pass `sameBrowserAs` to model an MV3 reconnect: the SAME long-term identity
 * (so the peer's pin still matches) with a fresh per-connection nonce (so the
 * transcript, and therefore the session key, differs). Minting a new identity
 * instead is a different browser, which a pinned peer correctly refuses —
 * which is easy to write by accident and reads as a v4 bug.
 */
export async function newFakeExtension(
  sameBrowserAs?: FakeExtension,
): Promise<FakeExtension> {
  const sessionNonce = new Uint8Array(32);
  (globalThis.crypto as Crypto).getRandomValues(sessionNonce);
  if (sameBrowserAs) {
    const hello: HelloFrameFromExtension = {
      ...sameBrowserAs.hello,
      sessionNonce: toB64(sessionNonce),
    };
    return {
      hello,
      sessionNonce,
      ed25519Priv: sameBrowserAs.ed25519Priv,
      pin: sameBrowserAs.pin,
    };
  }
  const x = await generateX25519();
  const ed = await generateEd25519();
  const hello: HelloFrameFromExtension = {
    type: 'hello',
    protocolVersion: PROTOCOL_VERSION,
    role: 'extension',
    platform: 'chrome',
    extensionId: 'fetchproxy',
    version: '3.0.0',
    identityX25519Pub: toB64(x.publicKey),
    identityEd25519Pub: toB64(ed.publicKey),
    sessionNonce: toB64(sessionNonce),
  };
  return {
    hello,
    sessionNonce,
    ed25519Priv: ed.privateKey,
    pin: (pinnedAt = 1_700_000_000_000) => ({
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
      pinnedAt,
    }),
  };
}

export interface FakeConcentrator {
  port: number;
  /** The peer's socket, once it has dialled in. */
  socket(): Promise<WebSocket>;
  /** Every server hello the peer has sent, oldest first. */
  hellos(): HelloFrameFromServer[];
  /** Wait until at least `nth + 1` server hellos have arrived; return the nth. */
  waitForHello(nth?: number): Promise<HelloFrameFromServer>;
  /** Every frame the peer has sent, of any type. */
  sent(): Record<string, unknown>[];
  /**
   * Wait until the peer has sent at least `count` ENCRYPTED frames and return
   * them. `sendInner` resolves when the socket has been written to, which is
   * one event-loop hop before this side has read it — so a test that counts
   * immediately after it counts zero.
   */
  waitForFrames(count?: number): Promise<Record<string, unknown>[]>;
  send(frame: unknown): Promise<void>;
  /** Relay an extension hello — the peer's Rule A mint trigger. */
  relayExtensionHello(ext: FakeExtension): Promise<void>;
  relayExtensionDisconnected(): Promise<void>;
  /**
   * Answer one of the peer's hellos with a `ready`, as the browser does under
   * v4. Resolves with the session key both ends should now hold.
   */
  answerReady(
    ext: FakeExtension,
    hello: HelloFrameFromServer,
    opts?: { forgeSignature?: boolean; mcpSessionPub?: string },
  ): Promise<Uint8Array>;
  close(): Promise<void>;
}

export async function startFakeConcentrator(): Promise<FakeConcentrator> {
  const wss = loopbackWss();
  const port = await listenEphemeral(wss);
  let ws: WebSocket | null = null;
  const socketWaiters: ((s: WebSocket) => void)[] = [];
  const hellos: HelloFrameFromServer[] = [];
  const sent: Record<string, unknown>[] = [];
  const helloWaiters: (() => void)[] = [];

  wss.on('connection', (socket: WebSocket) => {
    ws = socket;
    for (const wake of socketWaiters.splice(0)) wake(socket);
    socket.on('message', (data) => {
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(data.toString()) as Record<string, unknown>;
      } catch {
        return;
      }
      sent.push(parsed);
      try {
        const frame = validateFrame(parsed);
        if (frame.type === 'hello' && frame.role === 'server') {
          hellos.push(frame);
          for (const wake of helloWaiters.splice(0)) wake();
        }
      } catch {
        /* a test may drive deliberate rubbish through here */
      }
    });
  });

  const socket = async (): Promise<WebSocket> =>
    ws ?? new Promise<WebSocket>((resolve) => socketWaiters.push(resolve));

  const waitForHello = async (nth = 0): Promise<HelloFrameFromServer> => {
    for (;;) {
      if (hellos.length > nth) return hellos[nth]!;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`no peer hello #${nth}`)), 5_000);
        helloWaiters.push(() => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
  };

  const send = async (frame: unknown): Promise<void> => {
    (await socket()).send(JSON.stringify(frame));
  };

  const waitForFrames = async (count = 1): Promise<Record<string, unknown>[]> => {
    const deadline = Date.now() + 5_000;
    for (;;) {
      const got = sent.filter((f) => f.type === 'frame');
      if (got.length >= count) return got;
      if (Date.now() > deadline) throw new Error(`only ${got.length} of ${count} frames arrived`);
      await new Promise((r) => setTimeout(r, 10));
    }
  };

  return {
    port,
    socket,
    hellos: () => [...hellos],
    waitForHello,
    sent: () => [...sent],
    waitForFrames,
    send,
    relayExtensionHello: (ext) => send(ext.hello),
    relayExtensionDisconnected: () => send({ type: 'extension-disconnected' }),
    answerReady: async (ext, hello, opts = {}) => {
      const eph = await generateX25519();
      const mcpSessionPub = fromB64(hello.sessionPub);
      const payload = readySignaturePayload(
        fromB64(hello.sessionNonce),
        ext.sessionNonce,
        eph.publicKey,
        mcpSessionPub,
      );
      const sig = opts.forgeSignature
        ? new Uint8Array(64).fill(9)
        : await ed25519Sign(ext.ed25519Priv, payload);
      await send({
        type: 'ready',
        mcpId: hello.mcpId,
        extensionSessionPub: toB64(eph.publicKey),
        mcpSessionPub: opts.mcpSessionPub ?? hello.sessionPub,
        sessionSig: toB64(sig),
      });
      const shared = await ecdhX25519(eph.privateKey, mcpSessionPub);
      const salt = await transcriptHash(
        fromB64(hello.sessionNonce),
        ext.sessionNonce,
        mcpSessionPub,
        eph.publicKey,
      );
      return hkdfSha256(shared, salt, new TextEncoder().encode(HKDF_SESSION_INFO), 32);
    },
    close: () => new Promise<void>((resolve) => wss.close(() => resolve())),
  };
}

/** A trust store that starts blank and remembers what it is handed. */
export function memoryTrust(initial: ExtensionPin | null = null): {
  allowNew: boolean;
  read: () => Promise<ExtensionPin | null>;
  write: (next: ExtensionPin) => Promise<void>;
} {
  let pin = initial;
  return {
    allowNew: false,
    read: async () => pin,
    write: async (next) => {
      pin = next;
    },
  };
}

/**
 * A peer, LINKED: dialled into a fake concentrator, told about a browser, and
 * holding a live v4 session key the caller also has.
 *
 * Exists because under v4 there is no shorter route to a session key than the
 * whole handshake. Every one of these tests used to open one with a
 * placeholder signature, no relayed extension hello and an ECDH against the
 * peer's long-term identity key — three things v4 removes — so the setup they
 * each inlined is now long enough that inlining it is how the suites drift.
 */
export async function linkedPeer(opts: {
  mcpId: string;
  serverName?: string;
  version?: string;
  domains?: string[];
  startPeer: (o: Record<string, unknown>) => Promise<{
    sendInner(inner: unknown): Promise<void>;
    close(): void;
  }>;
  identity: unknown;
  peerOpts?: Record<string, unknown>;
}): Promise<{
  rig: FakeConcentrator;
  ext: FakeExtension;
  peer: Awaited<ReturnType<(typeof opts)['startPeer']>>;
  sessionKey: Uint8Array;
  /** The peer hello the session was opened against. */
  sessionHello: HelloFrameFromServer;
}> {
  const rig = await startFakeConcentrator();
  const ext = await newFakeExtension();
  const peer = await opts.startPeer({
    host: '127.0.0.1',
    port: rig.port,
    identity: opts.identity,
    mcpId: opts.mcpId,
    serverName: opts.serverName ?? 'opentable-mcp',
    version: opts.version ?? '0.9.1',
    domains: opts.domains ?? ['opentable.com'],
    extensionTrust: memoryTrust(),
    ...opts.peerOpts,
  });
  await rig.waitForHello();
  await rig.relayExtensionHello(ext);
  const sessionHello = await rig.waitForHello(1);
  const sessionKey = await rig.answerReady(ext, sessionHello);
  // `sendInner` awaits the first ready, so this is also the wait for it.
  await peer.sendInner({ type: 'ping' });
  return { rig, ext, peer, sessionKey, sessionHello };
}
