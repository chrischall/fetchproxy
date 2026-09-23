import { WebSocket } from 'ws';
import {
  ecdhX25519,
  readySignaturePayload,
  pairTranscript,
  ed25519Verify,
  fromB64,
  toB64,
  generateX25519,
  hkdfSha256,
  transcriptHash,
  ANSWERS_NO_EXT_SESSION,
  HKDF_SESSION_INFO,
  openEncryptedFrameDetailed,
  peekHelloVersion,
  sealInnerFrame,
  validateFrame,
  PROTOCOL_VERSION,
  type Capability,
  type CaptureHeaderDecl,
  type IndexedDbScopeDecl,
  type DomSelectorDecl,
  type DomListSelectorDecl,
  type GraphqlOpDeclaration,
  type StoragePointerDecl,
  type HelloFrameFromExtension,
  type InnerFrame,
} from '@fetchproxy/protocol';
import { buildServerHello } from './build-server-hello.js';
import { encodeOutboundInnerFrame } from './frame-size.js';
import { MAX_PAYLOAD_BYTES } from './host.js';
import { SessionState } from './session.js';
import {
  awaitSessionReady,
  FetchproxyHelloRejectedError,
  FetchproxyProtocolVersionError,
} from './session-ready.js';
import type { Identity } from './identity.js';
import {
  decideExtensionTrust,
  type ExtensionPin,
  type ExtensionTrustPort,
} from './extension-trust.js';

/**
 * B-BUG-8: how long a peer waits for the host to complete the WebSocket
 * upgrade before giving up. A listener that accepts TCP but never answers
 * (a wedged or SIGSTOPped host, or some other process on the port) would
 * otherwise hang the dial — and every verb sharing its connecting promise —
 * forever. Loopback upgrades complete in milliseconds.
 */
export const PEER_DIAL_TIMEOUT_MS = 5_000;

export interface PeerOpts {
  host: string;
  port: number;
  /**
   * Bound on the WebSocket dial to the host, in ms. Defaults to
   * {@link PEER_DIAL_TIMEOUT_MS}; `0` disables it.
   */
  dialTimeoutMs?: number;
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
  domSelectors?: DomSelectorDecl[];
  domListSelectors?: DomListSelectorDecl[];
  graphqlOps?: GraphqlOpDeclaration[];
  /**
   * 1.12.0+ (#208): this MCP's pin on the extension's identity. Same store the
   * host path uses — a peer that becomes the host after an election must
   * recognise the same browser it recognised as a peer.
   */
  extensionTrust: ExtensionTrustPort;
  /**
   * 1.12.0+ (#208): refuse to derive a session when the host forwards no
   * extension hello.
   *
   * DEPRECATED and inert since 3.0.0 (protocol 4), and kept only so the
   * cohort's constructors still compile. The "unless" it used to buy is gone:
   * under v4 the HKDF salt is a transcript containing the EXTENSION's hello
   * nonce, which arrives on that relayed hello and nowhere else, so a peer
   * that never receives one cannot compute a session key at all — the branch
   * that used to warn and proceed is now a hard refusal whatever this says. A
   * v4 peer behind a v3 host is refused at the hello in any case.
   *
   * @deprecated v4 always refuses; the option changes nothing.
   */
  requireExtensionIdentity?: boolean;
  /**
   * Override `MAX_PAYLOAD_BYTES` on this peer's socket. Tests only, for the
   * reason `HostOpts.maxPayloadBytes` gives.
   */
  maxPayloadBytes?: number;
  /**
   * Mint an X25519 keypair — the bootstrap one at dial and every session
   * ephemeral after it. Tests only, and for the reasons `HostOpts` gives:
   * holding the buffer is the only way to assert it was ZEROED, and holding
   * the CALL is the only way to put two mints in flight inside one process,
   * which is the whole of Rule D (§1a).
   *
   * @default generateX25519
   */
  generateSessionKeypair?: () => Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;
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
   * dropped (most commonly MV3 service-worker eviction) and reconnected.
   *
   * 3.0.0 (protocol 4): the trigger is the host relaying the NEW extension
   * hello, which makes this peer mint a fresh session ephemeral and hello
   * again. It is no longer "the host replays our hello" — that replay is
   * gone, because under v4 a cached hello names an ephemeral whose private
   * half has already been zeroed, so the extension would derive against a
   * key nobody holds. A comment naming a path that no longer exists is how
   * the next reader concludes the replay is still there.
   *
   * Any in-flight requests sent under the
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
   * 2.5.0: whether the extension is known to be attached to the host. A
   * peer learns arrivals from the extension hello the host relays (1.12.0+)
   * and departures from `extension-disconnected` (host 2.5.0+); against an
   * older concentrator it stays false even while linked, and against a
   * 1.12–2.4 host it is last-known — it cannot see the extension leave.
   */
  extensionConnected: () => boolean;
  /** 2.5.0: whether a session key exists — the first ready landed. */
  sessionLinked: () => boolean;
  /**
   * 0.13.0+: fires when the WebSocket to the host closes — most importantly
   * when the host process dies, stranding this peer. The owning
   * `FetchproxyServer` uses this to tear down the dead peer handle and
   * re-elect (becoming the new host if the port is now free). Fires on ANY
   * close, including our own `close()`; the peer is intent-agnostic, so the
   * owner decides what a close means.
   */
  onClose: (cb: () => void) => void;
  /**
   * B-BUG-5: fires when the host relays `extension-disconnected` — the
   * extension's own socket to the concentrator closed, so every request this
   * peer sent under the old session key is unreachable. Mirrors the host's
   * `onExtensionDisconnect`; the owner fails its in-flight calls at once.
   */
  onExtensionDisconnect: (cb: () => void) => void;
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

/**
 * The error for a request that never left this process because the link to
 * the host closed first. Distinct from the host-loss "may already have run":
 * nothing reached the browser, so the caller can simply retry.
 */
function notSentError(): Error {
  return new Error(
    'fetchproxy: request not sent — the connection to the bridge host closed before it went ' +
      'out, so nothing reached the browser. It is safe to retry.',
  );
}

export async function startPeer(opts: PeerOpts): Promise<InternalPeerHandle> {
  // The same cap the host puts on what a peer sends it. Without it host→peer
  // sat at `ws`'s 100 MiB default: that much of this MCP's memory, allocated
  // before a byte is validated, on the say-so of whoever bound the port first.
  const ws = new WebSocket(`ws://${opts.host}:${opts.port}`, {
    maxPayload: opts.maxPayloadBytes ?? MAX_PAYLOAD_BYTES,
  });
  const dialTimeoutMs = opts.dialTimeoutMs ?? PEER_DIAL_TIMEOUT_MS;
  await new Promise<void>((resolve, reject) => {
    // Both listeners come off once either fires: leaving the handshake's
    // 'error' listener attached would make it the socket's only one for the
    // rest of the connection, swallowing the first later error into a reject
    // of an already-settled promise.
    let timer: ReturnType<typeof setTimeout> | undefined;
    const onOpen = (): void => {
      cleanup();
      resolve();
    };
    const onError = (e: Error): void => {
      cleanup();
      reject(e);
    };
    const cleanup = (): void => {
      if (timer !== undefined) clearTimeout(timer);
      ws.off('open', onOpen);
      ws.off('error', onError);
    };
    ws.once('open', onOpen);
    ws.once('error', onError);
    if (dialTimeoutMs > 0) {
      timer = setTimeout(() => {
        cleanup();
        // terminate() emits 'error' on a CONNECTING socket; keep a listener so
        // it cannot surface as an uncaught exception.
        ws.on('error', () => undefined);
        ws.terminate();
        reject(
          new Error(
            `fetchproxy: the process holding ${opts.host}:${opts.port} did not answer the ` +
              `WebSocket upgrade within ${dialTimeoutMs}ms — it may be wedged or not a ` +
              `fetchproxy host. Restart the MCP that owns the port (or free it) and retry.`,
          ),
        );
      }, dialTimeoutMs);
    }
  });

  // A socket error is an EventEmitter 'error': with no listener it is an
  // uncaught exception that takes the whole MCP process down. The handshake's
  // listener is gone by now, and the frame cap makes an emit here routine
  // rather than exotic — `ws` reports an oversize frame by emitting
  // (WS_ERR_UNSUPPORTED_MESSAGE_LENGTH) before closing with 1009 — so the host
  // could kill this peer by sending one big frame. `ws` closes the socket
  // itself; there is nothing to do but say so. Mirrors host.ts.
  ws.on('error', (e) => {
    console.warn(`[fetchproxy] peer: socket error: ${String(e)}`);
  });

  const generateSessionKeypair = opts.generateSessionKeypair ?? generateX25519;

  // 3.0.0 (protocol 4): this peer needs TWO keypairs, because its hello does
  // two jobs — it REGISTERS the peer with the host and it offers a session.
  //
  // The BOOTSTRAP one is minted here and signs the registration hello. A peer
  // cannot wait for an extension hello before it hellos: the hello is what
  // puts it in the host's map, and the host relays extension hellos only to
  // peers already in that map, so a peer that stayed silent at dial would
  // never be told an extension exists and would never reach the other mint.
  // It is a registration credential and never a session ephemeral: no key is
  // ever derived from it, and what makes that a fact rather than an intention
  // is the wire — the frame says it answers NO extension session, so the
  // host's gate will not forward it and no `ready` can ever name it.
  // Everything about our hello except the two values minted per extension
  // session. Rebuilt per mint, because `sessionNonce` and `sessionPub` are.
  const helloBase = {
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
    domSelectors: opts.domSelectors,
    domListSelectors: opts.domListSelectors,
    localStoragePointers: opts.localStoragePointers,
    sessionStoragePointers: opts.sessionStoragePointers,
    graphqlOps: opts.graphqlOps,
    // 2.5.0: let a host ≥2.5.0 tell us when the extension leaves, so
    // `extensionConnected()` / `sessionLinked()` can go back to false.
    // 2.6.0: `hello-rejected` for the same reason, from the extension.
    accepts: ['extension-disconnected', 'hello-rejected'],
  };
  const bootstrapKeypair = await generateSessionKeypair();
  let bootstrapPriv: Uint8Array | null = bootstrapKeypair.privateKey;
  const hello = await buildServerHello({
    ...helloBase,
    sessionPub: bootstrapKeypair.publicKey,
    // At dial this peer has been told of no extension session, and saying so
    // is what keeps the host from forwarding a hello whose ephemeral is not
    // one a session may be opened from.
    answersExtNonce: ANSWERS_NO_EXT_SESSION,
  });
  ws.send(JSON.stringify(hello));

  const innerListeners: ((inner: InnerFrame) => void)[] = [];
  const renegotiateListeners: (() => void)[] = [];
  const pendingPairListeners: ((code: string) => void)[] = [];
  const closeListeners: (() => void)[] = [];
  const extensionDisconnectListeners: (() => void)[] = [];
  // `session` is the LATEST session derived from a ready frame. Every ready
  // frame for our mcpId replaces it — the extension can renegotiate at any
  // time (most commonly after MV3 service-worker eviction reconnects the
  // browser side, which the host answers by relaying the NEW extension hello
  // to us; we mint a fresh session ephemeral and hello again, and the ready
  // for THAT hello is what lands here). 3.0.0 (protocol 4): this used to say
  // "and the host replays our hello", and there is no such replay any more —
  // under v4 a cached hello names an ephemeral whose private half has been
  // zeroed, so the extension would derive against a key nobody holds. A
  // comment naming a deleted path is how the next reader concludes it is
  // still there. `sendInner` reads `session` at call time, not at handshake
  // time, so sealing always uses the current key.
  let session: SessionState | null = null;
  /**
   * The SESSION ephemeral — minted when a relayed extension hello arrives
   * (§1a Rule A), committed only while that hello is still the current one
   * (Rule D), and the only thing a `ready` may be derived against. `null`
   * between extension sessions.
   *
   * Zeroing is by EVENT on this path. The three events are
   * `extension-disconnected`, the next mint's commit point, and this peer's
   * own socket closing. Only the first two end an extension session; the
   * third is a teardown obligation — that socket is this peer's link to the
   * HOST, and the extension's link to the concentrator is untouched by it.
   */
  let sessionEphemeral: { nonce: Uint8Array; pub: Uint8Array; priv: Uint8Array } | null = null;

  /** Zero and drop the session ephemeral, if one is held. */
  function dropSessionEphemeral(): void {
    if (sessionEphemeral) sessionEphemeral.priv.fill(0);
    sessionEphemeral = null;
  }

  /**
   * Install a mint that passed Rule D's check, zeroing what it displaces —
   * the previous session ephemeral, and the BOOTSTRAP half, which dies at the
   * first session mint that COMMITS (a mint that loses Rule D's check zeroes
   * only its own half, so the bootstrap survives it and dies to the winner).
   */
  function installSessionEphemeral(next: {
    nonce: Uint8Array;
    pub: Uint8Array;
    priv: Uint8Array;
  }): void {
    dropSessionEphemeral();
    if (bootstrapPriv) {
      bootstrapPriv.fill(0);
      bootstrapPriv = null;
    }
    sessionEphemeral = next;
  }
  // 0.5.2+: latest pair code the host has forwarded for our mcpId. Set on
  // pair-pending; cleared on the next ready (user approved). MCP-level
  // callers consult it to fail tool calls fast with an actionable error
  // instead of waiting on a session promise that never resolves.
  // M1 (bridge review 2026-09-10): only ever set from `pairCodeFor` — the
  // number the frame carried is checked against that, never copied out of it.
  let pendingPairCode: string | null = null;
  let warnedUnverifiablePairCode = false;

  // `sessionPromise` fires once: it gates the first `sendInner` until the
  // initial ready arrives. After that, renegotiations update `session` in
  // place without re-creating the promise.
  let resolveFirstReady!: (s: SessionState) => void;
  let rejectFirstReady!: (e: Error) => void;
  let sessionPromise!: Promise<SessionState>;
  // B-BUG-5: whether the CURRENT `sessionPromise` has settled. An
  // `extension-disconnected` after a session existed replaces the resolved
  // promise with a fresh one, so `sendInner` waits for the next session
  // instead of sealing under a key nobody holds any more; one that arrives
  // while the promise is still pending keeps it, so its waiters are not
  // stranded on a promise nothing will ever settle.
  let sessionPromiseSettled = false;
  function resetSessionPromise(): void {
    sessionPromiseSettled = false;
    sessionPromise = new Promise<SessionState>((resolve, reject) => {
      resolveFirstReady = (st) => {
        sessionPromiseSettled = true;
        resolve(st);
      };
      rejectFirstReady = (e) => {
        sessionPromiseSettled = true;
        reject(e);
      };
    });
    // Swallow unhandled-rejection noise when no caller has subscribed at the
    // moment we reject. The rejection still reaches any later `await`.
    sessionPromise.catch(() => { /* noop */ });
  }
  resetSessionPromise();

  // 1.12.0 (#208): the extension hello, once the host has relayed it. Null
  // means "this host does not relay it" — an older concentrator.
  let extensionHello: HelloFrameFromExtension | null = null;
  // 2.5.0: set when the host relays `extension-disconnected`; cleared by the
  // next `ready`. Since B-BUG-5 `session` is dropped on that event too, so
  // this flag is belt-and-braces for `sessionLinked()`.
  let extensionGone = false;
  // `undefined` = not read yet; `null` = read, nothing pinned. See the note in
  // `authenticateExtension` for why this is cached rather than re-read.
  let cachedPin: ExtensionPin | null | undefined = undefined;

  /**
   * The joint pair code for a relayed extension hello —
   * `pairTranscript(ourPub, extPub, ourNonce, itsNonce, ourSessionPub)`, the
   * five values in the order the popup uses. The only code this peer will
   * ever show, and what every `pair-pending` frame is judged against.
   *
   * M1 (bridge review 2026-09-10): computed FROM THE LIVE HELLO on demand
   * rather than cached beside it, which is what makes two properties
   * structural instead of remembered. (1) `ws` does not serialise an async
   * message handler, so a `pair-pending` in the same read turn as the hello
   * runs while the hello's own awaits are still outstanding: against a cached
   * value that frame was judged against a derivation in flight, which reads as
   * "no extension identity was ever relayed" and downgraded the close-on-
   * disagreement to a warning on a live socket. Here it derives from the hello
   * itself and gets the same answer whenever it runs. (2) A code cannot
   * outlive the pair of identities it commits to, because there is no stored
   * code to forget to clear when that extension goes — clearing
   * `extensionHello` is the whole of it.
   *
   * 3.0.0 (protocol 4): the transcript also commits to OUR side of this
   * extension session — the nonce and ephemeral of the hello we minted in
   * answer to the relayed one — so `mint` is a PARAMETER rather than a read of
   * `sessionEphemeral` inside an async function, for the reason (1) above: the
   * caller captures both halves synchronously and this function cannot be
   * handed one pairing's hello and another's ephemeral. No mint, no code.
   */
  const pairCodeFor = async (
    hello: HelloFrameFromExtension,
    mint: { nonce: Uint8Array; pub: Uint8Array } | null,
  ): Promise<string | null> => {
    if (!mint) return null;
    try {
      return await pairTranscript(
        opts.identity.x25519Pub,
        fromB64(hello.identityX25519Pub),
        mint.nonce,
        fromB64(hello.sessionNonce),
        mint.pub,
      );
    } catch (e) {
      console.error('[fetchproxy] could not derive the pair code:', e);
      return null;
    }
  };

  /**
   * Decide whether the extension behind this host may open a session with us:
   * its signature must verify, and its identity must be the one we pinned (or
   * the first we have seen). Pins on success, since the signature is what
   * makes committing meaningful.
   *
   * 3.0.0 (protocol 4): the payload is `readySignaturePayload(ourHelloNonce,
   * itsHelloNonce, itsSessionPub, ourSessionPub)` — this comment used to name
   * `(ourHelloNonce || itsHelloNonce)` alone, which has not been the payload
   * since 2.0.0 and is now two fields short. Both ephemerals are in it, which
   * is what stops either half of the ECDH being substituted in the path.
   *
   * BOTH of the values this reads about the far end are PARAMETERS, captured
   * by the caller at Rule C's synchronous point: `held` is the ephemeral, and
   * `hello` is the relayed extension hello. Neither is re-read off the
   * enclosing `let` here, because this function awaits — `ed25519Verify` and,
   * once per peer, the pin read — and a relayed hello for a LATER extension
   * session lands inside that window on the ordinary MV3 path (it is assigned
   * synchronously, before its own mint's first await). Re-reading made the
   * signature and the trust decision disagree about which browser connection
   * this `ready` belongs to, and it is `extensionHello`'s mutability rather
   * than any check that made that possible.
   *
   * It RETURNS the hello it authenticated rather than a boolean, so the
   * caller's derivation cannot salt its transcript with a different one: the
   * nonce in the HKDF salt is then the nonce in the verified payload by
   * construction, which is exactly the property that was silently false.
   */
  const authenticateExtension = async (
    sessionSig: string,
    extensionSessionPub: string,
    held: { nonce: Uint8Array; pub: Uint8Array; priv: Uint8Array },
    hello: HelloFrameFromExtension | null,
  ): Promise<HelloFrameFromExtension | null> => {
    if (!hello) {
      // 3.0.0 (protocol 4): a hard refusal, and not because the policy got
      // stricter — because the alternative became uncomputable. The HKDF salt
      // is a transcript over BOTH nonces, and the extension's arrives only on
      // the hello the host relays, so a peer without it has nothing to derive
      // from. The `warnedUnverifiable` branch that used to proceed is gone
      // rather than left looking alive, and `requireExtensionIdentity`'s
      // "unless" with it.
      console.error(
        `[fetchproxy] ${opts.serverName}: no extension hello has been relayed to this peer, so ` +
          `there is nothing to derive a v4 session from — refusing. Upgrade the MCP holding the ` +
          `bridge port to 3.0.0 or later.`,
      );
      return null;
    }

    const payload = readySignaturePayload(
      held.nonce,
      fromB64(hello.sessionNonce),
      fromB64(extensionSessionPub),
      held.pub,
    );
    let sigOk = false;
    try {
      sigOk = await ed25519Verify(
        fromB64(hello.identityEd25519Pub),
        payload,
        fromB64(sessionSig),
      );
    } catch {
      sigOk = false;
    }
    if (!sigOk) {
      console.warn(
        `[fetchproxy] ${opts.serverName}: extension session signature invalid — refusing ` +
          `(the concentrator may be answering in the browser's place)`,
      );
      return null;
    }

    // Read the pin ONCE per peer, not once per ready. The extension
    // renegotiates on every MV3 eviction, and a disk read on that path widens
    // the window between "the extension is back" and "this peer's session key
    // has caught up" — during which a call is sealed with the stale key and
    // then rejected by the renegotiation. Nothing else writes this file while
    // we hold it, and a pin deleted underneath a live process should not
    // silently downgrade it mid-session anyway.
    if (cachedPin === undefined) {
      try {
        cachedPin = await opts.extensionTrust.read();
      } catch (e) {
        console.error(`[fetchproxy] ${String(e)}`);
        return null;
      }
    }
    const pin = cachedPin;
    const outcome = decideExtensionTrust({
      pin,
      hello,
      allowNew: opts.extensionTrust.allowNew,
      serverName: opts.serverName,
      location: opts.extensionTrust.location,
    });
    if (outcome.decision === 'refused') {
      console.warn(outcome.message);
      return null;
    }
    if (outcome.decision === 'replace') console.warn(outcome.message);
    if (outcome.decision !== 'pinned') {
      try {
        const written = {
          identityX25519Pub: hello.identityX25519Pub,
          identityEd25519Pub: hello.identityEd25519Pub,
          pinnedAt: Date.now(),
        };
        await opts.extensionTrust.write(written);
        cachedPin = written;
      } catch (e) {
        console.error(`[fetchproxy] could not persist the extension pin: ${String(e)}`);
      }
    }
    return hello;
  };

  const onMessage = async (data: WebSocket.RawData): Promise<void> => {
    // Held outside the try so the catch can read the bytes back: a hello this
    // build refuses is the one frame worth a second look (Task 4.2).
    let raw: unknown;
    try {
      raw = JSON.parse(data.toString());
      const frame = validateFrame(raw);
      // 1.12.0 (#208): the host relays the extension's hello so a peer can
      // authenticate the far end of its own session. Before 1.12.0 no host
      // sent this, which is why its absence is handled rather than assumed.
      if (frame.type === 'hello' && frame.role === 'extension') {
        // M1 (bridge review 2026-09-10): this is also the whole of what makes
        // a pair code derivable here — `pairCodeFor` reads it back off this
        // hello. Assigned synchronously, so a `pair-pending` delivered in the
        // same read turn is judged against the identity it belongs to rather
        // than against nothing.
        extensionHello = frame;
        // 3.0.0 (protocol 4), §1a Rule A: this relayed hello is this peer's
        // ONE mint trigger, and the answer is a FRESH server hello in the
        // same handler. A peer that minted only at dial would hold a
        // per-PROCESS ephemeral reused across every extension session for the
        // life of the MCP — on a laptop, days — which is not an ephemeral.
        //
        // All of the crypto goes into LOCALS: `onMessage` is `async` and
        // nothing awaits the promise `ws.on('message', onMessage)` returns,
        // so a second relayed hello can arrive, complete and install while
        // this one is still inside `generateX25519`.
        const mintedKeypair = await generateSessionKeypair();
        const mintedHello = await buildServerHello({
          ...helloBase,
          sessionPub: mintedKeypair.publicKey,
          answersExtNonce: fromB64(frame.sessionNonce),
        });
        // §1a Rule D — the commit. `extensionHello === frame` is the
        // triggering frame this handler is already holding, so the check
        // costs nothing here. A mismatch means either a NEWER relayed hello
        // has landed or an `extension-disconnected` has (leaving it null),
        // and both are the same refusal to commit.
        //
        // On a mismatch: zero the half just minted, assign nothing, send no
        // hello, return. The hello is one Rule B refuses to forward anyway,
        // so the send is merely pointless; the ASSIGNMENT is the bug — it
        // leaves this peer holding a superseded pub while the extension holds
        // the live one, with Rule C then discarding the only `ready` there
        // will be and no trigger left to mint again.
        if (extensionHello !== frame) {
          mintedKeypair.privateKey.fill(0);
          return;
        }
        installSessionEphemeral({
          nonce: fromB64(mintedHello.sessionNonce),
          pub: mintedKeypair.publicKey,
          priv: mintedKeypair.privateKey,
        });
        ws.send(JSON.stringify(mintedHello));
        return;
      }
      // 2.5.0: the extension's socket to the host closed. Forget what we
      // knew of it; the host relays a fresh hello (and the extension a fresh
      // ready) when it comes back.
      if (frame.type === 'extension-disconnected') {
        extensionHello = null;
        extensionGone = true;
        // 3.0.0: this ENDS an extension session, so the private half goes
        // with it (and, since B-BUG-5, the session key — below).
        dropSessionEphemeral();
        // Same as the host: a code nobody can approve any more must not
        // outrank "the extension is gone" in the session snapshot. Nothing
        // else has to be forgotten here — clearing the hello above is what
        // retires the derivation with it (M1, `pairCodeFor`).
        pendingPairCode = null;
        // B-BUG-5: the session this key belonged to is over — the extension
        // keeps no state for it across a reconnect — so drop it, as the host
        // drops its own. New calls wait for the next session rather than
        // being sealed under a dead key and silently dropped, and the owner
        // fails the calls already in flight instead of letting each burn its
        // whole timeout (and then fetch()'s retry).
        if (session !== null) {
          session = null;
          if (sessionPromiseSettled) resetSessionPromise();
        }
        extensionDisconnectListeners.forEach((cb) => cb());
        return;
      }
      if (frame.type === 'ready' && frame.mcpId === opts.mcpId) {
        // 3.0.0 (protocol 4), §1a Rule C: is this `ready` for the ephemeral
        // we currently hold? Asked FIRST — before `authenticateExtension`,
        // before any signature — and answered by a DISCARD.
        //
        // This is where Rule C earns its keep. With the host's replay of our
        // cached hello gone, a re-hello is the only route this peer's session
        // hello takes to the extension, so an extension reconnect that races
        // one is the ORDINARY case. Under v3 it ended here in a 1008 plus
        // `rejectFirstReady` — a bridged MCP stranded on a failure an MV3
        // eviction caused. A mismatch now logs and returns, touching neither
        // `session` nor `extensionGone` nor the promise, and the socket to
        // the host stays up because the host is not the party at fault.
        //
        // The 1008 below stays for the case it was written for: a `ready`
        // naming the CURRENT ephemeral whose signature does not verify.
        const held = sessionEphemeral;
        // Captured in the SAME synchronous breath as the ephemeral, and for
        // the same reason: everything below awaits, and `extensionHello` is
        // reassigned by the next relayed hello — synchronously, before that
        // mint's own first await — so a hello for a LATER extension session
        // lands inside this handler's window on the ordinary MV3 path. The
        // two values are one fact ("the extension session this `ready`
        // belongs to") and reading one of them later is how they came apart:
        // the signature was verified against E1's nonce while the salt took
        // E2's, which installs a key the browser does not hold and resolves
        // the first-ready promise with it. `host.ts` captures the same value
        // at the same point (`extNonce`, one line above its verify).
        const heldExtHello = extensionHello;
        if (!held || frame.mcpSessionPub !== toB64(held.pub)) {
          console.warn(
            `[fetchproxy] ${opts.serverName}: discarding a ready for a session ephemeral this ` +
              `peer no longer holds (the extension reconnected while a hello was in flight)`,
          );
          return;
        }
        // #208: authenticate the extension BEFORE deriving anything from a
        // key it supplied. Without this, anything that could reach us could BE
        // the extension with no key material at all.
        //
        // 2.0.0: the signature covers `extensionSessionPub` as well as the
        // two nonces, so this also makes the session private against
        // something already in the middle — a relay would have to sign its
        // own ephemeral key with the extension's Ed25519 key. Under v2 it
        // could not, and that was the whole of the remaining MITM. 3.0.0
        // extends it to OUR ephemeral, so neither half of the ECDH can be
        // substituted.
        // Both of the far end's values are handed over rather than read from
        // in here, and the hello it authenticated comes back out — see its
        // doc comment.
        const authenticated = await authenticateExtension(
          frame.sessionSig,
          frame.extensionSessionPub,
          held,
          heldExtHello,
        );
        if (!authenticated) {
          ws.close(1008, 'extension identity refused');
          rejectFirstReady(new Error('peer: extension identity refused'));
          return;
        }
        // 3.0.0: ephemeral × ephemeral, salted with the transcript over both
        // nonces and both ephemerals — not our own hello nonce, and not our
        // long-term identity key, which under v3 made the identity a standing
        // decryption capability for every session it ever opened.
        //
        // EVERY input is one captured at Rule C, not re-read: the ephemeral,
        // because a mint that commits while this derivation is in flight
        // zeroes the private half we are holding; and the extension nonce,
        // because a relayed hello for a later session reassigns
        // `extensionHello` in the same window — and the nonce in this salt
        // has to be the one in the payload the signature was just verified
        // over, or the two ends derive different keys and nothing says so.
        // Taking it off `authenticated` rather than off the binding is what
        // makes that structural instead of remembered.
        const extPub = fromB64(frame.extensionSessionPub);
        const extNonce = fromB64(authenticated.sessionNonce);
        const shared = await ecdhX25519(held.priv, extPub);
        const salt = await transcriptHash(held.nonce, extNonce, held.pub, extPub);
        const sessionKey = await hkdfSha256(
          shared,
          salt,
          enc.encode(HKDF_SESSION_INFO),
          32,
        );
        // The mirror of the host's `if (extensionWs !== ws) return;` one line
        // before it installs: the authenticate and the two crypto calls above
        // all await, and a Rule A mint can COMMIT inside that window — which
        // zeroes the private half this derivation was using, so `sessionKey`
        // is then computed from a scrubbed scalar. Installing it would put a
        // dead session in place of a live one and resolve the first-ready
        // promise with it. Declining costs nothing: the hello that superseded
        // this ephemeral is already on its way, and the `ready` answering it
        // will install the session — which is the same argument that makes
        // Rule C's discard safe.
        if (sessionEphemeral !== held) {
          console.warn(
            `[fetchproxy] ${opts.serverName}: dropping a session derived against an ephemeral ` +
              `that was superseded while it was being derived`,
          );
          return;
        }
        const isRenegotiation = session !== null;
        session = new SessionState(sessionKey);
        extensionGone = false;
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
      // 2.6.0: a refusal relayed by the host. Same reasoning as on the host:
      // fail this peer's wait now, with the extension's own reason.
      if (frame.type === 'hello-rejected' && frame.mcpId === opts.mcpId) {
        rejectFirstReady(
          new FetchproxyHelloRejectedError({ mcpId: frame.mcpId, reason: frame.reason }),
        );
      }

      if (frame.type === 'pair-pending' && frame.mcpId === opts.mcpId) {
        // M1 (bridge review 2026-09-10): as on the host — the code a user
        // compares against the popup is the one derived here from the two
        // identities, and the frame's number is only ever checked against it.
        // It arrives plaintext across the concentrator, so surfacing it would
        // let whatever is in the middle pick the string both "channels" show.
        // Read off the hello that is live NOW, and derived from it here: this
        // handler runs interleaved with the hello's, so a code remembered by
        // that one is a code this one may find half-written (see
        // `pairCodeFor`).
        //
        // 3.0.0 (protocol 4): the ephemeral is captured in the same breath,
        // so the transcript judged against is one pairing's worth of values.
        const hello = extensionHello;
        const mint = sessionEphemeral;
        const derived = hello === null ? null : await pairCodeFor(hello, mint);
        if (derived === null) {
          // Nothing to judge against: no extension identity is on this handle
          // — a pre-1.12.0 host relays none at all, and a host that has told
          // us the browser went has taken back the one it relayed; 3.0.0 adds
          // a third, the window before this peer has minted its answer to a
          // relayed hello, since the transcript needs that ephemeral too.
          // Refusing the socket would take down a working (if unverifiable)
          // bridge for a hint; displaying the frame's number is the hole
          // itself. So say so once and show nothing — the same trade
          // `authenticateExtension` makes about such a host.
          if (!warnedUnverifiablePairCode) {
            warnedUnverifiablePairCode = true;
            console.warn(
              `[fetchproxy] ${opts.serverName}: a pair code arrived that this peer cannot ` +
                `derive for itself (no extension identity has been relayed to it, or no ` +
                `session ephemeral has been minted in answer to one), so it is ` +
                `not being shown. If the MCP holding the bridge port is older than 1.12.0, ` +
                `upgrading it closes this.`,
            );
          }
          return;
        }
        if (frame.pairCode !== derived) {
          console.error(
            `[fetchproxy] ${opts.serverName}: the extension's pair code (${frame.pairCode}) ` +
              `does not match the one this peer derived from the pair transcript ` +
              `(${derived}) — refusing ` +
              `to pair (possible MITM between this MCP and the extension)`,
          );
          ws.close(1008, 'pair code mismatch');
          return;
        }
        pendingPairCode = derived;
        pendingPairListeners.forEach((cb) => cb(derived));
        return;
      }
      if (frame.type === 'frame' && frame.mcpId === opts.mcpId) {
        // Captured, not re-read after the await: the seq belongs to the
        // session whose key opened the frame, and a renegotiation during the
        // open would otherwise commit it against the new one.
        const inboundSession = session;
        if (!inboundSession) return; // ignore encrypted frames before handshake
        // Claimed SYNCHRONOUSLY, before the await below. A bare freshness
        // question changes nothing, so two copies of one frame arriving in a
        // single read both passed it — deterministically, since the counter
        // cannot move until the open returns. The claim takes the seq out of
        // circulation now and the duplicate behind it is refused as a replay.
        const claim = inboundSession.claimInboundSeq(frame.seq);
        // A replay is dropped silently, as ever. Saturation is not a replay —
        // it drops frames that may be genuine — so say so, but once per run of
        // it: the session latches the warning until an 'ok' claim shows the
        // set has drained (#376).
        if (inboundSession.saturationWarningDue(claim)) {
          console.warn(
            `[fetchproxy] ${opts.serverName}: dropped an inbound frame (seq ${frame.seq}) ` +
              `unread — too many frames from the extension are still being opened ` +
              `(inbound claims saturated). Not a replay. Further drops are not logged ` +
              `until the in-flight set drains.`,
          );
        }
        if (claim !== 'ok') return;
        let result;
        try {
          // 'e2s': a frame reaching this peer was sealed by the EXTENSION and
          // relayed by the host, so one this peer sealed itself and had
          // reflected back fails the tag rather than arriving well-formed. The
          // direction names the two ends of the MCP-to-extension session, not
          // the socket hop — a peer is a server exactly as the host is.
          result = await openEncryptedFrameDetailed(inboundSession.sessionKey, frame, 'e2s');
        } catch (e) {
          // `openEncryptedFrameDetailed` reports both failures in its result
          // rather than throwing, so this is the unexpected path — but the
          // claim must not leak out of it whatever went wrong.
          inboundSession.releaseInboundSeq(frame.seq);
          throw e;
        }
        // The counter moves for a frame that AUTHENTICATED, which is both
        // outcomes below except `decrypt-failed` — a validation failure
        // decrypted under the live key, so its seq is genuinely spent and
        // replaying it must still be refused. A decrypt failure gives the
        // claim back instead: advancing before the open let one
        // unauthenticated frame with a high seq wedge the session, every
        // genuine frame afterwards carrying a lower number and being dropped.
        if (result.stage !== 'decrypt-failed') inboundSession.commitInboundSeq(frame.seq);
        else inboundSession.releaseInboundSeq(frame.seq);
        if (result.stage === 'ok') {
          innerListeners.forEach((cb) => cb(result.inner));
        } else if (result.stage === 'decrypt-failed') {
          // AES-GCM authentication failed — typically a straggler frame
          // from a previous session (extension reconnected mid-flight).
          // Nothing about the plaintext can be trusted; drop it silently,
          // as before — the next legitimate frame on the new key will land.
        } else {
          // 'validation-failed': decryption SUCCEEDED — this frame really
          // is from the current, live host — but the plaintext is
          // malformed JSON or fails schema validation. That's a genuine
          // protocol bug, not a stale-key symptom, so (unlike a decrypt
          // failure) it must not be swallowed silently: previously this
          // branch was indistinguishable from decrypt-failed, so a real
          // validation bug (e.g. the "download bytes:-1" class of issue)
          // would leave whichever pending call is awaiting this frame's
          // `id` to hang until its own timeout with zero diagnostic
          // signal. Log loudly, and when the id was recoverable, route a
          // synthetic ok:false response through the normal id-keyed
          // dispatch so that ONE call fails fast — without tearing down
          // the connection, which decryption just proved is legitimate.
          // eslint-disable-next-line no-console
          console.error(
            '[fetchproxy] peer: received a frame that decrypted OK but failed validation:',
            result.error,
          );
          if (result.recoveredId !== undefined) {
            innerListeners.forEach((cb) =>
              cb({
                type: 'response',
                id: result.recoveredId!,
                ok: false,
                error: `malformed response failed protocol validation: ${String(result.error)}`,
              }),
            );
          }
        }
      }
    } catch (e) {
      // 3.0.0 (protocol 4), Task 4.2: the host's refusal, on the peer path.
      // A hello whose `protocolVersion` is not ours used to reject this
      // peer's wait with `hello.protocolVersion: must be 4` — a validator's
      // sentence, in a tool error, for a person who has an extension and a
      // sibling MCP and no idea either has a version. The far end is named
      // from the peek: a relayed EXTENSION hello (no `mcpId`) is the browser,
      // anything else on this socket is the MCP holding the bridge port.
      //
      // The socket is NOT closed here, unlike the host's mirror of this: a
      // peer's link is to another MCP process, its close is wired to
      // re-election, and re-electing into a port a v3 host still holds would
      // dial straight back into the same refusal. Failing the wait is what
      // the caller needed; the link staying up costs nothing.
      const peek = peekHelloVersion(raw);
      const mismatch =
        peek && peek.protocolVersion !== PROTOCOL_VERSION
          ? new FetchproxyProtocolVersionError({
              ourVersion: PROTOCOL_VERSION,
              theirVersion: peek.protocolVersion,
              peer: peek.mcpId === null ? 'extension' : 'mcp',
            })
          : null;
      if (mismatch) console.warn(`[fetchproxy] ${opts.serverName}: ${mismatch.message}`);
      rejectFirstReady(mismatch ?? (e instanceof Error ? e : new Error(String(e))));
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
    // 3.0.0 (protocol 4): this process is leaving and must not keep a private
    // half it can no longer use — both halves, because a peer that never
    // received an extension hello still holds its bootstrap one. A teardown
    // obligation rather than one of §1a's session-ending events: the socket
    // closing here is this peer's link to the HOST.
    dropSessionEphemeral();
    if (bootstrapPriv) {
      bootstrapPriv.fill(0);
      bootstrapPriv = null;
    }
    // 0.13.0+: notify the owner the host link dropped, so it can tear down
    // this stranded handle and re-elect. Fires after rejectFirstReady so a
    // pre-ready close still surfaces the original error to in-flight awaiters.
    closeListeners.forEach((cb) => cb());
  });
  const handle: InternalPeerHandle = {
    ws,
    // A getter: `extension-disconnected` replaces the promise (B-BUG-5).
    get session() {
      return sessionPromise;
    },
    sendInner: async (inner: InnerFrame) => {
      // Wait for the FIRST ready; subsequent renegotiations swap `session`
      // in place, so we read it freshly here rather than reusing the
      // promise's resolved value (which is permanently the first session).
      // Bounded so a never-confirmed session surfaces a clear
      // FetchproxySessionNotReadyError instead of hanging indefinitely.
      try {
        await awaitSessionReady(sessionPromise, {
          mcpId: opts.mcpId,
          pendingPairCode: () => pendingPairCode,
        });
      } catch (e) {
        // Queued for a session and the link to the host went first: the
        // frame never left this process, and the caller must be told THAT
        // rather than the handshake's internal reason.
        if (ws.readyState !== WebSocket.OPEN) throw notSentError();
        throw e;
      }
      // `session` is non-null once `sessionPromise` has resolved — it is set
      // two statements before `resolveFirstReady(session)` — EXCEPT across an
      // `extension-disconnected` that landed between that resolution and this
      // line (B-BUG-5 returns it to null). Fail that call plainly rather than
      // seal it under nothing.
      const s = session;
      if (s === null) throw new Error('peer: extension disconnected');
      // Measured before a seq is claimed, so a refused frame spends nothing
      // and leaves no gap: an oversize payload would otherwise meet the host's
      // `maxPayload` as a 1009 CLOSE, taking this peer's only link to the
      // bridge down to report that one call was too big.
      const plaintext = encodeOutboundInnerFrame(opts.mcpId, inner);
      const sealed = await sealInnerFrame(
        s.sessionKey,
        opts.mcpId,
        s.nextOutboundSeq(),
        plaintext,
        's2e',
      );
      // The socket can close while the frame is being sealed, and `ws`
      // DISCARDS a send on a socket that is not open — no throw, no error
      // event — so this call would resolve as if it had gone out. Checked
      // here, where nothing can run between the check and the send: a frame
      // written to an OPEN socket may have reached the browser, one refused
      // here provably did not, and that is the line the host-loss error
      // messages are drawn on.
      if (ws.readyState !== WebSocket.OPEN) throw notSentError();
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
    extensionConnected: () => extensionHello !== null,
    sessionLinked: () => session !== null && !extensionGone,
    onClose: (cb) => {
      closeListeners.push(cb);
    },
    onExtensionDisconnect: (cb) => {
      extensionDisconnectListeners.push(cb);
    },
    close: () => ws.close(),
  };
  return handle;
}
