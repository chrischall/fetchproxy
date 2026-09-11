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
  MAX_FRAME_BYTES,
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
import { encodeOutboundInnerFrame } from './frame-size.js';
import { SessionState } from './session.js';
import { awaitSessionReady, FetchproxyHelloRejectedError } from './session-ready.js';
import type { Identity } from './identity.js';
import { decideExtensionTrust, type ExtensionTrustPort } from './extension-trust.js';

// Reject WS upgrades from browsing contexts (drive-by webpage defense).
// Browsers send Origin: <scheme>://<host>[:<port>] on WS upgrades from
// pages. Extensions send chrome-extension:// (moz-, safari-web-); a Node
// peer dialing the concentrator sends no Origin header at all. We allow
// exactly two things, and `originVerdict` below is an ALLOWLIST of them
// rather than a list of refusals with everything else falling through:
// - A missing Origin header (a peer, or curl)
// - chrome-extension://, moz-extension://, safari-web-extension://
// Every http(s) origin is a PAGE and is rejected, as is the opaque `null`
// origin, and so is any other scheme — a packaged desktop or mobile app
// (tauri://, capacitor://, app://) is a page with an origin of its own.
const HTTP_ORIGIN_RE = /^https?:\/\//i;
const PUBLIC_ORIGIN_RE = /^https?:\/\/(?!(127\.0\.0\.1|localhost|\[::1\])(:|$))/i;

/**
 * The origin a browser extension's own pages and service worker dial with.
 *
 * This is the whole of what the gate admits with an `Origin` header present,
 * which is why it is a regex over named schemes and not "not one of the ones
 * we refuse": the population this layer exists to keep out is every browsing
 * context that is not the extension, and a browsing context does not have to
 * be served over http to be one. A `tauri://`, `capacitor://`, `ionic://` or
 * `app://` page is an installed app's UI, it can reach loopback, and it can
 * raise a pair prompt under a name of its choosing exactly as a web page can.
 *
 * Adding a browser means adding its scheme here — which is the point. A
 * fallthrough admits the next scheme nobody has thought of, silently.
 */
const EXTENSION_ORIGIN_RE = /^(chrome-extension|moz-extension|safari-web-extension):\/\//i;

/**
 * The literal value a browsing context with an OPAQUE origin sends: a
 * sandboxed iframe, an `srcdoc` document, a `data:` URL, a `file://` page.
 * The header is present and its value is the four characters `null`, which
 * is not the same thing as the header being absent.
 */
const OPAQUE_ORIGIN = 'null';

/**
 * The one documented way to put `null` and `localhost` origins back.
 *
 * Both were accepted until this existed, and the comment above used to call
 * `null` "the extension" — it is not. An extension's socket carries its own
 * `chrome-extension://` origin; `null` is what a page with an opaque origin
 * sends, and `http://localhost:<port>` is what a dev server, a notebook or
 * any locally-served app sends. Admitting those means such a page, in a
 * browser the user already has open, reaches the concentrator and is
 * answered — and `docs/SECURITY.md` §T2 defence 2 is the layer that exists
 * to stop exactly that. With those two through, it stopped `https://evil.com`
 * and nothing else.
 *
 * They are still useful when somebody is BUILDING against the bridge from a
 * local page, which is why this is an escape rather than a removal — and why
 * it is an environment variable rather than an option: the packages that
 * construct a `FetchproxyServer` are not edited to debug one of them.
 * Exactly `1` turns it on. Anything else is a typo rather than an intention
 * and is refused WITH A WARNING rather than read as "on", because a value
 * that half works is how a development escape survives into a deployment.
 */
export const ALLOW_LOCAL_ORIGINS_ENV = 'FETCHPROXY_ALLOW_LOCAL_ORIGINS';

function envAllowsLocalOrigins(env: Record<string, string | undefined> = process.env): boolean {
  const raw = env[ALLOW_LOCAL_ORIGINS_ENV];
  if (raw === undefined || raw.trim() === '') return false;
  if (raw.trim() === '1') return true;
  console.warn(
    `[fetchproxy] ignoring ${ALLOW_LOCAL_ORIGINS_ENV}=${JSON.stringify(raw)}: the only value ` +
      `that turns it on is 1. Upgrades from a null or localhost origin stay refused.`,
  );
  return false;
}

/** What the origin gate decided about one upgrade — see `originVerdict`. */
export type OriginVerdict = { allow: true } | { allow: false; reason: string; escapable: boolean };

/**
 * Decide one upgrade's `Origin`.
 *
 * A refusal is either ESCAPABLE (a local page, which a developer may
 * genuinely be holding) or not (a public page, which the escape deliberately
 * does not admit — turning the gate off entirely is not on offer). "Local" is
 * the complement of `PUBLIC_ORIGIN_RE` within http(s) rather than a second
 * regex of its own, so the two cannot drift apart and leave an http origin
 * that is neither and so falls through to the next branch.
 *
 * The allowed population is an extension scheme, or no `Origin` header at
 * all. Everything else is refused, including a scheme this file does not
 * name: the last branch is a refusal rather than an `allow`.
 */
export function originVerdict(origin: string | undefined, allowLocal: boolean): OriginVerdict {
  // No Origin header: a Node peer dialing the concentrator, or curl. A page
  // cannot get here — every browser sends one on a WS upgrade.
  if (origin === undefined) return { allow: true };

  if (HTTP_ORIGIN_RE.test(origin)) {
    if (PUBLIC_ORIGIN_RE.test(origin)) {
      return { allow: false, reason: 'origin not allowed', escapable: false };
    }
    return allowLocal
      ? { allow: true }
      : { allow: false, reason: 'localhost page origin not allowed', escapable: true };
  }

  if (origin.toLowerCase() === OPAQUE_ORIGIN) {
    return allowLocal
      ? { allow: true }
      : { allow: false, reason: 'opaque (null) origin not allowed', escapable: true };
  }

  // chrome-extension:// and its siblings — the extension itself.
  if (EXTENSION_ORIGIN_RE.test(origin)) return { allow: true };

  // Anything else with an Origin header is a browsing context we have no
  // reason to know: a packaged app's page, a scheme a future browser mints,
  // or a present-but-empty header. Refused, and not escapable — the escape
  // admits local ORIGINS, it does not widen what counts as the extension.
  return { allow: false, reason: 'origin not allowed', escapable: false };
}

/**
 * How long a socket may sit on the port without identifying itself.
 *
 * docs/SECURITY.md §T2 defense 3 has promised this for as long as the threat
 * model has existed ("connections that don't send a valid hello frame within
 * 15 seconds get closed") and nothing implemented it: a drive-by page that
 * reached the upgrade — or any local process enumerating the port — could
 * hold a connection open indefinitely. Identification is the gate rather than
 * bytes arriving, because a socket that chats without ever sending a hello is
 * exactly the connection being described.
 */
export const HANDSHAKE_TIMEOUT_MS = 15_000;

/**
 * The largest frame the host will accept from a peer or the extension.
 *
 * `ws` defaults to 100 MiB, which is a lot of process memory a local peer can
 * make the host allocate before a single byte is validated. Over the cap, `ws`
 * closes the socket with 1009 without buffering the rest.
 *
 * That close is why the number is `MAX_FRAME_BYTES` — the protocol's own
 * budget, derived in `seal.ts` from the biggest body the extension will relay
 * — rather than a figure picked for how much memory feels reasonable. 8 MiB
 * was picked that way, and it sat UNDER the worst legitimate frame: the wire
 * form is base64 of the JSON of the plaintext, so a 5 MiB response body of
 * non-ASCII text (never mind a storage read, which has no cap of its own at
 * all) comes out the far side of that expansion well past 8 MiB. A 1009 on
 * the extension's socket is not one failed call — it is the ONE socket every
 * MCP on this concentrator shares, so all of them drop together.
 *
 * A conforming sender never reaches this at all: the extension measures each
 * frame against the same constant before sealing it and fails the single
 * request instead. What is left here is the backstop for a sender that is not
 * the extension.
 */
export const MAX_PAYLOAD_BYTES = MAX_FRAME_BYTES;

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
  /**
   * Override `HANDSHAKE_TIMEOUT_MS`. Tests only — a suite cannot afford to
   * wait out fifteen real seconds to watch a silent socket be closed.
   */
  handshakeTimeoutMs?: number;
  /**
   * Override `MAX_PAYLOAD_BYTES`. Tests only — proving the cap bites means
   * sending a frame over it, and pushing 42 MiB across loopback to watch a
   * 1009 arrive tests the size of the constant rather than the behaviour.
   */
  maxPayloadBytes?: number;
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
  // Read once, at boot: the answer cannot change while the process runs, and
  // reading it here is what makes the warning below fire once rather than on
  // every upgrade a port scanner attempts.
  const allowLocalOrigins = envAllowsLocalOrigins();
  if (allowLocalOrigins) {
    console.warn(
      `[fetchproxy] ${ALLOW_LOCAL_ORIGINS_ENV}=1: accepting WebSocket upgrades from null and ` +
        `localhost page origins. This is a development escape — any local page the browser ` +
        `has open can reach this concentrator while it is set.`,
    );
  }

  /**
   * Origins already named in a warning. Bounded because the thing on the
   * other end of a refusal may be a page in a loop, and a log line per
   * attempt is a way to fill a disk from outside.
   */
  const warnedOrigins = new Set<string>();

  const wss = new WebSocketServer({
    server: opts.httpServer,
    maxPayload: opts.maxPayloadBytes ?? MAX_PAYLOAD_BYTES,
    verifyClient: (info, cb) => {
      const origin = info.req.headers.origin;
      const verdict = originVerdict(origin, allowLocalOrigins);
      if (verdict.allow) {
        cb(true);
        return;
      }
      // Only the escapable refusals say anything. A developer holding a
      // localhost page has a remedy and needs to be told it; a public page
      // has none, so there is nothing to print and every reason not to —
      // that refusal is the drive-by this gate exists for.
      if (verdict.escapable && origin !== undefined && warnedOrigins.size < 8) {
        if (!warnedOrigins.has(origin)) {
          warnedOrigins.add(origin);
          console.warn(
            `[fetchproxy] refused a WebSocket upgrade from ${JSON.stringify(origin)}: ` +
              `${verdict.reason}. If that is you, developing against the bridge, set ` +
              `${ALLOW_LOCAL_ORIGINS_ENV}=1 on this MCP — never on a deployed one.`,
          );
        }
      }
      cb(false, 403, verdict.reason);
    },
  });

  // Build own hello once at startup. The session nonce inside is what
  // the eventual ECDH session-key derivation will salt with, so we
  // recover it from the frame rather than threading it as a second
  // return value from the helper.
  const ownHello: HelloFrameFromServer = await buildServerHello({
    // 2.6.0: tell the extension it can say WHY it refused a hello, instead of
    // leaving us to time out and guess.
    accepts: ['hello-rejected'],
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
  // M1 (bridge review 2026-09-10): only ever set from `pairCodeFor` — the
  // number on the wire is checked against that, never copied out of the frame.
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

  /**
   * The joint pair code for an extension hello — `SHA256(ownPub || extPub)`,
   * the order the popup derives it in. The only code this MCP ever shows a
   * user, and the value every `pair-pending` frame is judged against.
   *
   * M1 (bridge review 2026-09-10): computed FROM THE LIVE HELLO on demand
   * rather than cached beside it, for the two reasons `peer.ts`'s twin gives —
   * a `pair-pending` interleaved with the hello it belongs to is judged
   * against that identity rather than against a derivation still in flight,
   * and a code cannot outlive the pair of identities it commits to, because
   * clearing `extensionHello` when the browser goes is the whole of retiring
   * it. A stale code left behind here would be one identity's number
   * vouching for the next connection's.
   */
  const pairCodeFor = async (
    hello: HelloFrameFromExtension,
  ): Promise<string | null> => {
    try {
      return await derivePairCodeFromIds(
        opts.ownIdentity.x25519Pub,
        fromB64(hello.identityX25519Pub),
      );
    } catch (e) {
      // Nothing to compare against and nothing to show. Every caller fails
      // closed on the null rather than falling back to the frame's number.
      console.error('[fetchproxy] could not derive the pair code:', e);
      return null;
    }
  };

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

    // Close a socket that never identifies itself. The check is on
    // `identified` rather than on a flag the hello paths have to remember to
    // clear: the extension path sets it only after an awaited pin read, so a
    // "we got a hello" flag set earlier would spare a socket the trust
    // decision is still refusing, and one set in two places is one somebody
    // forgets in the third. Unref'd because a host holding the event loop
    // open for fifteen seconds after its last socket died would be this
    // defense making the process harder to exit than it was.
    const handshakeTimer = setTimeout(() => {
      if (identified || closed) return;
      try {
        ws.close(1008, 'handshake timeout');
      } catch {
        /* already going down */
      }
    }, opts.handshakeTimeoutMs ?? HANDSHAKE_TIMEOUT_MS);
    handshakeTimer.unref?.();

    // A socket error is an EventEmitter 'error': unhandled, it is an uncaught
    // exception that takes the whole MCP process down. The cap above makes
    // that routine rather than exotic — `ws` reports an oversize frame by
    // emitting here (WS_ERR_UNSUPPORTED_MESSAGE_LENGTH) before closing with
    // 1009 — so a peer could kill the host by sending one big frame. `ws`
    // closes the socket itself; there is nothing to do but say so.
    ws.on('error', (e) => {
      console.warn(`[fetchproxy] host: socket error: ${String(e)}`);
    });

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
          //
          // M1 (bridge review 2026-09-10): the hook is handed OUR derivation
          // and never the wire's number — a code taken off a `pair-pending`
          // is the relay's claim about itself, which is precisely what the
          // SAS comparison is supposed to catch. What the hook is shown and
          // what a frame is judged against are the same function of the same
          // hello, so a deployment with no hook is judged identically.
          const helloPairCode = await pairCodeFor(frame);
          if (opts.onPairCode && helloPairCode !== null) {
            try {
              opts.onPairCode(helloPairCode);
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
          // 1.12.0 (#208): a peer joining an already-connected extension needs
          // the same identity material a peer that was here first receives.
          // Written to this peer BEFORE its hello goes the other way, to make
          // the dependency explicit rather than incidental: the extension
          // answers that hello with a `pair-pending`, and a peer judges one
          // against a code derived from the extension hello (M1). The order is
          // not what makes that safe — both sends are synchronous in one turn,
          // and the answer costs a round trip through the extension, so the
          // identity is on this socket long before it — but the two lines read
          // in the order the peer consumes them, and nothing later can reorder
          // them by accident.
          if (extensionHello) ws.send(JSON.stringify(extensionHello));
          if (extensionWs) extensionWs.send(JSON.stringify(frame));
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
              // Captured, not re-read after the await: the seq belongs to the
              // session whose key opened the frame, and a renegotiation
              // during the open would otherwise commit it against the new one.
              const session = ownSession;
              if (!session) return;
              // Claimed SYNCHRONOUSLY, before the await below: two copies of
              // one frame read in the same pass would otherwise both be told
              // the seq was free, since nothing moves the counter until the
              // open returns. The claim takes it out of circulation now, so
              // the duplicate is refused here as a replay.
              if (!session.claimInboundSeq(frame.seq)) return;
              let inner;
              try {
                inner = await openEncryptedFrame(session.sessionKey, frame);
              } catch (e) {
                // A frame that fails GCM authentication never happened: give
                // the claim back and leave the counter where it was —
                // otherwise one forged frame with a high seq takes every
                // genuine frame already in flight behind it down with the
                // socket it tears up.
                session.releaseInboundSeq(frame.seq);
                throw e;
              }
              // Only now is the seq spent.
              session.commitInboundSeq(frame.seq);
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
        // 2.6.0: the extension refused a hello and said why. Route exactly
        // like pair-pending — own → fail our own wait now; peer → forward —
        // so a refusal reaches whichever process was waiting on it.
        if (frame.type === 'hello-rejected' && identified === 'extension') {
          if (frame.mcpId === opts.ownMcpId) {
            // Fail FAST with the real reason rather than letting
            // `awaitSessionReady` time out and report a guess. A rejection of
            // this promise propagates through it unchanged.
            rejectOwnSession(
              new FetchproxyHelloRejectedError({ mcpId: frame.mcpId, reason: frame.reason }),
            );
          } else {
            // Gated exactly like `extension-disconnected` above, and for the
            // same reason: a peer older than 2.6.0 refuses the type in its
            // validator and closes the socket. Forwarding ungated would turn
            // a diagnosable refusal into a dropped connection — the very
            // failure the extension-side gate exists to prevent, one hop
            // further along. A peer that cannot hear it keeps today's
            // behaviour and times out.
            const slot = peers.get(frame.mcpId);
            if (slot?.helloFrame.accepts?.includes('hello-rejected')) {
              slot.ws.send(JSON.stringify(frame));
            }
          }
        }

        if (frame.type === 'pair-pending' && identified === 'extension') {
          if (frame.mcpId === opts.ownMcpId) {
            // M1 (bridge review 2026-09-10): the code a user compares against
            // the popup has to be the one this process derived from the two
            // identity pubs. The frame is plaintext and unauthenticated, and
            // it crosses whatever sits between us and the browser — so
            // displaying ITS number lets an in-path party show each end a
            // code of its own choosing and make the two "channels" agree. A
            // disagreement is therefore an alarm and a closed socket, never a
            // display value; there is no benign reading of it, since the real
            // extension derives the same way from the same two keys. Taken
            // from the hello that is live NOW and derived from it here, so
            // this judgement never sees a code half-written by the hello
            // handler it interleaves with, nor one left over from a browser
            // that has gone (see `pairCodeFor`).
            const hello = extensionHello;
            const derived = hello === null ? null : await pairCodeFor(hello);
            if (derived === null || frame.pairCode !== derived) {
              console.error(
                `[fetchproxy] ${opts.ownServerName}: the extension's pair code ` +
                  `(${frame.pairCode}) does not match the one derived from both ` +
                  `identities` +
                  (derived === null
                    ? ' (none — this MCP could not derive its own)'
                    : ` (${derived})`) +
                  ' — refusing to pair (possible MITM between this MCP and the extension)',
              );
              ws.close(1008, 'pair code mismatch');
              return;
            }
            ownPendingPairCode = derived;
            pendingPairListeners.forEach((cb) => cb(derived));
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
      clearTimeout(handshakeTimer);
      if (extensionClaim === ws) extensionClaim = null;
      if (identified === 'extension' && extensionWs === ws) {
        extensionWs = null;
        // M1 (bridge review 2026-09-10): dropping the hello is also what
        // retires the joint code — it belongs to THIS pair of identities, and
        // a stale one would let this browser's number vouch for whatever
        // connects next. Nothing separate is cleared, because `pairCodeFor`
        // keeps nothing separate to clear.
        extensionHello = null;
        if (!ownSession) {
          rejectOwnSession(new Error('extension disconnected before ready'));
        }
        ownSession = null;
        // A pair code the user never approved is not actionable once the
        // browser holding the popup is gone — and `bridgeHealth().session`
        // ranks `pair_pending` above "extension not attached", so leaving it
        // would tell the user to approve a popup that no longer exists. The
        // extension re-sends pair-pending on its next hello if it still
        // wants approval.
        ownPendingPairCode = null;
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
      // Measured before a seq is claimed, so a refused frame spends nothing
      // and leaves no gap. The socket this would go out on is the ONE the
      // extension holds for every MCP on this concentrator, so meeting its
      // `maxPayload` as a 1009 close would drop every sibling's bridge to
      // report that one of our own calls was too big.
      const plaintext = encodeOutboundInnerFrame(opts.ownMcpId, inner);
      const sealed = await sealInnerFrame(
        session.sessionKey,
        opts.ownMcpId,
        session.nextOutboundSeq(),
        plaintext,
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
