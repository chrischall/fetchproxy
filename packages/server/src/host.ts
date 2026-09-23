import { Server as HttpServer } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import {
  ecdhX25519,
  ed25519Verify,
  answersNoExtSession,
  generateX25519,
  helloSignaturePayload,
  readySignaturePayload,
  transcriptHash,
  fromB64,
  toB64,
  hkdfSha256,
  openEncryptedFrameDetailed,
  peekHelloVersion,
  sealInnerFrame,
  validateFrame,
  pairTranscript,
  HKDF_SESSION_INFO,
  PROTOCOL_VERSION,
  MAX_FRAME_BYTES,
  type Capability,
  type CaptureHeaderDecl,
  type IndexedDbScopeDecl,
  type DomSelectorDecl,
  type DomListSelectorDecl,
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
import {
  awaitSessionReady,
  FetchproxyHelloRejectedError,
  FetchproxyProtocolVersionError,
  protocolVersionCloseReason,
} from './session-ready.js';
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
  ownDomListSelectors?: DomListSelectorDecl[];
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
  /**
   * Mint the per-connection X25519 session ephemeral. Tests only, and the
   * only seam through which two of v4's properties can be asserted at all:
   * a test that holds the buffer this returns can check the private half was
   * ZEROED when the session ended, and a test that HOLDS the first call can
   * put two mints inside one process, which is the whole of Rule D (§1a).
   * Neither is reachable from the exported surface, and the alternative —
   * an accessor that exists only for the test — would be a readable copy of
   * the very key this task exists to make unreadable.
   *
   * @default generateX25519
   */
  generateSessionKeypair?: () => Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;
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

/**
 * How many frames in a row for the host's OWN session may fail authentication
 * before it re-handshakes that session. One is an expected straggler from a
 * previous session; a run means the keys have diverged.
 */
export const OWN_DECRYPT_FAILURES_BEFORE_REHANDSHAKE = 3;

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

  // 3.0.0 (protocol 4): everything about our own hello EXCEPT the two values
  // that are minted per extension session. The hello used to be built once at
  // startup and sent to every connection for the life of the process; under
  // v4 the session key is derived from `sessionPub`, so one hello per process
  // would bound forward secrecy at the process lifetime — worth having, not
  // worth calling forward secrecy (§1a Rule A).
  const ownHelloBase = {
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
    domListSelectors: opts.ownDomListSelectors,
    graphqlOps: opts.ownGraphqlOps,
  };
  const generateSessionKeypair = opts.generateSessionKeypair ?? generateX25519;

  let extensionWs: WebSocket | null = null;
  const peers = new Map<string, PeerSlot>();
  const ownInnerListeners: ((inner: InnerFrame) => void)[] = [];
  const disconnectListeners: (() => void)[] = [];
  const pendingPairListeners: ((code: string) => void)[] = [];
  let ownSession: SessionState | null = null;
  /**
   * The session ephemeral this host currently holds — minted per extension
   * connection (§1a Rule A), committed only while it is still the current one
   * (Rule D), and the ONLY thing a `ready` may be derived against. `null`
   * between extension sessions, which is also what makes a `ready` naming a
   * superseded `sessionPub` a discard rather than a derivation (Rule C).
   */
  let ownEphemeral: { nonce: Uint8Array; pub: Uint8Array; priv: Uint8Array } | null = null;

  /**
   * Zero the private half and drop it, answering `null` so the caller clears
   * `ownSession` in the SAME statement. Forward secrecy is the property that
   * an identity holder cannot open a PAST session, and it is false if the
   * process keeps every ephemeral private key it ever minted — so the drop
   * and the zeroing must not be two steps somebody can end up performing one
   * of.
   */
  function dropOwnSessionAndEphemeral(): null {
    if (ownEphemeral) ownEphemeral.priv.fill(0);
    ownEphemeral = null;
    return null;
  }

  /**
   * Install a mint that has passed Rule D's check. Zeroes whatever it
   * displaces: on this path the close handler has normally done that already,
   * but "normally" is not a property, and an install that leaked the previous
   * private half would be the same loss as never zeroing at all.
   */
  function installOwnEphemeral(next: { nonce: Uint8Array; pub: Uint8Array; priv: Uint8Array }): void {
    if (ownEphemeral) ownEphemeral.priv.fill(0);
    ownEphemeral = next;
  }

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

  // 3.0.0 (protocol 4), Task 4.2: the version refusal this host is standing
  // on, if any. Held because the refusal must OUTLIVE the socket it was made
  // on — a v3 extension reconnects on its backoff every few seconds, and a
  // call issued between two of those attempts must say "version mismatch"
  // rather than start a fresh thirty-second wait — and cleared the moment a
  // hello this build can actually read arrives, so upgrading the extension
  // does not also mean restarting every MCP.
  let ownSessionRefusal: FetchproxyProtocolVersionError | null = null;

  /**
   * Refuse a hello whose `protocolVersion` is not ours, out loud (Task 4.2).
   *
   * Reads the refused frame through {@link peekHelloVersion}, whose contract
   * is that it GRANTS NOTHING: no session is started, no `mcpId` slot bound,
   * no trust record read or written, no counter moved. Every field here came
   * out of a frame no validator accepted, so the version is used only to
   * decide whether to speak and the presence of an `mcpId` only to tell an
   * extension's hello (which carries none by construction) from a sibling
   * MCP's.
   *
   * That distinction is the whole reason this is not one branch: our session
   * is with the EXTENSION, so a stale v3 sibling registering on the
   * concentrator gets its own reason and its own close and must not be able
   * to fail our pending session.
   *
   * What a caller CAN do with the extension branch is make our next call fail
   * fast with a version sentence by sending one unsigned frame. That is not a
   * new boundary: the origin gate admits an extension scheme or no `Origin`
   * at all, so the population able to reach it is this uid's own processes,
   * which already hold `~/.fetchproxy/identity/*.json`. And the refusal is
   * self-clearing — the real extension's next hello ends it.
   *
   * That last sentence is only true of a host with NOTHING attached, which is
   * why the extension branch is gated on exactly that. This runs in the
   * `validateFrame` catch, upstream of the `extension already connected`
   * guard, so a v3 hello reaches it on any socket at any time — including
   * while a v4 extension holds the slot with a derived session. Standing a
   * refusal up there would destroy a WORKING bridge and wedge it for the life
   * of the connection: the attached extension has already sent its hello and
   * will not send another, so nothing clears the refusal, and a new socket is
   * refused `1008 'extension already connected'` — while `sessionLinked()`
   * and `extensionConnected()` both keep reporting true, so the bridge looks
   * healthy while every call fails with a version sentence about a version
   * nothing attached speaks. The reachable form of that is the rollout this
   * whole group exists for, not an adversary: an old Transporter in a second
   * browser profile dials the same port and reconnects on its backoff every
   * few seconds. The close below is unconditional — the stranger is refused
   * out loud either way; what is conditional is whether OUR session hears
   * about it.
   *
   * Returns whether it answered FOR the mismatch — false leaves the caller on
   * the pre-existing `1002 'protocol error'` path.
   */
  function refuseVersionMismatch(
    ws: WebSocket,
    raw: unknown,
    identified: 'extension' | 'peer' | null,
  ): boolean {
    const peek = peekHelloVersion(raw);
    if (!peek || peek.protocolVersion === PROTOCOL_VERSION) return false;
    const err = new FetchproxyProtocolVersionError({
      ourVersion: PROTOCOL_VERSION,
      theirVersion: peek.protocolVersion,
      peer: peek.mcpId === null ? 'extension' : 'mcp',
    });
    console.warn(`[fetchproxy] host: ${err.message}`);
    // Three names for one question — "is something better already here?" —
    // because the answer lives in a different variable at each stage of an
    // extension's arrival: `extensionClaim` from the synchronous moment a v4
    // hello lands, `extensionWs` once the trust read has let it take the slot,
    // `ownSession` once its `ready` has derived a key. They deliberately
    // overlap (today the claim is held for the whole life of the connection,
    // so it alone would answer), because the cost of a redundant conjunct is
    // nothing and the cost of a missing one is a wedged bridge.
    const nothingBetterAttached =
      extensionWs === null && extensionClaim === null && ownSession === null;
    // ...and the far end is judged on what THIS socket already is, not only on
    // what the frame claims. A socket that registered as a peer is a sibling
    // MCP process; a later hello from it carrying no `mcpId` peeks as
    // 'extension', which would let a stale sibling fail the session we hold
    // with the browser — the very thing the `peer` branch below exists to
    // prevent for the hellos that do carry one.
    if (err.peer === 'extension' && identified !== 'peer' && nothingBetterAttached) {
      ownSessionRefusal = err;
      // Two rejections and a reset between them, and each does a different
      // job: the first fails whoever is waiting NOW (the `request()` that
      // used to hang for thirty seconds), and the second leaves the fresh
      // promise already refused so a call issued AFTERWARDS fails fast with
      // the same message instead of waiting the timeout out again.
      rejectOwnSession(err);
      resetSessionPromise();
      rejectOwnSession(err);
    }
    try {
      ws.close(1002, protocolVersionCloseReason(err));
    } catch {
      /* already going down */
    }
    return true;
  }

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
   * The joint pair code for an extension hello — `pairTranscript(ownPub,
   * extPub, ourNonce, itsNonce, ourSessionPub)`, the five values in the order
   * the popup derives them in. The only code this MCP ever shows a user, and
   * the value every `pair-pending` frame is judged against.
   *
   * M1 (bridge review 2026-09-10): computed FROM THE LIVE HELLO on demand
   * rather than cached beside it, for the two reasons `peer.ts`'s twin gives —
   * a `pair-pending` interleaved with the hello it belongs to is judged
   * against that identity rather than against a derivation still in flight,
   * and a code cannot outlive the pair of identities it commits to, because
   * clearing `extensionHello` when the browser goes is the whole of retiring
   * it. A stale code left behind here would be one identity's number
   * vouching for the next connection's.
   *
   * 3.0.0 (protocol 4): the transcript also commits to OUR side of this
   * extension session — the hello nonce and the ephemeral we minted for it —
   * so `mint` is a PARAMETER rather than a read of `ownEphemeral` inside an
   * async function. At the hello the caller passes the locals it has just
   * minted, because `ownEphemeral` can be replaced by a second extension
   * hello inside this function's own await; everywhere else it passes
   * `ownEphemeral`, which is by then the one the live extension holds. No
   * mint, no code: the user has nothing to compare a number against, and
   * every caller already fails closed on the null.
   */
  const pairCodeFor = async (
    hello: HelloFrameFromExtension,
    mint: { nonce: Uint8Array; pub: Uint8Array } | null,
  ): Promise<string | null> => {
    if (!mint) return null;
    try {
      return await pairTranscript(
        opts.ownIdentity.x25519Pub,
        fromB64(hello.identityX25519Pub),
        mint.nonce,
        fromB64(hello.sessionNonce),
        mint.pub,
      );
    } catch (e) {
      // Nothing to compare against and nothing to show. Every caller fails
      // closed on the null rather than falling back to the frame's number.
      console.error('[fetchproxy] could not derive the pair code:', e);
      return null;
    }
  };

  /**
   * Consecutive frames for our OWN session that failed authentication. Reset by
   * any frame that authenticates, and by every new session.
   */
  let ownDecryptFailures = 0;

  /**
   * B-BUG-4 follow-up: re-handshake our OWN session on the socket we already
   * have. One undecryptable frame is a straggler from a previous session and
   * is dropped; a RUN of them means our key and the extension's have diverged,
   * and before this nothing would ever mend it — every reply for this MCP was
   * dropped until the process restarted. The old cure, closing the socket, is
   * not available: that socket is the extension's link for every MCP on this
   * concentrator.
   *
   * So only our half is reset — the session and its ephemeral go, sends wait
   * on a fresh promise — and a new hello is minted exactly as the extension
   * hello path does (§1a Rule A, and Rule D's re-check before the commit),
   * answering the extension session this socket already carries. The
   * extension treats it like any re-hello for an id this link holds, and its
   * `ready` lands on the ordinary derivation path. Peers are not involved.
   */
  const rehandshakeOwnSession = async (ws: WebSocket): Promise<void> => {
    const hello = extensionHello;
    if (extensionWs !== ws || !hello) return;
    console.warn(
      `[fetchproxy] ${opts.ownServerName}: ${OWN_DECRYPT_FAILURES_BEFORE_REHANDSHAKE} frames in a ` +
        `row from the extension failed authentication under this MCP's session key — ` +
        `re-handshaking this MCP's session (the extension stays connected).`,
    );
    ownSession = dropOwnSessionAndEphemeral();
    resetSessionPromise();
    const mintedKeypair = await generateSessionKeypair();
    const mintedHello: HelloFrameFromServer = await buildServerHello({
      ...ownHelloBase,
      sessionPub: mintedKeypair.publicKey,
      answersExtNonce: fromB64(hello.sessionNonce),
    });
    // Rule D: the extension may have gone (or been replaced, or a session
    // derived by some other path) while the crypto ran.
    if (extensionWs !== ws || extensionHello !== hello || ownSession !== null) {
      mintedKeypair.privateKey.fill(0);
      return;
    }
    installOwnEphemeral({
      nonce: fromB64(mintedHello.sessionNonce),
      pub: mintedKeypair.publicKey,
      priv: mintedKeypair.privateKey,
    });
    ws.send(JSON.stringify(mintedHello));
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
        let raw: unknown;
        try {
          raw = JSON.parse(data.toString());
        } catch {
          ws.close(1002, 'protocol error');
          return;
        }
        let frame: Frame;
        try {
          frame = validateFrame(raw);
        } catch {
          // 3.0.0 (protocol 4), Task 4.2: a version mismatch is the ONE
          // refusal that answers rather than dropping. Everything else keeps
          // today's generic close, so a malformed-frame flood neither changes
          // shape nor touches the pending session.
          if (!refuseVersionMismatch(ws, raw, identified)) ws.close(1002, 'protocol error');
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
          // 3.0.0 (protocol 4), Task 4.2: an extension this build CAN read is
          // attaching, so the standing version refusal is over. Its promise is
          // one nothing can resolve (it was rejected the moment the refusal
          // was made), and the only other thing that ever resets is this
          // socket's close — which never fires for a socket refused before it
          // was ever identified. Without this, upgrading the extension would
          // leave every MCP process wedged on a refusal about a version that
          // is no longer on the wire.
          if (ownSessionRefusal) {
            ownSessionRefusal = null;
            resetSessionPromise();
          }
          // 3.0.0 (protocol 4), §1a Rule A: mint a session ephemeral for THIS
          // extension session and build the hello from it. Placed after the
          // liveness re-check above and immediately before the send, so a
          // hello the trust decision refused mints nothing.
          //
          // All of the crypto goes into LOCALS, because both calls below
          // await: `ws` does not serialise this handler, so a second
          // extension hello can arrive, complete, and install its own mint
          // inside this window.
          const mintedKeypair = await generateSessionKeypair();
          const mintedHello: HelloFrameFromServer = await buildServerHello({
            ...ownHelloBase,
            sessionPub: mintedKeypair.publicKey,
            // The echo Rule B's gate reads, inside the signed payload: this
            // hello answers the extension session whose hello triggered it.
            answersExtNonce: fromB64(frame.sessionNonce),
          });
          // §1a Rule D — the commit, and the whole of it is that it is
          // SYNCHRONOUS and re-reads the single authoritative variable. The
          // idiom is `if (extensionWs !== ws) return;` at the v3 derivation
          // below, one handshake later; this is the same guard moved to the
          // mint. Without it, a mint for an extension session that has since
          // ended overwrites the live one when its crypto resolves — and
          // because the only thing that mints is an extension hello, and the
          // live extension has already sent its, nothing re-mints: the
          // session never opens and no error is raised.
          if (extensionWs !== ws) {
            mintedKeypair.privateKey.fill(0);
            return;
          }
          const mint = {
            nonce: fromB64(mintedHello.sessionNonce),
            pub: mintedKeypair.publicKey,
          };
          installOwnEphemeral({ ...mint, priv: mintedKeypair.privateKey });
          // 1.12.0 (#208): relay this hello to every peer, so a peer can
          // authenticate the extension behind us instead of taking whatever
          // `ready` we hand it on trust. Peers before 1.12.0 ignore the frame.
          // 3.0.0: it is also each peer's Rule A trigger — one per extension
          // session, to every peer in the map at this moment.
          for (const slot of peers.values()) slot.ws.send(JSON.stringify(frame));
          // Send own hello.
          ws.send(JSON.stringify(mintedHello));
          // 3.0.0: the replay of each peer's CACHED hello is GONE. Under v4
          // that frame is stale by construction — the `sessionPub` it names
          // is one the peer has already superseded or is about to — so the
          // extension would derive against a key nobody holds. The relay
          // above is what prompts each peer to hello afresh, and those are
          // forwarded as they arrive (§1a, Task 2.2).

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
          //
          // 3.0.0 (protocol 4): derived from the MINT's locals, because the
          // transcript commits to the nonce and the ephemeral of the hello
          // just sent — under v3 it read two long-term identity pubs and so
          // could be, and was, derived before that hello existed. It is also
          // LAST rather than first: the derivation awaits a SHA-256, and an
          // await placed before the send would let a second extension hello
          // install its own mint and send its own hello inside the window,
          // after which this one's arrives second and the extension derives
          // against an ephemeral nobody holds. The code is for a human to
          // read; the hello is what the session is made of.
          const helloPairCode = await pairCodeFor(frame, mint);
          if (opts.onPairCode && helloPairCode !== null) {
            try {
              opts.onPairCode(helloPairCode);
            } catch (e) {
              console.error('[fetchproxy] onPairCode threw:', e);
            }
          }
          return;
        }
        if (frame.type === 'hello' && frame.role === 'server') {
          // FP-C: authenticate the peer hello BEFORE touching the routing
          // table. Peer registration was unauthenticated — any local process
          // could `peers.set` a foreign mcpId and overwrite a legit peer's
          // routing slot (cross-server DoS / mcpId squatting). The hello
          // already carries an Ed25519 identity + a signature over its own
          // hello payload; verify it (proves the dialer holds the private key
          // it presents) before mapping the slot.
          // 3.0.0 (protocol 4): the payload comes from
          // `helloSignaturePayload`, so it covers the peer's `sessionPub` and
          // the extension session its hello answers. Verifying the v3
          // concatenation here would leave both fields unauthenticated while
          // compiling perfectly well — the ephemeral substitutable by
          // anything in the path, and the echo re-pointable at whichever
          // extension session a relay wanted the hello delivered to.
          const peerEdPub = fromB64(frame.identityEd25519Pub);
          const peerSigMsg = helloSignaturePayload(
            frame.mcpId,
            fromB64(frame.sessionNonce),
            fromB64(frame.sessionPub),
            fromB64(frame.answersExtNonce),
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
          // §1a Rule B, MIRRORED: hand a peer the cached extension hello only
          // in answer to a hello that answers NO extension session — i.e. a
          // registration hello. Un-gated, this send is itself a Rule A
          // trigger on every peer hello, including the re-hello the gate
          // below exists to let through: re-hello → forwarded → extension
          // hello sent back → mint → re-hello, unbounded. A peer already in
          // the map when an extension connects is triggered once by the
          // fan-out above instead, so nothing else needs this re-send.
          if (extensionHello && answersNoExtSession(frame.answersExtNonce)) {
            ws.send(JSON.stringify(extensionHello));
          }
          // §1a Rule B: forward a peer's hello to the extension only when the
          // hello NAMES the current extension session. Both operands are read
          // HERE — one off the frame, one off the single authoritative
          // variable — and nothing is recorded on `PeerSlot`. A per-peer mark
          // cannot do this job: this line runs after the `await ed25519Verify`
          // above, and the extension-hello handler re-points every peer's mark
          // inside that window, so a mark says which extension is attached NOW
          // rather than which one this frame was minted for. A registration
          // hello answers 32 zero bytes and so never matches a CSPRNG nonce.
          //
          // On the SPELLING rather than the bytes, and deliberately, because
          // the sibling predicate read one gate up decodes and says in its own
          // doc why ("base64 of 32 bytes leaves slack bits in its final
          // character"). What differs is what each compares against:
          // `answersNoExtSession` judges a value against a CONSTANT, whose
          // canonical spelling is not the writer's to choose, while this gate
          // judges two values that both came out of `toB64` — the one base64
          // encoder in this cohort, exported from `@fetchproxy/protocol` and
          // used by every producer of both fields — so here they round-trip
          // canonically. The residual is interop, not security: the echo is
          // inside the signed hello payload, so nothing in the path can
          // re-point it, and a divergent encoder makes this gate WITHHOLD (a
          // hang, never a stale ephemeral forwarded). If a second
          // implementation with its own encoder ever appears, the repair is to
          // compare `fromB64(...)` bytes at BOTH readers of this field — here
          // and `extension-core/src/background/server-hello.ts`'s Rule C
          // refusal — which is why they are named together.
          if (
            extensionWs &&
            extensionHello &&
            frame.answersExtNonce === extensionHello.sessionNonce
          ) {
            extensionWs.send(JSON.stringify(frame));
          }
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
            // 3.0.0 (protocol 4), §1a Rule C: is this `ready` for the
            // ephemeral we currently hold? Asked BEFORE the signature check,
            // and answered by a DISCARD rather than a refusal.
            //
            // Under v3 a stale `ready` and a forged one were the same 1008,
            // so an ordinary MV3 reconnect that raced a re-hello stranded a
            // bridged MCP. A mismatch here changes nothing, closes nothing
            // and rejects nothing, because the hello that superseded it is
            // already on its way. This branch is reached before anything has
            // been verified, so anything that can put a frame on the socket
            // can reach it — which is exactly why it must cost nothing.
            //
            // It is before the verify for a second reason: the extension
            // signs over the pub it derived against, so a stale `ready`'s
            // signature is ALWAYS over the stale pub, and checking the
            // signature first would refuse every stale one for the wrong
            // reason.
            const held = ownEphemeral;
            if (!held || frame.mcpSessionPub !== toB64(held.pub)) {
              console.warn(
                '[fetchproxy] discarding a ready for a session ephemeral this host no longer ' +
                  'holds (the extension reconnected while a hello was in flight)',
              );
              return;
            }
            const extEdPub = fromB64(extensionHello.identityEd25519Pub);
            const extNonce = fromB64(extensionHello.sessionNonce);
            const msg = readySignaturePayload(
              held.nonce,
              extNonce,
              fromB64(frame.extensionSessionPub),
              held.pub,
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
            // 3.0.0 (protocol 4): ephemeral × ephemeral, and the salt is the
            // TRANSCRIPT over both nonces and both ephemerals rather than our
            // own hello nonce. Under v3 our half of the ECDH was the
            // long-term identity key, so anyone holding this MCP's identity
            // plus a recording decrypted its sessions afterwards. Swapping
            // the salt is not a compile error either, which is why the test
            // beside this derives the key the browser's way and opens a real
            // frame with it.
            const extPub = fromB64(frame.extensionSessionPub);
            const shared = await ecdhX25519(held.priv, extPub);
            const salt = await transcriptHash(held.nonce, extNonce, held.pub, extPub);
            const key = await hkdfSha256(
              shared,
              salt,
              enc.encode(HKDF_SESSION_INFO),
              32,
            );
            if (extensionWs !== ws) return;
            ownSession = new SessionState(key);
            ownDecryptFailures = 0;
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
              const claim = session.claimInboundSeq(frame.seq);
              // A replay is dropped silently, as ever. Saturation is not a
              // replay — it drops frames that may be genuine — so say so, but
              // once per run of it: the session latches the warning until an
              // 'ok' claim shows the set has drained (#376).
              if (session.saturationWarningDue(claim)) {
                console.warn(
                  `[fetchproxy] ${opts.ownServerName}: dropped an inbound frame (seq ${frame.seq}) ` +
                    `unread — too many frames from the extension are still being opened ` +
                    `(inbound claims saturated). Not a replay. Further drops are not logged ` +
                    `until the in-flight set drains.`,
                );
              }
              if (claim !== 'ok') return;
              let result;
              try {
                // 'e2s': this socket is the extension's, so a frame the host
                // itself sealed and had reflected back at it fails the tag
                // rather than arriving as a well-formed inner frame.
                result = await openEncryptedFrameDetailed(session.sessionKey, frame, 'e2s');
              } catch (e) {
                // Documented never to throw; the claim must not leak if it does.
                session.releaseInboundSeq(frame.seq);
                throw e;
              }
              // B-BUG-4: mirror peer.ts. This socket is the EXTENSION's, shared
              // by every MCP on the concentrator, so one bad frame on the
              // host's own session must never close it — that used to reject
              // every MCP's in-flight calls and renegotiate every session.
              if (result.stage === 'decrypt-failed') {
                // A frame that fails GCM authentication never happened: give
                // the claim back and leave the counter where it was —
                // otherwise one forged frame with a high seq takes every
                // genuine frame already in flight behind it. Typically a
                // straggler from a previous session; drop it.
                session.releaseInboundSeq(frame.seq);
                console.warn(
                  `[fetchproxy] ${opts.ownServerName}: dropped an inbound frame (seq ${frame.seq}) ` +
                    `that failed authentication — most likely a straggler from a previous session.`,
                );
                // Counted only against the session that is still live: a
                // frame opened under a key since replaced says nothing about
                // the current one.
                if (session === ownSession) {
                  ownDecryptFailures += 1;
                  if (ownDecryptFailures >= OWN_DECRYPT_FAILURES_BEFORE_REHANDSHAKE) {
                    ownDecryptFailures = 0;
                    void rehandshakeOwnSession(ws).catch((e: unknown) =>
                      console.error(`[fetchproxy] ${opts.ownServerName}: re-handshake failed:`, e),
                    );
                  }
                }
                return;
              }
              // It authenticated under the live key, so the seq is spent.
              if (session === ownSession) ownDecryptFailures = 0;
              session.commitInboundSeq(frame.seq);
              if (result.stage === 'ok') {
                ownInnerListeners.forEach((cb) => cb(result.inner));
              } else {
                // 'validation-failed': a genuine frame from the live
                // extension with a malformed payload (e.g. version skew in a
                // response shape). Say so loudly and fail just the call
                // waiting on it, when its id is recoverable.
                console.error(
                  '[fetchproxy] host: received a frame that decrypted OK but failed validation:',
                  result.error,
                );
                const recoveredId = result.recoveredId;
                if (recoveredId !== undefined) {
                  ownInnerListeners.forEach((cb) =>
                    cb({
                      type: 'response',
                      id: recoveredId,
                      ok: false,
                      error: `malformed response failed protocol validation: ${String(result.error)}`,
                    }),
                  );
                }
              }
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
            //
            // 3.0.0 (protocol 4): the ephemeral is read the same way and at
            // the same moment, off `ownEphemeral` — the mint the live hello
            // named. Both halves are captured here, synchronously, so the
            // transcript this frame is judged against is one pairing's worth
            // of values rather than two.
            const hello = extensionHello;
            const mint = ownEphemeral;
            const derived = hello === null ? null : await pairCodeFor(hello, mint);
            if (derived === null || frame.pairCode !== derived) {
              console.error(
                `[fetchproxy] ${opts.ownServerName}: the extension's pair code ` +
                  `(${frame.pairCode}) does not match the one this MCP derived ` +
                  `from the pair transcript` +
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
        // 3.0.0 (protocol 4): the session and the private half it was derived
        // from go in ONE statement. This close IS the end of the extension
        // session the ephemeral was minted for, and from here no `ready` can
        // name it usefully — so keeping the key would buy nothing and cost
        // the forward secrecy this version exists for.
        ownSession = dropOwnSessionAndEphemeral();
        ownDecryptFailures = 0;
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
        if (peers.get(peerMcpId)?.ws === ws) {
          peers.delete(peerMcpId);
          // B-BUG-9: the extension keeps a session, scope grants and a link
          // binding per mcpId, and only a whole-link close used to clear
          // them — so every peer that came and went (each bootstrap lift,
          // each `fpx` call) left one behind, shown as connected in the
          // popup. Tell it, gated on its hello as extension-disconnected is
          // on a peer's: an older extension refuses the unknown type.
          if (extensionWs && extensionHello?.accepts?.includes('peer-gone')) {
            try {
              extensionWs.send(JSON.stringify({ type: 'peer-gone', mcpId: peerMcpId }));
            } catch {
              /* extension already gone; its own close tears everything down */
            }
          }
        }
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
        's2e',
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
