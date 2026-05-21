/**
 * Frame types for fetchproxy protocol v2 (0.4.0+).
 *
 * Top-level frames on the wire: hello, ready, frame (encrypted).
 * Inner frames (inside ciphertext): ping, pong, request, response.
 *
 * 0.2.0 wire change: the server hello carries `domains: string[]`
 * instead of `domain: string`. 0.1.x and 0.2.x cannot interoperate.
 *
 * 0.2.0 also introduces `capabilities: string[]` on the server hello
 * and a discriminated `op` on inner request/response frames so MCPs
 * can opt into additional verbs beyond `fetch` (e.g. `read_cookies`).
 *
 * 0.4.0: PROTOCOL_VERSION bumps 1 → 2. Extension hello frames now
 * carry an identity X25519 + Ed25519 pub plus a session nonce and a
 * signature binding the MCP-side hello nonce. Pair codes commit to
 * BOTH identities (MCP || extension), and trust records persist the
 * extension's identity so the MCP can verify extension session
 * signatures on subsequent connections. This is the MITM-as-extension
 * fix — 0.3.0 ↔ 0.4.0 are NOT interoperable and all packages release
 * together.
 *
 * 0.4.0 also adds `read_indexed_db`, JSON-pointer extraction in
 * storage reads, and glob patterns in declared key arrays. All
 * additions within v2 remain wire-additive — only the version bump
 * itself is a hard break.
 */

export const PROTOCOL_VERSION = 2 as const;
export type Platform = 'chrome' | 'safari' | 'firefox';

/**
 * Inner-verb capabilities an MCP may declare in its server hello.
 *
 * `'fetch'`                 — issue HTTP requests against the user's
 *                             signed-in tab. The default; if
 *                             `capabilities` is omitted, the extension
 *                             treats it as `['fetch']`.
 * `'read_cookies'`          — read cookies (HttpOnly-visible via
 *                             `chrome.cookies.get` on 0.3.0+) scoped to
 *                             declared `cookieKeys`. Strictly opt-in;
 *                             surfaces a warning in the pair popup so
 *                             the user sees the elevated trust.
 * `'read_local_storage'`    — read declared `localStorageKeys` from the
 *                             matched tab's localStorage. Elevated.
 * `'read_session_storage'`  — same shape against sessionStorage. Elevated.
 * `'capture_request_header'`— snapshot the next outgoing request's
 *                             declared header for a declared urlPattern.
 *                             Elevated. Single-shot per call.
 *
 * Future additions are wire-additive: unknown capabilities are rejected
 * by the validator, so adding a new verb requires extending this union.
 */
export type Capability =
  | 'fetch'
  | 'read_cookies'
  | 'read_local_storage'
  | 'read_session_storage'
  | 'capture_request_header';

/**
 * Set of capability strings that are valid on the wire. Runtime sibling
 * of the `Capability` union — kept here so validators in any package
 * (server, extension, protocol) can share one source of truth without
 * each defining their own private `Set`.
 */
export const KNOWN_CAPABILITIES: ReadonlySet<Capability> = new Set<Capability>([
  'fetch',
  'read_cookies',
  'read_local_storage',
  'read_session_storage',
  'capture_request_header',
]);

/**
 * Declaration entry for the `capture_request_header` capability — a
 * specific (urlPattern, headerName) pair the MCP is allowed to snapshot.
 * Pinned in the server hello and re-checked on every capture request.
 */
export interface CaptureHeaderDecl {
  /**
   * HTTPS URL with `*` wildcards permitted in the path. Host portion
   * must be a fully-qualified hostname (no wildcards). The extension
   * uses this as a Chrome `webRequest` filter pattern.
   */
  urlPattern: string;
  /** Single HTTP header name to capture (`[A-Za-z0-9\-_]+`, ≤128 chars). */
  headerName: string;
}

export interface HelloFrameFromServer {
  type: 'hello';
  protocolVersion: 2;
  role: 'server';
  mcpId: string;                  // server:version:rand
  serverName: string;
  version: string;
  /**
   * Non-empty array of hostnames this MCP is allowed to reach. The
   * extension treats each entry as "exact hostname or any subdomain
   * of it." (0.2.0+: replaces the singular `domain: string` field.)
   */
  domains: string[];
  /**
   * Optional non-empty list of inner-verb capabilities this MCP wants
   * to use. Defaults to `['fetch']` when absent — pre-capability MCPs
   * keep working without code changes. Unknown values are rejected by
   * the validator. The extension stores the approved set in the trust
   * record and forces a re-pair if the MCP later asks for a different
   * set.
   */
  capabilities?: Capability[];
  /**
   * 0.3.0+: declared cookie names the MCP is allowed to read via
   * `read_cookies`. The extension refuses requests for any key outside
   * this set. Empty/absent means no cookie reads are permitted even if
   * `'read_cookies'` is in `capabilities` (this is the safe default —
   * the user always sees the explicit list of names in the pair popup).
   */
  cookieKeys?: string[];
  /** 0.3.0+: declared localStorage keys for `read_local_storage`. */
  localStorageKeys?: string[];
  /** 0.3.0+: declared sessionStorage keys for `read_session_storage`. */
  sessionStorageKeys?: string[];
  /** 0.3.0+: declared (urlPattern, headerName) pairs for `capture_request_header`. */
  captureHeaders?: CaptureHeaderDecl[];
  identityX25519Pub: string;      // base64 raw 32B
  identityEd25519Pub: string;     // base64 raw 32B
  sessionNonce: string;           // base64 raw ≥16B
  sessionSig: string;             // base64 — Ed25519Sign(identityEd25519Priv, mcpId || sessionNonce)
}

export interface HelloFrameFromExtension {
  type: 'hello';
  protocolVersion: 2;
  role: 'extension';
  platform: Platform;
  extensionId: string;
  version: string;
  /**
   * 0.4.0+: long-term X25519 identity public key, base64 raw 32B.
   * Used by the MCP server to look up the trusted extension identity
   * and verify subsequent connections.
   */
  identityX25519Pub: string;
  /**
   * 0.4.0+: long-term Ed25519 identity public key, base64 raw 32B.
   * Used to verify the `ReadyFrame.sessionSig`.
   */
  identityEd25519Pub: string;
  /**
   * 0.4.0+: per-connection nonce, base64 ≥16B. Fresh per WS connect;
   * binds the `ReadyFrame.sessionSig` to this specific handshake.
   */
  sessionNonce: string;
}

export type HelloFrame = HelloFrameFromServer | HelloFrameFromExtension;

export interface ReadyFrame {
  type: 'ready';
  mcpId: string;
  extensionSessionPub: string;    // base64 raw 32B (ephemeral extension X25519 pub)
  /**
   * 0.4.0+: `Ed25519Sign(extEdPriv, mcpHelloSessionNonce || extHello.sessionNonce)`.
   * Verified by the MCP host's connection handler against the
   * extension's claimed `identityEd25519Pub` (from its earlier hello).
   * Binds both endpoints' fresh-per-connection nonces, so a relay
   * MITM can neither replay a captured signature nor substitute its
   * own keypair without producing a visible pair-code mismatch.
   */
  sessionSig: string;
}

export interface EncryptedFrame {
  type: 'frame';
  mcpId: string;
  seq: number;                    // monotonic per direction per session, ≥ 1
  iv: string;                     // base64 raw 12B
  ciphertext: string;             // base64 — AES-256-GCM(sessionKey, iv, innerFrameJson)
}

export type Frame = HelloFrame | ReadyFrame | EncryptedFrame;

// --- Inner frames (inside ciphertext) ---

export interface FetchInit {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  tabUrl: string;
}

export interface InnerPing {
  type: 'ping';
}
export interface InnerPong {
  type: 'pong';
}

/** `init` payload for an inner `op: 'read_cookies'` request (legacy 0.2.0 shape). */
export interface ReadCookiesInitLegacy {
  /**
   * Coarse prefix the extension uses to pick a tab via
   * `chrome.tabs.query({})`. Same semantics as `FetchInit.tabUrl`.
   *
   * Kept for back-compat with 0.2.0 senders. New code uses
   * `ReadCookiesInitV3` (origin + keys).
   */
  tabUrl: string;
}

/** 0.3.0 `init` payload for `read_cookies`: origin + declared key subset. */
export interface ReadCookiesInitV3 {
  /** Bare HTTPS origin (no path). E.g. `https://www.honeybook.com`. */
  origin: string;
  /**
   * Subset of the MCP's declared `cookieKeys` to read. Extension reads
   * via `chrome.cookies.get` so HttpOnly cookies ARE visible. Each entry
   * must appear in the trust record's `cookieKeys`.
   */
  keys: string[];
}

/** Discriminated init for `read_cookies` — 0.2.0 legacy or 0.3.0 new shape. */
export type ReadCookiesInit = ReadCookiesInitLegacy | ReadCookiesInitV3;

/** 0.3.0 `init` payload for `read_local_storage` / `read_session_storage`. */
export interface ReadStorageInit {
  /** Bare HTTPS origin of the tab whose storage is being read. */
  origin: string;
  /** Subset of declared `localStorageKeys` / `sessionStorageKeys`. */
  keys: string[];
}

/** 0.3.0 `init` payload for `capture_request_header`. */
export interface CaptureRequestHeaderInit {
  /**
   * HTTPS URL pattern (host fully qualified; `*` in path). Must exactly
   * match an entry in the declared `captureHeaders`.
   */
  urlPattern: string;
  /** Header name to capture (matches the declared entry exactly). */
  headerName: string;
  /**
   * Optional capture timeout in milliseconds. Defaults to 30000 on the
   * extension if omitted. After the timeout, the response is
   * `{ ok: false, op: 'capture_request_header', error: 'timeout' }`.
   */
  timeoutMs?: number;
}

export interface InnerRequestFetch {
  type: 'request';
  id: number;
  op: 'fetch';
  init: FetchInit;
}

export interface InnerRequestReadCookies {
  type: 'request';
  id: number;
  op: 'read_cookies';
  init: ReadCookiesInit;
}

export interface InnerRequestReadLocalStorage {
  type: 'request';
  id: number;
  op: 'read_local_storage';
  init: ReadStorageInit;
}

export interface InnerRequestReadSessionStorage {
  type: 'request';
  id: number;
  op: 'read_session_storage';
  init: ReadStorageInit;
}

export interface InnerRequestCaptureRequestHeader {
  type: 'request';
  id: number;
  op: 'capture_request_header';
  init: CaptureRequestHeaderInit;
}

/**
 * Inner request frame. Discriminated by `op` so MCPs can extend the
 * verb set without breaking existing fetch traffic.
 */
export type InnerRequest =
  | InnerRequestFetch
  | InnerRequestReadCookies
  | InnerRequestReadLocalStorage
  | InnerRequestReadSessionStorage
  | InnerRequestCaptureRequestHeader;

export interface InnerResponseFetchOk {
  type: 'response';
  id: number;
  ok: true;
  op: 'fetch';
  status: number;
  url: string;
  body: string;
}

export interface InnerResponseReadCookiesOk {
  type: 'response';
  id: number;
  ok: true;
  op: 'read_cookies';
  /**
   * Either the legacy raw `document.cookie` string (0.2.0 senders) or
   * the new 0.3.0 `values` map. Both shapes are accepted by the
   * validator; new senders always use `values`.
   */
  cookies?: string;
  /**
   * 0.3.0+: cookie name → value map, only including keys that exist.
   * The extension reads via `chrome.cookies.get` so HttpOnly cookies
   * are included.
   */
  values?: Record<string, string>;
}

export interface InnerResponseReadLocalStorageOk {
  type: 'response';
  id: number;
  ok: true;
  op: 'read_local_storage';
  /** Key → value map, omitting keys that don't exist in storage. */
  values: Record<string, string>;
}

export interface InnerResponseReadSessionStorageOk {
  type: 'response';
  id: number;
  ok: true;
  op: 'read_session_storage';
  values: Record<string, string>;
}

export interface InnerResponseCaptureRequestHeaderOk {
  type: 'response';
  id: number;
  ok: true;
  op: 'capture_request_header';
  /** Captured header value. */
  value: string;
}

/**
 * Successful inner response, discriminated by `op`. Existing 0.1.x
 * fetch responses (with no `op`) are accepted by the validator for
 * back-compat, but new servers always set it.
 */
export type InnerResponseOk =
  | InnerResponseFetchOk
  | InnerResponseReadCookiesOk
  | InnerResponseReadLocalStorageOk
  | InnerResponseReadSessionStorageOk
  | InnerResponseCaptureRequestHeaderOk;

export interface InnerResponseError {
  type: 'response';
  id: number;
  ok: false;
  /**
   * Optional op echo. Set by the extension when the failure is op-specific
   * (e.g. capability denied). Absent for transport-level failures (no tab,
   * fetch threw) since those predate the discriminator.
   */
  op?: Capability;
  error: string;
}
export type InnerFrame =
  | InnerPing
  | InnerPong
  | InnerRequest
  | InnerResponseOk
  | InnerResponseError;
