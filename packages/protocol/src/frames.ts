/**
 * Frame types for fetchproxy protocol v1 (0.2.0+).
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
 */

export const PROTOCOL_VERSION = 1 as const;
export type Platform = 'chrome' | 'safari' | 'firefox';

/**
 * Inner-verb capabilities an MCP may declare in its server hello.
 *
 * `'fetch'`       — issue HTTP requests against the user's signed-in tab.
 *                   The default; if `capabilities` is omitted, the extension
 *                   treats it as `['fetch']`.
 * `'read_cookies'` — read non-HttpOnly `document.cookie` from a matching
 *                    tab. Strictly opt-in; surfaces a warning in the pair
 *                    popup so the user sees the elevated trust.
 *
 * Future additions are wire-additive: unknown capabilities are rejected
 * by the validator, so adding a new verb requires bumping the protocol
 * or extending this union.
 */
export type Capability = 'fetch' | 'read_cookies';

/**
 * Set of capability strings that are valid on the wire. Runtime sibling
 * of the `Capability` union — kept here so validators in any package
 * (server, extension, protocol) can share one source of truth without
 * each defining their own private `Set`.
 */
export const KNOWN_CAPABILITIES: ReadonlySet<Capability> = new Set<Capability>([
  'fetch',
  'read_cookies',
]);

export interface HelloFrameFromServer {
  type: 'hello';
  protocolVersion: 1;
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
  identityX25519Pub: string;      // base64 raw 32B
  identityEd25519Pub: string;     // base64 raw 32B
  sessionNonce: string;           // base64 raw ≥16B
  sessionSig: string;             // base64 — Ed25519Sign(identityEd25519Priv, mcpId || sessionNonce)
}

export interface HelloFrameFromExtension {
  type: 'hello';
  protocolVersion: 1;
  role: 'extension';
  platform: Platform;
  extensionId: string;
  version: string;
}

export type HelloFrame = HelloFrameFromServer | HelloFrameFromExtension;

export interface ReadyFrame {
  type: 'ready';
  mcpId: string;
  extensionSessionPub: string;    // base64 raw 32B (ephemeral extension X25519 pub)
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

/** `init` payload for an inner `op: 'read_cookies'` request. */
export interface ReadCookiesInit {
  /**
   * Coarse prefix the extension uses to pick a tab via
   * `chrome.tabs.query({})`. Same semantics as `FetchInit.tabUrl`.
   */
  tabUrl: string;
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

/**
 * Inner request frame. Discriminated by `op` so MCPs can extend the
 * verb set without breaking existing fetch traffic.
 */
export type InnerRequest = InnerRequestFetch | InnerRequestReadCookies;

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
   * Raw `document.cookie` value (semicolon-separated `k=v` pairs) from
   * the matched tab. Only non-HttpOnly cookies are visible from page
   * JS — that is the intentional security model.
   */
  cookies: string;
}

/**
 * Successful inner response, discriminated by `op`. Existing 0.1.x
 * fetch responses (with no `op`) are accepted by the validator for
 * back-compat, but new servers always set it.
 */
export type InnerResponseOk = InnerResponseFetchOk | InnerResponseReadCookiesOk;

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
