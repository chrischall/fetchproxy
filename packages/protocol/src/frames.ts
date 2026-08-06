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
 *
 * 2.0.0: PROTOCOL_VERSION bumps 2 → 3. `ReadyFrame.sessionSig` now
 * covers the extension's EPHEMERAL public key as well as the two
 * nonces. Under v2 it did not, and that gap was the whole of the
 * remaining MITM: a relay could forward the genuine hellos and the
 * genuine signature while substituting an ephemeral key it held the
 * private half of, derive the same shared secret, and read the
 * session. Nothing the receiver checked committed to the key the ECDH
 * actually used. Same class of fix as 0.4.0's, and the same handling —
 * a hard break, all packages released together, no downgrade path
 * (a negotiated variant would just let a rewriting relay ask for v2).
 */

export const PROTOCOL_VERSION = 3 as const;

/**
 * HKDF info label for session-key derivation. Both sides (MCP server
 * and browser extension) must use the same value or the derived keys
 * diverge and AES-GCM decryption fails silently.
 */
export const HKDF_SESSION_INFO = 'fetchproxy/1.0.0/session' as const;

/**
 * The bytes `ReadyFrame.sessionSig` signs, in one place so the extension that
 * produces it and the two server paths that verify it cannot drift apart.
 *
 * `mcpHelloNonce || extHelloNonce || extensionSessionPub` (2.0.0+). The
 * ephemeral pub is what makes this worth signing: the nonces prove freshness
 * of the two endpoints, and only this third field commits to the key the
 * session is actually derived from.
 */
export function readySignaturePayload(
  mcpHelloNonce: Uint8Array,
  extHelloNonce: Uint8Array,
  extensionSessionPub: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(
    mcpHelloNonce.length + extHelloNonce.length + extensionSessionPub.length,
  );
  out.set(mcpHelloNonce, 0);
  out.set(extHelloNonce, mcpHelloNonce.length);
  out.set(extensionSessionPub, mcpHelloNonce.length + extHelloNonce.length);
  return out;
}

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
 *                             declared header for a declared
 *                             (host, path?). Elevated. Single-shot per call.
 * `'capture_redirect'`      — snapshot the redirect target URL of the next
 *                             request the browser makes to a declared
 *                             (host, path?), via
 *                             `chrome.webRequest.onBeforeRedirect`. Lets a
 *                             page-level fetch that sees only an opaque
 *                             cross-origin redirect recover the redirect
 *                             target (e.g. a presigned URL). Elevated.
 *                             Single-shot per call. Capture is limited to
 *                             the MCP's own declared `domains`.
 * `'download'`              — download a declared-domain URL via
 *                             `chrome.downloads`, i.e. the BROWSER's own
 *                             network stack (real cookies + TLS/JA3
 *                             fingerprint). Clears a Cloudflare challenge
 *                             that a page-level `fetch()` (cors mode)
 *                             cannot, and follows the cross-origin redirect
 *                             to the final file. Returns the saved local
 *                             file path (the bridge is loopback-only /
 *                             single-host, so the MCP reads it from the same
 *                             disk). Elevated — writes a file to the user's
 *                             machine. Limited to the MCP's declared `domains`.
 * `'read_dom'`              — read the value of a declared DOM element in the
 *                             matched tab, selected by a pinned CSS selector
 *                             (`domSelectors`). Runs in the content script's
 *                             ISOLATED world — it only touches the shared DOM
 *                             (`querySelector(...).value` / an attribute), never
 *                             page-MAIN-world JS, never a page function call, so
 *                             it cannot execute page code. Lets an MCP recover a
 *                             token a page writes into a hidden input (e.g. a
 *                             Cloudflare Turnstile `cf-turnstile-response`) that
 *                             a POST body must carry. Elevated — surfaces the
 *                             exact selectors in the pair popup. Scoped to the
 *                             MCP's declared `domains`.
 * `'graphql'`               — run a declared GraphQL operation through the
 *                             matched tab's OWN Apollo client
 *                             (`window.__APOLLO_CLIENT__`) in the page MAIN
 *                             world, reusing the DocumentNode the page already
 *                             owns for the declared `operationName`. This is
 *                             the organic request path, so it carries whatever
 *                             per-request bot-telemetry the page's Apollo link
 *                             injects — clearing edge bot-protection (e.g.
 *                             Akamai) that the isolated-world `fetch` path
 *                             cannot. The MCP declares an allowlist of
 *                             operations in `graphqlOps` (approved at pair
 *                             time, diffed on change); per-call requests
 *                             reference one by `name` and supply their own
 *                             `variables`. Elevated — surfaces the declared
 *                             operations in the pair popup. Scoped to the
 *                             MCP's declared `domains`.
 *
 * Future additions are wire-additive: unknown capabilities are rejected
 * by the validator, so adding a new verb requires extending this union.
 */
export type Capability =
  | 'fetch'
  | 'read_cookies'
  | 'read_local_storage'
  | 'read_session_storage'
  | 'capture_request_header'
  | 'capture_redirect'
  | 'read_indexed_db'
  | 'read_dom'
  | 'download'
  | 'graphql'
  | 'write_cookies';

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
  'capture_redirect',
  'read_indexed_db',
  'read_dom',
  'download',
  'graphql',
  'write_cookies',
]);

/**
 * 0.4.0+: declaration of a JSON-pointer extraction over a stored
 * blob. `key` must match a declared `localStorageKeys` (resp.
 * `sessionStorageKeys`) entry; `jsonPointer` is the RFC 6901 path
 * within the JSON-parsed value at that key.
 *
 * MCPs use this when an auth token lives nested inside a large JSON
 * blob in localStorage (HoneyBook's `jStorage` style). Without
 * pointer support the MCP either reads the whole 50KB and parses in
 * Node, OR declares each top-level key separately.
 */
export interface StoragePointerDecl {
  /** Storage key the pointer is evaluated against. */
  key: string;
  /** RFC 6901 JSON Pointer, beginning with `/`. */
  jsonPointer: string;
}

/**
 * 0.4.0+: declaration entry for `read_indexed_db`. The extension
 * gates per-call requests on subset-match against the declared
 * scopes: same `origin`/`database`/`store`, requested `keys` ⊆
 * declared `keys`. Pinned in the server hello and surfaced in the
 * pair popup so the user sees the exact DB / store names that this
 * MCP would read.
 */
export interface IndexedDbScopeDecl {
  /** Bare HTTPS origin (no path). E.g. `https://resy.com`. */
  origin: string;
  /** IndexedDB database name. 1-256 chars from `[A-Za-z0-9_.\-]`. */
  database: string;
  /** Object-store name in the database. Same char rules as database. */
  store: string;
  /** Non-empty array of key names to read. Same char rules. */
  keys: string[];
}

/**
 * Declaration entry for the `capture_request_header` capability — a
 * specific (host, path?, headerName) tuple the MCP is allowed to
 * snapshot. Pinned in the server hello and re-checked on every capture
 * request. The host is validated against the MCP's declared `domains`.
 */
export interface CaptureHeaderDecl {
  /**
   * Fully-qualified hostname (no scheme, no wildcards). Must be a
   * declared `domain` or a subdomain of one. The extension builds the
   * Chrome `webRequest` filter as `https://${host}${path ?? '/*'}`.
   */
  host: string;
  /**
   * Optional URL path to scope the capture. Omitted ⇒ all paths
   * (`/*`). Must start with `/`; a trailing `*` wildcard is allowed.
   */
  path?: string;
  /** Single HTTP header name to capture (`[A-Za-z0-9\-_]+`, ≤128 chars). */
  headerName: string;
}

/**
 * Declaration entry for the `read_dom` capability — a single named DOM
 * read the MCP is allowed to perform. Pinned in the server hello,
 * surfaced verbatim in the pair popup, and re-checked on every
 * `read_dom` call (per-call `names` must each match a declared entry).
 *
 * The extension reads the value from the ISOLATED-world content script:
 * `document.querySelector(selector)`, then `getAttribute(attribute)` when
 * `attribute` is set, otherwise the element's `.value` (falling back to
 * `.textContent`). It never enters the page MAIN world and never invokes
 * a page function — this is a pure DOM property read.
 */
export interface DomSelectorDecl {
  /**
   * Logical handle the MCP references in a per-call `read_dom` request
   * (via `ReadDomInit.names`). `[A-Za-z0-9_.\-]`, 1-128 chars. Unique
   * within `domSelectors`.
   */
  name: string;
  /**
   * CSS selector passed to `document.querySelector`. 1-512 chars, no
   * control characters. The extension reads the FIRST match only.
   */
  selector: string;
  /**
   * Optional attribute name to read via `getAttribute`. `[A-Za-z0-9\-_:]`,
   * ≤128 chars. Omitted ⇒ read the element's `.value`, falling back to
   * `.textContent` for non-form elements.
   */
  attribute?: string;
}

/**
 * Declaration entry for the `graphql` capability — a single named GraphQL
 * operation the MCP is allowed to invoke through the page's own Apollo
 * client. Pinned in the server hello, surfaced verbatim in the pair popup,
 * and re-checked on every `graphql_query` call (per-call `name` must match
 * a declared entry).
 *
 * The extension carries NO query text and NO persisted-query hash: it
 * resolves `name` → `operationName` → the live `DocumentNode` the page's
 * Apollo client already observed for that operation, then invokes
 * `client.query(...)` in the MAIN world. This auto-adapts when the site
 * revises the query.
 */
export interface GraphqlOpDeclaration {
  /**
   * Logical handle the MCP references in a per-call `graphql_query` request
   * (via `GraphqlQueryInit.name`). `[A-Za-z0-9_.\-]`, 1-256 chars. Unique
   * within `graphqlOps`.
   */
  name: string;
  /**
   * GraphQL operation name whose DocumentNode the page owns — e.g.
   * `'RestaurantsAvailability'`. Standard GraphQL name shape
   * (`[_A-Za-z][_0-9A-Za-z]*`).
   */
  operationName: string;
}

export interface HelloFrameFromServer {
  type: 'hello';
  protocolVersion: typeof PROTOCOL_VERSION;
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
  /** 0.3.0+: declared (host, path?, headerName) tuples for `capture_request_header`. */
  captureHeaders?: CaptureHeaderDecl[];
  /**
   * 0.4.0+: declared IndexedDB scopes the MCP is allowed to read via
   * `read_indexed_db`. Each entry declares a specific
   * `(origin, database, store, keys)` tuple — per-call requests must
   * subset-match an entry.
   */
  indexedDbScopes?: IndexedDbScopeDecl[];
  /**
   * 0.4.0+: declared JSON-pointer extractions over localStorage
   * values. Each entry binds `(localStorageKeys[i], jsonPointer)`.
   * Per-call requests must use a declared pair.
   */
  localStoragePointers?: StoragePointerDecl[];
  /** 0.4.0+: same shape for sessionStorage. */
  sessionStoragePointers?: StoragePointerDecl[];
  /**
   * 1.4.0+: declared DOM reads for `read_dom`. Each entry names a CSS
   * selector (+ optional attribute) the MCP may read from the matched
   * tab's DOM. Per-call `read_dom` requests reference these by `name`.
   * Empty/absent ⇒ no DOM reads permitted even if `'read_dom'` is in
   * `capabilities`.
   */
  domSelectors?: DomSelectorDecl[];
  /**
   * 1.x+: declared GraphQL operations for the `graphql` capability. Each
   * entry maps a logical `name` the MCP references per-call to the
   * `operationName` whose DocumentNode the page's Apollo client owns.
   * Per-call `graphql_query` requests reference these by `name`.
   * Empty/absent ⇒ no GraphQL operations permitted even if `'graphql'` is
   * in `capabilities`.
   */
  graphqlOps?: GraphqlOpDeclaration[];
  identityX25519Pub: string;      // base64 raw 32B
  identityEd25519Pub: string;     // base64 raw 32B
  sessionNonce: string;           // base64 raw ≥16B
  sessionSig: string;             // base64 — Ed25519Sign(identityEd25519Priv, mcpId || sessionNonce)
}

export interface HelloFrameFromExtension {
  type: 'hello';
  protocolVersion: typeof PROTOCOL_VERSION;
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
   * 2.0.0+: `Ed25519Sign(extEdPriv, mcpHelloSessionNonce ||
   * extHello.sessionNonce || extensionSessionPub)` — see
   * {@link readySignaturePayload}. Before 2.0.0 the ephemeral pub was NOT
   * covered, so a relay could swap it and share the session.
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

/**
 * 0.5.2+: extension → MCP notification that the user has been asked to
 * approve a pair for `mcpId`. Carries the same 6-digit joint pair code
 * the popup is showing (`SHA256(mcpPub || extPub)[0..3] mod 1_000_000`,
 * formatted `XXX-XXX`) so the MCP can surface it back to its caller
 * (typically as a tool error like "pairing required, code: 845-237").
 *
 * Routed by mcpId on the host (own → fire onPairCode + record, peer →
 * forward to peer WS). Unencrypted — the pair code is not a secret on
 * its own; security comes from the user comparing it across two
 * channels (extension popup + MCP-side display) before approving.
 *
 * Subsequent ready (after user approval) implicitly clears the pending
 * state on the MCP side. Cancellation has no explicit signal — the
 * stored pair code is a hint, not authoritative state.
 */
export interface PairPendingFrame {
  type: 'pair-pending';
  mcpId: string;
  pairCode: string;               // formatted "XXX-XXX"
}

export type Frame = HelloFrame | ReadyFrame | EncryptedFrame | PairPendingFrame;

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
   * 1.11.0+: optional cookie path, e.g. `/campus`.
   *
   * `chrome.cookies.get({ url, name })` matches the cookie's `Path` attribute
   * against the URL's path, so a cookie set with `Path=/campus` is invisible
   * to a read aimed at the origin root — the read silently returns nothing and
   * looks exactly like "the user is signed out". Tomcat scopes `JSESSIONID` to
   * the servlet context by default, so this is common, not exotic.
   *
   * Carried as its own validated field rather than folded into `origin`:
   * `origin` is deliberately constrained to a bare origin (see
   * `assertHttpsOriginOnly`) so a path cannot be smuggled past the domain gate,
   * and that invariant is worth keeping.
   */
  path?: string;
  /**
   * Subset of the MCP's declared `cookieKeys` to read. Extension reads
   * via `chrome.cookies.get` so HttpOnly cookies ARE visible. Each entry
   * must appear in the trust record's `cookieKeys`.
   */
  keys: string[];
}

/** Discriminated init for `read_cookies` — 0.2.0 legacy or 0.3.0 new shape. */
export type ReadCookiesInit = ReadCookiesInitLegacy | ReadCookiesInitV3;

/**
 * 1.12.0+ `init` payload for `write_cookies`.
 *
 * The only write verb on the wire. It exists for one failure class: sites that
 * ROTATE a credential cookie. The MCP refreshes, the site issues a new value,
 * and the copy in the browser's cookie is now dead — so the user gets silently
 * signed out of a tab they never touched, usually blamed on "inactivity".
 * Reading cannot fix that; only writing the rotated value back can.
 *
 * Deliberately scoped to the names already in the trust record's `cookieKeys`.
 * A write is strictly more dangerous than a read, so it is gated by its own
 * `write_cookies` capability that the user approves at pair time — but it
 * cannot reach a cookie the MCP was not already trusted to read, which keeps
 * the blast radius identical to the read scope the user already saw.
 */
export interface WriteCookiesInit {
  /** Bare HTTPS origin the cookies belong to. E.g. `https://www.example.com`. */
  origin: string;
  /** Optional cookie path, same semantics as {@link ReadCookiesInitV3.path}. */
  path?: string;
  /**
   * Cookies to set. Each `name` must appear in the trust record's
   * `cookieKeys`; the extension refuses the whole request otherwise rather
   * than partially applying it.
   */
  cookies: WriteCookieDecl[];
}

/** One cookie to write. Attributes beyond the value are deliberately not
 *  settable — this verb exists to refresh a value in place, not to author
 *  arbitrary cookies with attacker-chosen scope or lifetime. */
export interface WriteCookieDecl {
  name: string;
  value: string;
}

/** 0.3.0 `init` payload for `read_local_storage` / `read_session_storage`. */
export interface ReadStorageInit {
  /** Bare HTTPS origin of the tab whose storage is being read. */
  origin: string;
  /** Subset of declared `localStorageKeys` / `sessionStorageKeys`. */
  keys: string[];
  /**
   * 0.4.0+: optional pointer extractions. Each output key (record
   * key) names a value the response should include; the value
   * `{ storageKey, jsonPointer }` identifies the source. The
   * extension reads `storageKey` from storage, JSON-parses, evaluates
   * `jsonPointer`, and returns the extracted node as a JSON-stringified
   * string under the output key.
   *
   * Per-request pointers must each match a declared
   * `localStoragePointers` / `sessionStoragePointers` entry exactly.
   */
  pointers?: Record<string, { storageKey: string; jsonPointer: string }>;
}

/** 0.4.0 `init` payload for `read_indexed_db`. */
export interface ReadIndexedDbInit {
  /** Bare HTTPS origin (same shape as storage origin). */
  origin: string;
  /** IDB database name. Must match an entry in declared `indexedDbScopes`. */
  database: string;
  /** Object-store name. Must match the matching declared entry. */
  store: string;
  /** Subset of declared `keys` for the matching scope. */
  keys: string[];
}

/** 0.3.0 `init` payload for `capture_request_header`. */
export interface CaptureRequestHeaderInit {
  /**
   * Fully-qualified hostname. Must match an entry in the declared
   * `captureHeaders` (together with `path`).
   */
  host: string;
  /**
   * Optional URL path scoping. Omitted ⇒ all paths (`/*`). Must match
   * the declared entry (normalized: omitted ≡ `/*`).
   */
  path?: string;
  /** Header name to capture (matches the declared entry exactly). */
  headerName: string;
  /**
   * Optional capture timeout in milliseconds. Defaults to 30000 on the
   * extension if omitted. After the timeout, the response is
   * `{ ok: false, op: 'capture_request_header', error: 'timeout' }`.
   */
  timeoutMs?: number;
}

/**
 * `init` payload for `capture_redirect`. Lighter than
 * `CaptureRequestHeaderInit` — no `headerName` (the captured value is the
 * redirect target URL, not a header) and no declared-scope plumbing. The
 * extension gates the watched `host` against the MCP's declared `domains`.
 */
export interface CaptureRedirectInit {
  /**
   * Fully-qualified hostname (no scheme, no wildcards). Must be a declared
   * `domain` or a subdomain of one. The extension builds the Chrome
   * `webRequest` filter as `https://${host}${path ?? '/*'}`.
   */
  host: string;
  /**
   * Optional URL path scoping. Omitted ⇒ all paths (`/*`). Must start with
   * `/`; a trailing `*` wildcard is allowed.
   */
  path?: string;
  /**
   * Optional capture timeout in milliseconds. Defaults to 30000 on the
   * extension if omitted. After the timeout, the response is
   * `{ ok: false, op: 'capture_redirect', error: 'timeout' }`.
   */
  timeoutMs?: number;
}

/**
 * `init` payload for `download`. The extension hands `url` to
 * `chrome.downloads.download` — the BROWSER fetches it (real cookies +
 * TLS/JA3 fingerprint), so it clears a Cloudflare challenge a page-level
 * `fetch()` cannot, and follows the cross-origin redirect to the final
 * file. The `url` host is gated against the MCP's declared `domains`.
 */
export interface DownloadInit {
  /** Absolute `https:` URL to download. Host gated to declared `domains`. */
  url: string;
  /**
   * Optional download filename, relative to the browser's default
   * Downloads directory (e.g. `fetchproxy-tmp/abc.bin`). No absolute paths
   * and no `..` segments. Omitted ⇒ the browser names it from the response.
   */
  filename?: string;
  /**
   * Optional timeout in milliseconds. Defaults to 120000 on the extension
   * if omitted (downloads can be multi-MB). After the timeout, the response
   * is `{ ok: false, op: 'download', error: 'timeout' }`.
   */
  timeoutMs?: number;
}

/** `init` payload for `read_dom`. */
export interface ReadDomInit {
  /** Bare HTTPS origin of the tab whose DOM is being read. */
  origin: string;
  /**
   * Subset of the MCP's declared `domSelectors` names to read. Each
   * entry must match a declared `DomSelectorDecl.name`.
   */
  names: string[];
}

/** `init` payload for `graphql_query`. */
export interface GraphqlQueryInit {
  /**
   * Logical handle of the operation to invoke. Must match a declared
   * `graphqlOps[].name`. The extension resolves it to the corresponding
   * `operationName` → cached DocumentNode.
   */
  name: string;
  /**
   * The MCP's full GraphQL variables object, passed straight through to
   * `client.query({ query, variables })`. A plain (non-array, non-null)
   * object; may be empty.
   */
  variables: Record<string, unknown>;
  /**
   * Optional coarse tab hint the extension uses to pick the matched tab,
   * same semantics as `FetchInit.tabUrl`. Omitted ⇒ the extension picks a
   * tab on the MCP's declared domain.
   */
  tabUrl?: string;
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

export interface InnerRequestWriteCookies {
  type: 'request';
  id: number;
  op: 'write_cookies';
  init: WriteCookiesInit;
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

export interface InnerRequestCaptureRedirect {
  type: 'request';
  id: number;
  op: 'capture_redirect';
  init: CaptureRedirectInit;
}

export interface InnerRequestReadIndexedDb {
  type: 'request';
  id: number;
  op: 'read_indexed_db';
  init: ReadIndexedDbInit;
}

export interface InnerRequestReadDom {
  type: 'request';
  id: number;
  op: 'read_dom';
  init: ReadDomInit;
}

export interface InnerRequestDownload {
  type: 'request';
  id: number;
  op: 'download';
  init: DownloadInit;
}

export interface InnerRequestGraphqlQuery {
  type: 'request';
  id: number;
  op: 'graphql_query';
  init: GraphqlQueryInit;
}

/**
 * Inner request frame. Discriminated by `op` so MCPs can extend the
 * verb set without breaking existing fetch traffic.
 */
export type InnerRequest =
  | InnerRequestFetch
  | InnerRequestReadCookies
  | InnerRequestWriteCookies
  | InnerRequestReadLocalStorage
  | InnerRequestReadSessionStorage
  | InnerRequestCaptureRequestHeader
  | InnerRequestCaptureRedirect
  | InnerRequestReadIndexedDb
  | InnerRequestReadDom
  | InnerRequestDownload
  | InnerRequestGraphqlQuery;

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

export interface InnerResponseWriteCookiesOk {
  type: 'response';
  id: number;
  ok: true;
  op: 'write_cookies';
  /** Names actually written, echoed so the caller can confirm rather than
   *  assume. Same order as requested. */
  written: string[];
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

export interface InnerResponseCaptureRedirectOk {
  type: 'response';
  id: number;
  ok: true;
  op: 'capture_redirect';
  /** Captured redirect target URL (`details.redirectUrl`). */
  value: string;
}

export interface InnerResponseReadIndexedDbOk {
  type: 'response';
  id: number;
  ok: true;
  op: 'read_indexed_db';
  /**
   * Key → value map for keys present in the named (database, store).
   * Values are JSON-serializable (strings, numbers, booleans, null,
   * plain objects, arrays). Non-serializable values (Blob, typed
   * arrays, etc.) cause the entire call to fail rather than be
   * silently dropped — the user expected a specific value, not a
   * skipped one. Missing keys are omitted.
   */
  values: Record<string, unknown>;
}

export interface InnerResponseReadDomOk {
  type: 'response';
  id: number;
  ok: true;
  op: 'read_dom';
  /**
   * Name → value map for declared selectors whose element (and requested
   * property/attribute) was present. Names whose selector matched nothing,
   * or whose attribute was absent, are omitted.
   */
  values: Record<string, string>;
}

/** Saved-file metadata returned by a successful `download`. */
export interface DownloadResult {
  /** Absolute local path the browser saved the file to (`DownloadItem.filename`). */
  path: string;
  /**
   * Saved file size in bytes (`DownloadItem.fileSize`). Always a
   * non-negative integer on the wire — Chrome's own `-1` ("size unknown")
   * sentinel is clamped to `0` by the extension before sending, since this
   * field is required and validated strictly.
   */
  bytes: number;
  /** Server-reported MIME type, when known (`DownloadItem.mime`). */
  mime?: string;
  /** Final URL after redirects, when known (`DownloadItem.finalUrl`). */
  finalUrl?: string;
}

export interface InnerResponseDownloadOk {
  type: 'response';
  id: number;
  ok: true;
  op: 'download';
  /** Saved local file path + metadata. The MCP reads it from the same disk. */
  value: DownloadResult;
}

export interface InnerResponseGraphqlQueryOk {
  type: 'response';
  id: number;
  ok: true;
  op: 'graphql_query';
  /**
   * The GraphQL `data` object returned by the page's Apollo client
   * (e.g. `{ availability: [...] }`). A plain object; the MCP reads its
   * declared fields from here. The `ok: false` path (including the typed
   * "operation not yet observed on this tab" case) uses the shared
   * `InnerResponseError`.
   */
  data: unknown;
}

/**
 * Successful inner response, discriminated by `op`. Existing 0.1.x
 * fetch responses (with no `op`) are accepted by the validator for
 * back-compat, but new servers always set it.
 */
export type InnerResponseOk =
  | InnerResponseFetchOk
  | InnerResponseReadCookiesOk
  | InnerResponseWriteCookiesOk
  | InnerResponseReadLocalStorageOk
  | InnerResponseReadSessionStorageOk
  | InnerResponseCaptureRequestHeaderOk
  | InnerResponseCaptureRedirectOk
  | InnerResponseReadIndexedDbOk
  | InnerResponseReadDomOk
  | InnerResponseDownloadOk
  | InnerResponseGraphqlQueryOk;

export interface InnerResponseError {
  type: 'response';
  id: number;
  ok: false;
  /**
   * Optional op echo. Set by the extension when the failure is op-specific
   * (e.g. capability denied). Absent for transport-level failures (no tab,
   * fetch threw) since those predate the discriminator. Every op string
   * equals its capability name except `graphql_query` (governed by the
   * `'graphql'` capability), which is included explicitly here.
   */
  op?: Capability | 'graphql_query';
  error: string;
}
export type InnerFrame =
  | InnerPing
  | InnerPong
  | InnerRequest
  | InnerResponseOk
  | InnerResponseError;
