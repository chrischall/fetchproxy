import {
  generateMcpId,
  KNOWN_CAPABILITIES,
  undeclaredKeys,
  validateCaptureHeaderDecls,
} from '@fetchproxy/protocol';
import type {
  Capability,
  CaptureHeaderDecl,
  IndexedDbScopeDecl,
  DomSelectorDecl,
  GraphqlOpDeclaration,
  StoragePointerDecl,
  InnerFrame,
  FetchInit,
  ReadCookiesInitV3,
  DownloadResult,
} from '@fetchproxy/protocol';
import { electRole } from './election.js';
import { startHost, type HostHandle } from './host.js';
import { startPeer, type PeerHandle } from './peer.js';
import { loadOrCreateIdentity, type Identity } from './identity.js';
import { classifyFetchError, type FetchErrorKind } from './error-kind.js';
import { classifyBridgeError, type BridgeError } from './classify-bridge-error.js';

export interface FetchproxyServerOpts {
  /**
   * Localhost TCP port the concentrator binds to. The first MCP to call
   * a verb races the bind; if it wins it becomes the `'host'` and the
   * extension dials this port. Subsequent MCPs that lose the race
   * become `'peer'` and tunnel through the existing host on the same
   * port. The browser extension's connect target is hard-coded to the
   * default in its manifest, so you should only override this for
   * local development or test isolation — production MCPs all need to
   * share one port for the concentrator to work.
   *
   * @default 37149
   */
  port?: number;
  /**
   * Localhost interface to bind. Always keep this on a loopback address
   * — fetchproxy's threat model assumes single-user, single-host
   * trust; binding a public address would expose the bridge (and via
   * it, the user's signed-in cookies) to the network. Override only
   * for test setups that need a non-`127.0.0.1` loopback alias.
   *
   * @default '127.0.0.1'
   * @see https://github.com/chrischall/fetchproxy/blob/main/docs/SECURITY.md
   */
  host?: string;
  /**
   * Stable identifier for this MCP — typically the npm package name
   * (`'opentable-mcp'`, `'honeybook-mcp'`). Surfaced in three places:
   * the extension UI's pair popup, the identity-key filename
   * (`~/.fetchproxy/identity/<serverName>.json`), and the computed
   * `mcpId`. Changing it after first pair means the user re-pairs
   * (different identity file path) — pick a name and keep it. No
   * default; required.
   */
  serverName: string;
  /**
   * Your MCP's package version (`'0.10.0'`). Surfaced in the pair popup
   * alongside `serverName` so the user can see what they're approving.
   * Pure label — does not gate any behavior in the bridge or the
   * extension. No default; required.
   */
  version: string;
  /**
   * Trust boundary. Non-empty array of hostnames. The extension refuses
   * any fetch outside these domains (or any subdomain of them).
   * Pair-code trust is keyed off the MCP's cryptographic identity together
   * with this set.
   *
   * Single-domain ergonomics: with `domains: ['opentable.com']`, all
   * convenience-method calls default to `https://opentable.com` and
   * `{ subdomain: 'www' }` targets `https://www.opentable.com`.
   *
   * Multi-domain MCPs (e.g. `domains: ['honeybook.com', 'hbsplit.com']`)
   * must specify `{ domain: 'honeybook.com' }` on every per-call request
   * so the resolver knows which base to use.
   *
   * No default; required. Changing the set after first pair forces the
   * user to re-approve in the extension popup with a diff UI.
   */
  domains: string[];
  /**
   * Optional non-empty list of inner-verb capabilities this MCP wants
   * to use. Defaults to `['fetch']`. Including `'read_cookies'` unlocks
   * `FetchproxyServer.readCookies()` but surfaces a warning in the pair
   * popup — only declare it if the MCP genuinely needs a cookie snapshot.
   * Changing the set after a pair forces the user to re-approve.
   */
  capabilities?: Capability[];
  /**
   * 0.3.0+: declared cookie names the MCP is allowed to read via
   * `readCookies({ keys })`. Each call's `keys` is checked subset-of this
   * list at the call site (gate #1); the extension re-checks against the
   * pair-approved trust record (gate #2). Empty/absent means cookie
   * reads with explicit keys are not permitted — back-compat
   * `readCookies()` without `keys` arg still works.
   */
  cookieKeys?: string[];
  /** 0.3.0+: declared localStorage keys for `readLocalStorage`. */
  localStorageKeys?: string[];
  /** 0.3.0+: declared sessionStorage keys for `readSessionStorage`. */
  sessionStorageKeys?: string[];
  /** 0.3.0+: declared (host, path?, headerName) tuples for `captureRequestHeader`. */
  captureHeaders?: CaptureHeaderDecl[];
  /**
   * 0.4.0+: declared IndexedDB scopes for `readIndexedDb()`. Each
   * entry is `{ origin, database, store, keys }`. Per-call requests
   * must subset-match a declared scope.
   */
  indexedDbScopes?: IndexedDbScopeDecl[];
  /**
   * 0.4.0+: declared JSON-pointer extractions over localStorage
   * values. Each entry `{ key, jsonPointer }` binds an existing
   * `localStorageKeys` entry to a pointer. Per-call `readLocalStorage`
   * requests must use a declared pair.
   */
  localStoragePointers?: StoragePointerDecl[];
  /** 0.4.0+: same shape against sessionStorage. */
  sessionStoragePointers?: StoragePointerDecl[];
  /**
   * 1.4.0+: declared DOM selectors for `readDom()`. Each entry is
   * `{ name, selector, attribute? }`. Per-call requests reference these
   * by `name` (subset-match). Reads a value from the matched tab's DOM
   * (isolated-world `querySelector`), e.g. a Cloudflare Turnstile token
   * a page writes into a hidden input that a POST body must carry.
   */
  domSelectors?: DomSelectorDecl[];
  /**
   * 1.x+: declared GraphQL operations for `graphqlQuery()`. Each entry
   * is `{ name, operationName }`. Requires `'graphql'` in `capabilities`.
   * Per-call `graphqlQuery` requests reference these by `name`
   * (subset-match). The extension resolves `name` → `operationName` →
   * the live DocumentNode the page's Apollo client already observed, then
   * invokes `client.query(...)` in the page's MAIN world — the same path
   * the site itself uses, so per-request bot telemetry (Akamai etc.) runs
   * automatically. Empty/absent ⇒ no GraphQL operations permitted even if
   * `'graphql'` is declared.
   */
  graphqlOps?: GraphqlOpDeclaration[];
  /**
   * Override the on-disk directory that holds this MCP's long-term
   * identity keypair (`<identityDir>/<serverName>.json`, mode 0600).
   * The identity is what makes pair trust survive restarts; rotating
   * it forces the user to re-pair. Override for tests (point at a
   * tmpdir) or for sandboxed deployments where `$HOME` isn't writable.
   * Production MCPs running as the user should leave this alone.
   *
   * @default '~/.fetchproxy/identity/'
   */
  identityDir?: string;
  /**
   * 0.4.0+: invoked once on receipt of the extension hello, with the
   * joint pair code derived from `SHA256(mcpPub || extPub)`. Used by
   * MCPs that need to surface the code on stderr or similar for the
   * user to verify against the browser popup. Optional — fetch-only
   * MCPs that don't need to print can omit it. (Off by default.)
   *
   * Override when the MCP host runs in an environment where the user
   * can't see stdout/stderr by default (e.g. Claude Desktop), so the
   * code can be surfaced via an MCP logging notification or similar
   * out-of-band channel.
   */
  onPairCode?: (code: string) => void;
  /**
   * 0.8.0+: per-request timeout (ms) for `fetch()`. The bridge has
   * no native timeout, so without this a frozen tab / dropped
   * extension would hang the call indefinitely. When the timer fires,
   * `fetch()` returns `{ ok: false, kind: 'timeout', error: '…' }`
   * (back-compat result shape); convenience methods (`get`/`post`/
   * `request` etc.) throw `FetchproxyTimeoutError`.
   *
   * Override to tighten for latency-sensitive call sites (e.g. interactive
   * tool calls where the user is waiting), or loosen for endpoints
   * known to be slow (large file downloads, long-running search). Pass
   * `0` to opt back into the legacy hang-forever behavior.
   *
   * @default 30_000
   * @see https://github.com/chrischall/fetchproxy/issues/58
   */
  fetchTimeoutMs?: number;
  /**
   * 0.8.0+: delay (ms) before the one-shot retry on the SW-eviction
   * cold-start symptom. `captureRequestHeader()` revives on
   * `content_script_unreachable`; `fetch()` revives on that AND on a
   * server-side `timeout` (#90 — a fully-cold worker often surfaces the
   * first post-idle `fetch()` as a `timeout` while Chrome is still
   * spinning the SW up). Chrome MV3 evicts extension service workers
   * after ~30s idle; this gives Chrome a moment to wake the SW on the
   * next inbound frame. The default `2_000` is the same value the
   * realty/dining cohort had been hand-rolling in their transport
   * adapters.
   *
   * Override to lengthen for slow machines where 2s isn't enough for
   * the SW to wake, or shorten if the caller is willing to surface
   * the bridge-down error sooner. On retry-exhaustion, convenience
   * methods + capture throw `FetchproxyBridgeDownError` (or
   * `FetchproxyTimeoutError` when the cold-start was a timeout) with
   * `retryAttempted: true`. Pass `0` to disable the retry entirely
   * (errors surface on the first attempt with `retryAttempted: false`).
   *
   * @default 2_000
   * @see https://github.com/chrischall/fetchproxy/issues/58
   * @see https://github.com/chrischall/fetchproxy/issues/90
   */
  bridgeReviveDelayMs?: number;
  /**
   * Server-initiated keep-alive ping interval (ms). The bridge fires
   * a no-op `{ type: 'ping' }` inner frame to the extension every
   * `keepAliveIntervalMs` while the MCP has been active (fetch /
   * capture success or failure, or `markActive()`) within
   * `keepAliveMaxIdleMs`. The extension responds with `pong`, which
   * resets Chrome's MV3 service-worker idle timer (any frame in/out
   * resets it).
   *
   * Comfortably under Chrome's ~30s eviction threshold. Override only
   * if you've measured a specific eviction pattern that needs a
   * different cadence. Set to `0` to disable (no pings).
   *
   * The extension-side `chrome.alarms` keepalive still runs
   * independently; this is the belt-and-braces server-initiated arm
   * that addresses the round-3 #23 feedback (alarm-only was
   * insufficient because the alarm doesn't re-arm while the SW is
   * evicted).
   *
   * @default 20_000 (since #90 — tightened from the 0.10.0 default of
   *   25_000, which left too little margin under Chrome's ~30s eviction
   *   window and still lost the cold-start race; 25_000 itself was the
   *   round-3 #71 cohort value promoted from off-by-default)
   * @see https://github.com/chrischall/fetchproxy/issues/67
   * @see https://github.com/chrischall/fetchproxy/issues/71
   * @see https://github.com/chrischall/fetchproxy/issues/90
   */
  keepAliveIntervalMs?: number;
  /**
   * 0.8.1+: how long after the most-recent user-visible activity
   * (fetch / capture success or failure, or `markActive()`) to keep
   * firing keep-alive pings. Paired with `keepAliveIntervalMs` —
   * without an idle gate, a long-running but dormant MCP would ping
   * forever and waste the SW's wake-budget on nothing.
   *
   * Override to lengthen for MCPs whose user-visible activity is
   * spread across long gaps (e.g. multi-step workflows where the user
   * thinks for a while between tool calls). Has no effect when
   * `keepAliveIntervalMs` is `0`.
   *
   * @default 300_000 (5 minutes)
   * @see https://github.com/chrischall/fetchproxy/issues/67
   */
  keepAliveMaxIdleMs?: number;
}

/**
 * The successful arm of the `fetch()` discriminated union. Any
 * upstream HTTP status (2xx, 3xx, 4xx, 5xx) returns this shape —
 * `ok: true` means "the bridge delivered a response", not "the
 * upstream returned 2xx". Inspect `status` for HTTP-level success.
 */
export interface FetchResult {
  /** Discriminator for the union with `FetchResultError`. */
  ok: true;
  /** Upstream HTTP status code (any 1xx-5xx). */
  status: number;
  /** Final URL after redirects, as observed by the browser. */
  url: string;
  /** Raw response body as a UTF-8 string. */
  body: string;
  /**
   * 0.8.0+: true when the server's lazy-revive retry path actually
   * fired for this call (a `content_script_unreachable` first attempt —
   * or, since 0.11.0+/#90, a cold-start `timeout` first attempt —
   * followed by a successful retry). False on the no-retry path.
   * Always populated by the server in 0.8.0+; declared optional in the
   * type so downstream test code that constructs envelope literals
   * directly stays back-compat without code changes.
   */
  retryAttempted?: boolean;
}

/**
 * The failure arm of the `fetch()` discriminated union. Only returned
 * when the bridge itself failed to deliver the request (no signed-in
 * tab, extension offline, transport timeout, etc.) — upstream HTTP
 * errors come back as `FetchResult` with a non-2xx `status`. The
 * convenience methods (`request`/`get`/`post`/…) translate this into
 * a typed throwable via `_typedErrorFor`.
 */
export interface FetchResultError {
  /** Discriminator for the union with `FetchResult`. */
  ok: false;
  /** Human-readable error string from the bridge or extension. */
  error: string;
  /**
   * Derived categorization of `error` so downstream MCPs can branch
   * on a small discriminated set rather than grep'ing strings. Always
   * populated by the server in 0.4.3+. The raw `error` string remains
   * the source of truth — `kind` is additive guidance.
   */
  kind: FetchErrorKind;
  /**
   * 0.8.0+: true when the server's lazy-revive retry path actually
   * fired AND the retry also failed. False otherwise (retry was
   * disabled, or this isn't a cold-start symptom so retry didn't
   * apply). The retry arms on a `content_script_unreachable` failure
   * or — since 0.11.0+/#90 — a cold-start `timeout`. Always populated
   * by the server in 0.8.0+; declared optional in the type so
   * downstream test code that constructs envelope literals directly
   * stays back-compat.
   */
  retryAttempted?: boolean;
  /**
   * 0.8.0+: actual elapsed milliseconds when `kind === 'timeout'`
   * (the timer firing wins the race). Populated only for the timeout
   * arm; undefined for other failure kinds.
   */
  elapsedMs?: number;
}

/**
 * Public response shape returned by the convenience helpers
 * (`get`/`post`/`request`/…). Strictly the success path — these
 * methods throw `FetchproxyHttpError` / `FetchproxyProtocolError`
 * on failure rather than returning a discriminated union.
 */
export interface HttpResponse {
  /** Upstream HTTP status code (any 1xx-5xx). */
  status: number;
  /** Raw response body as a UTF-8 string. */
  body: string;
  /** Final URL after redirects, as observed by the browser. */
  url: string;
}

/**
 * Options accepted by `request()` and the verb helpers. `subdomain`
 * controls per-call which host within the declared domain to target;
 * `domain` picks which base domain (only meaningful when the MCP
 * declared more than one):
 *
 *   fp.get('/path')                                          → https://${domains[0]}/path
 *   fp.get('/path', { subdomain: 'www' })                    → https://www.${domains[0]}/path
 *   fp.get('/path', { domain: 'b.com', subdomain: 'api' })   → https://api.b.com/path
 *
 * `subdomain` must be a single DNS label (or dot-separated labels)
 * without any URL scheme, path, or slashes.
 * `domain` must exactly equal one of the entries in
 * `FetchproxyServerOpts.domains`.
 */
export interface RequestOpts {
  /**
   * Per-call HTTP request headers. Merged into the outbound request
   * verbatim. JSON shortcuts add `Content-Type: application/json`
   * unless the caller already provided one. Off by default.
   */
  headers?: Record<string, string>;
  /**
   * Raw request body as a string. The bridge does not transform it —
   * `JSON.stringify` your own object if you're not using the JSON
   * shortcuts. Off by default (no body sent).
   */
  body?: string;
  /**
   * If provided, throws `FetchproxyHttpError` when the response status
   * does not match. A number is matched exactly; an array means "must be in this set".
   * Off by default — the caller inspects `response.status` themselves.
   */
  expectStatus?: number | number[];
  /**
   * Optional subdomain label(s) to prepend to the chosen base domain.
   * E.g. with base `'opentable.com'`, `subdomain: 'www'` builds the
   * URL against `https://www.opentable.com`. May be a single label
   * (`'www'`) or dot-separated labels (`'auth.api'`). Off by default
   * (uses the apex domain).
   */
  subdomain?: string;
  /**
   * Optional base domain selector for multi-domain MCPs. Must match one
   * of the entries in `FetchproxyServerOpts.domains` exactly. Required
   * on every per-call request when the MCP declared multiple domains;
   * may be omitted when only one domain is declared (the lone entry
   * becomes the implicit default).
   */
  domain?: string;
}

/**
 * Options accepted by JSON/HTML shortcuts (`getJson`/`postJson`/
 * `getHtml`/`get`/`delete`/…) — body is provided positionally so it
 * isn't part of this options object. Otherwise identical to
 * `RequestOpts`.
 */
export interface BodylessRequestOpts {
  /** Same as `RequestOpts.headers`. */
  headers?: Record<string, string>;
  /** Same as `RequestOpts.expectStatus`. */
  expectStatus?: number | number[];
  /** Same as `RequestOpts.subdomain`. */
  subdomain?: string;
  /** Same as `RequestOpts.domain`. */
  domain?: string;
}

/**
 * Thrown when the fetchproxy bridge itself failed to relay the request
 * (e.g. no signed-in tab, extension offline, transport error).
 */
export class FetchproxyProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FetchproxyProtocolError';
  }
}

/**
 * Thrown when the upstream HTTP response did not match an explicit
 * `expectStatus`. Carries the full response so the caller can inspect
 * status / body / url.
 */
export class FetchproxyHttpError extends Error {
  constructor(
    public readonly response: HttpResponse,
    message?: string,
  ) {
    super(message ?? `HTTP ${response.status} on ${response.url}`);
    this.name = 'FetchproxyHttpError';
  }
}

/**
 * 0.8.0+: thrown when the extension's MV3 service worker is
 * unreachable. Subclass of `FetchproxyProtocolError` so callers
 * already catching the parent still match.
 *
 * `retryAttempted: true` means the server's one-shot lazy-revive
 * retry (`bridgeReviveDelayMs`) already burned and the SW is still
 * down. `false` means the retry was disabled (`bridgeReviveDelayMs`
 * unset / 0), so the user could enable it for next time.
 */
export class FetchproxyBridgeDownError extends FetchproxyProtocolError {
  readonly originalError: string;
  readonly retryAttempted: boolean;
  readonly op: 'fetch' | 'capture_request_header' | 'capture_redirect' | 'download';
  readonly url?: string;
  /** 0.8.0+: bridge role at throw time; `null` if listen() hadn't bound yet. */
  readonly role: 'host' | 'peer' | null;
  /** 0.8.0+: bridge port at throw time (the same port `listen()` bound to). */
  readonly port: number;
  readonly hint: string;

  constructor(args: {
    originalError: string;
    retryAttempted?: boolean;
    op?: 'fetch' | 'capture_request_header' | 'capture_redirect' | 'download';
    url?: string;
    role?: 'host' | 'peer' | null;
    port?: number;
  }) {
    const retryAttempted = args.retryAttempted ?? false;
    const op = args.op ?? 'fetch';
    const retryClause = retryAttempted
      ? `Server already burned a one-shot lazy-revive retry; SW is still down. `
      : `Server lazy-revive retry was disabled (bridgeReviveDelayMs unset/0). `;
    const hint =
      `the fetchproxy extension's service worker is not responding ` +
      `("${args.originalError}"). Chrome evicts extension service ` +
      `workers after ~30s idle by default. ${retryClause}` +
      // #90 (P1-1): the real fix per the error's own diagnostic
      // (content_script_unreachable = a matched tab with no loaded
      // content script) is having a loaded, signed-in tab for that
      // domain — NOT clicking the toolbar icon (which doesn't inject a
      // content script into pre-existing tabs). Make the guidance match.
      `Make sure a tab for this domain is open, fully loaded, and ` +
      `signed in (the bridge fetches through that tab) — then retry. ` +
      `If it keeps happening, reload the extension from ` +
      `chrome://extensions and reload the tab.`;
    super(
      `fetchproxy bridge down during ${op}${args.url ? ` (${args.url})` : ''}. ${hint}`,
    );
    this.name = 'FetchproxyBridgeDownError';
    this.originalError = args.originalError;
    this.retryAttempted = retryAttempted;
    this.op = op;
    if (args.url !== undefined) this.url = args.url;
    this.role = args.role ?? null;
    this.port = args.port ?? 0;
    this.hint = hint;
  }
}

/**
 * 0.8.0+: thrown by convenience methods when `fetchTimeoutMs` fires.
 * The lower-level `fetch()` returns `{ ok: false, kind: 'timeout' }`
 * instead (back-compat with its result-envelope shape). Subclass of
 * `FetchproxyProtocolError` so existing callers still match.
 *
 * `retryAttempted: true` (0.11.0+, #90/#91) means the server's one-shot
 * lazy-revive retry (`bridgeReviveDelayMs`) treated this timeout as the
 * SW-eviction cold-start symptom, warmed the worker, and the retry also
 * timed out. `false` means the retry was disabled
 * (`bridgeReviveDelayMs` unset / 0), so the timeout surfaced on the
 * first attempt. Mirrors `FetchproxyBridgeDownError.retryAttempted` so
 * callers can branch identically across both throwable kinds.
 */
export class FetchproxyTimeoutError extends FetchproxyProtocolError {
  readonly url: string;
  readonly timeoutMs: number;
  /** 0.8.0+: bridge role at throw time; `null` if listen() hadn't bound yet. */
  readonly role: 'host' | 'peer' | null;
  /** 0.8.0+: bridge port at throw time. */
  readonly port: number;
  /** 0.8.0+: actual elapsed milliseconds when the timer won the race. */
  readonly elapsedMs: number;
  /**
   * 0.11.0+ (#90/#91): true when the server's lazy-revive retry path
   * fired for this timeout (a cold-start `timeout` symptom followed by
   * a warm-and-retry that also timed out). False when the retry was
   * disabled (`bridgeReviveDelayMs` unset/0) so the timeout surfaced on
   * the first attempt.
   */
  readonly retryAttempted: boolean;

  constructor(args: {
    url: string;
    timeoutMs: number;
    role?: 'host' | 'peer' | null;
    port?: number;
    elapsedMs?: number;
    retryAttempted?: boolean;
  }) {
    super(
      `fetchproxy: ${args.url} did not respond within ${args.timeoutMs}ms`,
    );
    this.name = 'FetchproxyTimeoutError';
    this.url = args.url;
    this.timeoutMs = args.timeoutMs;
    this.role = args.role ?? null;
    this.port = args.port ?? 0;
    this.elapsedMs = args.elapsedMs ?? args.timeoutMs;
    this.retryAttempted = args.retryAttempted ?? false;
  }
}

/**
 * 0.8.0+: snapshot of the bridge's process-wide freshness counters,
 * returned by `FetchproxyServer.bridgeHealth()`. Downstream MCPs use
 * this to power their `healthcheck` tools without re-tracking the
 * same counters in their transport adapters.
 */
export interface BridgeHealth {
  /** Bridge role at snapshot time; `null` if `listen()` never connected. */
  role: 'host' | 'peer' | null;
  /** Localhost port the bridge is bound to (matches `FetchproxyServerOpts.port`). */
  port: number;
  /** 0.8.0+: server version this bridge was constructed with. */
  serverVersion: string;
  /**
   * 0.8.0+: resolved per-request timeout (ms). Reflects either the
   * constructor override or the 0.8.0+ default of 30_000. Surfaced
   * so cohort healthcheck tools don't need a local
   * `DEFAULT_FETCH_TIMEOUT_MS` constant that risks drifting from the
   * server when defaults move. `0` means the caller explicitly opted
   * back into the legacy hang-forever behavior.
   *
   * @default 30_000
   * @see https://github.com/chrischall/fetchproxy/issues/58
   * @see https://github.com/chrischall/fetchproxy/issues/82
   */
  fetchTimeoutMs: number;
  /**
   * 0.8.0+: resolved lazy-revive delay after `content_script_unreachable`
   * (ms). Reflects either the constructor override or the 0.8.0+ default
   * of 2_000. Surfaced for the same drift-avoidance reason as
   * `fetchTimeoutMs`. `0` means the caller explicitly opted out of the
   * one-shot retry.
   *
   * @default 2_000
   * @see https://github.com/chrischall/fetchproxy/issues/58
   * @see https://github.com/chrischall/fetchproxy/issues/82
   */
  bridgeReviveDelayMs: number;
  /**
   * Wall-clock timestamp of the most recent user-visible `fetch()` /
   * capture success. Null until the first success lands.
   */
  lastSuccessAt: number | null;
  /**
   * Wall-clock timestamp of the most recent user-visible `fetch()` /
   * capture failure (any kind). Null until the first failure lands.
   */
  lastFailureAt: number | null;
  /**
   * `${kind}: ${error}` string from the most recent failure — handy
   * for surfacing the latest reason in a healthcheck tool. Null until
   * the first failure lands.
   */
  lastFailureReason: string | null;
  /**
   * Failures since the last success. Resets to 0 on any success. Use
   * as a "soft degraded" signal in a healthcheck tool.
   */
  consecutiveFailures: number;
  /**
   * 0.8.0+ (#23 ask 4): wall-clock timestamp of the most recent
   * inner frame received from the extension (regardless of whether
   * it was a success or error for the calling MCP). Distinct from
   * `lastSuccessAt`/`lastFailureAt`, which track *user-visible*
   * fetch outcomes — `lastExtensionMessageAt` is "is the extension
   * still answering?" liveness. Null until the first frame arrives.
   */
  lastExtensionMessageAt: number | null;
  /**
   * 0.10.0+ (#73): keep-alive observability surface for downstream
   * healthcheck tools. `enabled` mirrors the `> 0` interval guard;
   * `intervalMs` / `maxIdleMs` are the resolved option values (20_000
   * / 300_000 by default, since #90 tightened the interval from 25_000);
   * `lastPingAt` / `totalPings` track timer
   * activity (monotonic, never reset); `idleSinceMs` is the elapsed
   * time since `lastActiveAt`, or null if no activity has been recorded.
   */
  keepAlive: {
    enabled: boolean;
    intervalMs: number;
    maxIdleMs: number;
    lastPingAt: number | null;
    totalPings: number;
    idleSinceMs: number | null;
  };
  /**
   * 0.10.0+ (#73): MV3 SW-eviction observability. `lazyReviveAttempts`
   * increments when the lazy-revive retry path fires (one-shot on the
   * cold-start symptom — `content_script_unreachable`, or a `fetch()`
   * `timeout` as of #90); `lazyReviveSuccesses` increments when the
   * post-revive retry actually succeeds. `lastEvictionDetectedAt`
   * stamps the most recent time we observed a cold-start symptom (the
   * canonical sign of Chrome having evicted the SW between bursts) —
   * overwritten on each detection, so it reflects the latest eviction,
   * not the first.
   */
  swEviction: {
    lazyReviveAttempts: number;
    lazyReviveSuccesses: number;
    lastEvictionDetectedAt: number | null;
  };
}

/**
 * 0.11.0+: the typed result of `FetchproxyServer.runProbe()`. The
 * transport half of the healthcheck loop zillow/redfin/homes had been
 * duplicating verbatim in `src/tools/healthcheck.ts` — run a probe
 * fetch, measure elapsed ms, classify any error, and project
 * `bridgeHealth()` into a `bridge` sub-object.
 *
 * The tool registration + the site-specific hint text STAY in the
 * consumer — `runProbe` only does probe execution + classification +
 * the bridge projection, so each MCP keeps its own `${Site} redirecting
 * on login` phrasing.
 */
export interface BridgeProbeResult {
  /** True iff the probe `fetchFn` resolved without throwing. */
  ok: boolean;
  /** Wall-clock milliseconds the probe `fetchFn` took (success or failure). */
  elapsed_ms: number;
  /**
   * Snake-cased projection of `bridgeHealth()` — the subset cohort
   * healthcheck tools surface. Read after the probe so the freshness
   * counters reflect this very round-trip.
   */
  bridge: {
    role: 'host' | 'peer' | null;
    port: number;
    server_version: string;
    fetch_timeout_ms: number;
    last_success_at: number | null;
    last_failure_at: number | null;
    last_failure_reason: string | null;
    consecutive_failures: number;
  };
  /**
   * Present only when `ok` is false. `kind` is `classifyBridgeError`'s
   * verdict over the thrown error (`'timeout' | 'bridge_down' | 'http' |
   * 'protocol' | 'other'`); `message` is the error's message (or its
   * `String()` for a non-Error throw).
   */
  error?: {
    kind: BridgeError;
    message: string;
  };
}

/** Single DNS label or dot-separated labels (no scheme, no path). */
const SUBDOMAIN_LABEL_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;

function assertSubdomainLabel(label: string): void {
  if (!SUBDOMAIN_LABEL_RE.test(label)) {
    throw new Error(
      `FetchproxyServer: subdomain must be a DNS label like "www" or "api" (or dot-separated like "auth.api"), got ${JSON.stringify(label)}`,
    );
  }
}

/**
 * Verify that a request URL's hostname is one of the declared `domains`
 * or a subdomain of one of them. Used on every resolved request URL —
 * guards against an absolute URL being passed that escapes the declared
 * domain set.
 */
function assertUrlInDomains(field: string, url: string, domains: readonly string[]): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`FetchproxyServer: ${field} is not a valid URL: ${JSON.stringify(url)}`);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error(
      `FetchproxyServer: ${field} must be http(s), got ${parsed.protocol} (${url})`,
    );
  }
  const host = parsed.hostname.toLowerCase();
  for (const d of domains) {
    const expected = d.toLowerCase();
    if (host === expected || host.endsWith('.' + expected)) return;
  }
  const declared = domains.map((d) => JSON.stringify(d)).join(', ');
  throw new Error(
    `FetchproxyServer: ${field} host "${host}" is outside declared domains [${declared}] — must be one of them or a subdomain`,
  );
}

interface ResolvedOpts {
  port: number;
  host: string;
  serverName: string;
  version: string;
  domains: string[];
  capabilities: Capability[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: CaptureHeaderDecl[];
  indexedDbScopes: IndexedDbScopeDecl[];
  localStoragePointers: StoragePointerDecl[];
  sessionStoragePointers: StoragePointerDecl[];
  domSelectors: DomSelectorDecl[];
  graphqlOps: GraphqlOpDeclaration[];
  fetchTimeoutMs?: number;
  bridgeReviveDelayMs?: number;
  keepAliveIntervalMs: number;
  keepAliveMaxIdleMs: number;
  identityDir?: string;
  onPairCode?: (code: string) => void;
}

const DEFAULT_JSON_OK_STATUSES: readonly number[] = [200, 201, 202, 204];

/** Result of a successful `read_cookies` call. */
export interface ReadCookiesResult {
  /** Discriminator for the union with `ReadCookiesResultError`. */
  ok: true;
  /**
   * Raw `document.cookie` value (semicolon-separated `k=v` pairs).
   * HttpOnly cookies are NOT included — they're invisible to page JS
   * by design, which is the intentional security boundary of the
   * `read_cookies` capability.
   */
  cookies: string;
}

/** Result of a failed `read_cookies` call (transport / capability / no-tab). */
export interface ReadCookiesResultError {
  /** Discriminator for the union with `ReadCookiesResult`. */
  ok: false;
  /** Human-readable error string from the bridge or extension. */
  error: string;
}

/**
 * The MCP-facing handle for the fetchproxy bridge.
 *
 * `listen()` loads identity and reserves nothing. The first verb call
 * (or an explicit `connect()`) races the configured port: if the bind
 * succeeds, the instance becomes the concentrator (role `'host'`) the
 * extension dials. If the port is already taken by another fetchproxy
 * host, the instance becomes a peer (role `'peer'`) and tunnels through
 * that host's existing WebSocket. Either way, callers issue `fetch()`
 * (or one of the verb shortcuts) and get the response from the user's
 * signed-in browser tab as if they'd run `window.fetch` there
 * themselves.
 *
 * Behavior is identical between host and peer roles — `role` is
 * surfaced mostly for testability and metrics. Callers should not
 * branch on it.
 */
export class FetchproxyServer {
  /**
   * Bridge role. `null` until the first verb call (or an explicit
   * `connect()`) — `listen()` no longer triggers the role election
   * as of 0.5.3+. Reset to `null` on `close()`.
   */
  public role: 'host' | 'peer' | null = null;

  private opts: ResolvedOpts;
  private hostHandle: HostHandle | null = null;
  private peerHandle: PeerHandle | null = null;
  // 0.13.0+: true from the start of `close()` until the next `doConnect()`.
  // Distinguishes an intentional shutdown (whose WS close we must ignore)
  // from the host process dying (which strands a peer and must trigger
  // re-election). The WS `close` event fires asynchronously, so this stays
  // latched across `close()` rather than being reset in its tail.
  private closing = false;
  private nextRequestId = 1;
  // 0.8.0+: process-wide freshness counters surfaced via bridgeHealth().
  // Replaces the local copies every downstream MCP was rolling on top
  // of its own transport adapter — see realty-mcp cohort drift notes.
  // Updated by recordSuccess / recordFailure from fetch + capture paths.
  // `lastExtensionMessageAt` (#23 ask 4) is updated whenever any inner
  // frame from the extension arrives — gives extension-side liveness
  // distinct from per-call success/failure.
  private lastSuccessAt: number | null = null;
  private lastFailureAt: number | null = null;
  private lastFailureReason: string | null = null;
  private consecutiveFailures = 0;
  private lastExtensionMessageAt: number | null = null;
  private pending = new Map<number, (r: FetchResult | FetchResultError) => void>();
  // Separate pending map for read_cookies so the response shape (cookies
  // string vs status/body) doesn't have to share a union type with fetch.
  // Ids are still unique across both maps because `nextRequestId` advances
  // for every outbound inner request.
  private pendingReadCookies = new Map<
    number,
    (r: ReadCookiesResult | ReadCookiesResultError) => void
  >();
  // 0.3.0+: storage-read awaiters resolve a values map directly. We split
  // them off from `pending` (fetch) and `pendingReadCookies` (legacy
  // string-shape) so the response routing in `onInner` stays linear.
  private pendingStorage = new Map<
    number,
    { resolve: (v: Record<string, string>) => void; reject: (e: Error) => void }
  >();
  // 0.3.0+: capture-header awaiters resolve a single string.
  private pendingCapture = new Map<
    number,
    { resolve: (v: string) => void; reject: (e: Error) => void }
  >();
  // capture_redirect awaiters resolve the captured redirect URL string.
  private pendingRedirect = new Map<
    number,
    { resolve: (v: string) => void; reject: (e: Error) => void }
  >();
  // 0.4.0+: read_indexed_db awaiters resolve a JSON-typed values map.
  private pendingIdb = new Map<
    number,
    { resolve: (v: Record<string, unknown>) => void; reject: (e: Error) => void }
  >();
  // download awaiters resolve the saved-file metadata (path + size + mime).
  private pendingDownload = new Map<
    number,
    { resolve: (v: DownloadResult) => void; reject: (e: Error) => void }
  >();
  // 1.x+: graphql_query awaiters resolve the GraphQL `data` object. Its
  // shape is operation-specific, so the awaiter resolves `unknown` and the
  // caller narrows.
  private pendingGraphql = new Map<
    number,
    { resolve: (v: unknown) => void; reject: (e: Error) => void }
  >();
  private mcpId: string | null = null;
  private identity: Identity | null = null;
  // 0.5.3+: in-flight role-election / handle-start promise. Set the
  // first time a verb call runs `ensureConnected`, awaited by concurrent
  // callers, cleared once the connection is up. Single source of truth
  // for "we're connecting right now" so two parallel first-calls don't
  // race the port bind.
  private connectingPromise: Promise<void> | null = null;
  // 0.8.1+ (#67): server-initiated keep-alive ping. Active when
  // `keepAliveIntervalMs` is set AND we've seen recent activity
  // (fetch/capture success or failure, or markActive()) within
  // `keepAliveMaxIdleMs`. The interval handle is created lazily on
  // first activity and torn down on close() / extension disconnect.
  private keepAliveTimer: ReturnType<typeof setInterval> | null = null;
  private lastActiveAt: number | null = null;
  // 0.10.0+ (#73): observability counters surfaced via
  // bridgeHealth().keepAlive / .swEviction. Monotonic across the process
  // lifetime so a downstream healthcheck tool can verify the keep-alive
  // is actually preventing SW eviction. `lastPingAt` and `totalPings`
  // are stamped from `startKeepaliveIfIdle`'s tick. `lazyRevive*` and
  // `lastEvictionDetectedAt` are stamped from the lazy-revive code path
  // in fetch() / captureRequestHeader().
  private lastPingAt: number | null = null;
  private totalPings = 0;
  private lazyReviveAttempts = 0;
  private lazyReviveSuccesses = 0;
  private lastEvictionDetectedAt: number | null = null;

  constructor(opts: FetchproxyServerOpts) {
    if (!Array.isArray(opts.domains) || opts.domains.length === 0) {
      throw new Error(
        'FetchproxyServer: opts.domains must be a non-empty array of hostnames',
      );
    }
    // Default to ['fetch'] so existing callers that pre-date capabilities
    // keep working without code changes. When provided, the array must be
    // non-empty and contain only known capability strings — guard at the
    // call site so the error is clear rather than mysteriously bouncing
    // off the extension's validator later.
    let capabilities: Capability[];
    if (opts.capabilities === undefined) {
      capabilities = ['fetch'];
    } else {
      if (!Array.isArray(opts.capabilities) || opts.capabilities.length === 0) {
        throw new Error(
          'FetchproxyServer: opts.capabilities must be a non-empty array (or omit it for the default ["fetch"])',
        );
      }
      for (const c of opts.capabilities) {
        if (!KNOWN_CAPABILITIES.has(c)) {
          throw new Error(
            `FetchproxyServer: unknown capability ${JSON.stringify(c)} — known values: ["fetch", "read_cookies"]`,
          );
        }
      }
      capabilities = [...opts.capabilities];
    }
    // 0.13.0+ (#102 successor): validate declared captureHeaders against
    // the declared domains at construction — fail loud at boot rather
    // than silently at the bridge handshake. Each capture `host` must be
    // a declared domain or a subdomain of one.
    if (opts.captureHeaders !== undefined) {
      try {
        validateCaptureHeaderDecls(opts.captureHeaders, opts.domains);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        throw new Error('FetchproxyServer: invalid captureHeaders — ' + message);
      }
    }
    this.opts = {
      port: opts.port ?? 37149,
      host: opts.host ?? '127.0.0.1',
      serverName: opts.serverName,
      version: opts.version,
      domains: [...opts.domains],
      capabilities,
      cookieKeys: [...(opts.cookieKeys ?? [])],
      localStorageKeys: [...(opts.localStorageKeys ?? [])],
      sessionStorageKeys: [...(opts.sessionStorageKeys ?? [])],
      captureHeaders: (opts.captureHeaders ?? []).map((d) => ({
        host: d.host,
        ...(d.path !== undefined ? { path: d.path } : {}),
        headerName: d.headerName,
      })),
      indexedDbScopes: (opts.indexedDbScopes ?? []).map((d) => ({
        origin: d.origin,
        database: d.database,
        store: d.store,
        keys: [...d.keys],
      })),
      localStoragePointers: (opts.localStoragePointers ?? []).map((d) => ({
        key: d.key,
        jsonPointer: d.jsonPointer,
      })),
      sessionStoragePointers: (opts.sessionStoragePointers ?? []).map((d) => ({
        key: d.key,
        jsonPointer: d.jsonPointer,
      })),
      domSelectors: (opts.domSelectors ?? []).map((d) => ({
        name: d.name,
        selector: d.selector,
        ...(d.attribute !== undefined ? { attribute: d.attribute } : {}),
      })),
      graphqlOps: (opts.graphqlOps ?? []).map((d) => ({
        name: d.name,
        operationName: d.operationName,
      })),
      // 0.8.0+: timer + lazy-revive default to ON. Every realty MCP
      // adapter was about to set these to the same numbers anyway; the
      // back-door is `0` (explicit opt-out) if a caller genuinely wants
      // the legacy hang-forever / fail-once-on-SW-eviction behavior.
      fetchTimeoutMs: opts.fetchTimeoutMs ?? 30_000,
      bridgeReviveDelayMs: opts.bridgeReviveDelayMs ?? 2_000,
      // 0.10.0+ (#72): keep-alive defaults to 25s — round-3 #71 cohort
      // wave showed every Pattern A consumer was opting into this same
      // value. Pass `0` to disable; the existing `<= 0` guards in
      // `startKeepaliveIfIdle` / `noteActivityForKeepalive` honour that.
      //
      // #90 (P1-1): tightened to 20s. 25s left only ~5s of slack under
      // Chrome's ~30s SW-eviction window — slack that timer drift, a
      // busy host event loop (CPU-bound response parsing between calls),
      // and the ping's own round-trip latency routinely ate, so the SW
      // evicted before the next ping landed and the next call cold-
      // started. 20s restores real margin. (The extension
      // `chrome.alarms` backstop is clamped by Chrome to a 30s minimum
      // period, firing *at* the edge — it can't rescue a sub-30s race;
      // the server ping is the real defense.)
      keepAliveIntervalMs: opts.keepAliveIntervalMs ?? 20_000,
      keepAliveMaxIdleMs: opts.keepAliveMaxIdleMs ?? 5 * 60 * 1000,
      identityDir: opts.identityDir,
      onPairCode: opts.onPairCode,
    };
  }

  /**
   * Prepare the bridge for use. Loads the long-term identity keypair
   * from disk (creating it on first call) and computes this instance's
   * `mcpId`. Does NOT bind the bridge port or dial any WebSocket — the
   * connection is established lazily on the first verb call (see
   * `ensureConnected` / `getOrConnect`).
   *
   * Pre-0.5.3 behavior: `listen()` also did role election and started
   * the host/peer immediately, which meant every configured-but-unused
   * MCP claimed bridge resources at MCP-client boot. Several MCPs
   * starting in parallel under Claude Desktop also produced noisy
   * `ERR_CONNECTION_REFUSED` errors in the extension if it raced ahead
   * of the first MCP's port bind. Deferring keeps boot quiet and
   * leaves the port unowned until something actually needs it.
   *
   * Calling `listen()` twice without an intervening `close()` is a
   * no-op (the second call's identity load is idempotent).
   */
  async listen(): Promise<void> {
    if (!this.identity) {
      this.identity = await loadOrCreateIdentity(this.opts.serverName, this.opts.identityDir);
    }
    if (!this.mcpId) {
      this.mcpId = generateMcpId(this.opts.serverName, this.opts.version);
    }
  }

  /**
   * Force an eager bridge connection (role-election + host/peer handle
   * start + listener wiring) without waiting for the first verb call.
   * Useful for callers that want to surface the role / connection
   * outcome at boot, or for tests whose harness dials a mock extension
   * immediately after server construction. Production MCPs that just
   * answer tool calls should NOT call this — the lazy connect via
   * `ensureConnected` will do the right thing on first use, keeping
   * boot cheap and avoiding port-bind contention for MCPs that never
   * actually get invoked.
   *
   * Idempotent: a second call after the first has resolved is a no-op
   * (the existing handle is reused). Throws if `listen()` was never
   * called.
   */
  async connect(): Promise<void> {
    await this.ensureConnected();
  }

  /**
   * Establish the bridge connection (role-election + host/peer handle
   * start + listener wiring) the first time a verb is invoked.
   * Idempotent after the connection is up; concurrent first-callers
   * share the same in-flight promise so only one election happens.
   *
   * Throws if `listen()` was never called — the contract is that the
   * MCP author still must wire `transport.start()` at boot to load
   * identity / set mcpId, even though the WS doesn't open until a
   * verb runs.
   */
  private async ensureConnected(): Promise<void> {
    if (this.hostHandle || this.peerHandle) return;
    if (this.connectingPromise) {
      await this.connectingPromise;
      return;
    }
    if (!this.identity || !this.mcpId) {
      throw new Error(
        'FetchproxyServer: ensureConnected called before listen() — call listen() at MCP boot to load identity',
      );
    }
    this.connectingPromise = this.doConnect();
    try {
      await this.connectingPromise;
    } finally {
      // Always clear so a transient connect failure can be retried by
      // the next verb call. Successful path: the handle is now set, so
      // the next `ensureConnected` short-circuits on the first branch.
      this.connectingPromise = null;
    }
  }

  private async doConnect(): Promise<void> {
    // Identity / mcpId are guaranteed by `ensureConnected`'s precondition.
    const identity = this.identity!;
    const mcpId = this.mcpId!;
    // 0.13.0+: re-arm the host-death guard before wiring a fresh handle.
    // (A stray WS-close from a torn-down socket can fire after `close()`
    // returned; keeping `closing` latched until here means it's correctly
    // ignored, while a genuine new connection treats future closes as
    // host death.)
    this.closing = false;
    const el = await electRole({ host: this.opts.host, port: this.opts.port });
    if (el.role === 'host') {
      this.role = 'host';
      this.hostHandle = await startHost({
        httpServer: el.server,
        ownIdentity: identity,
        ownMcpId: mcpId,
        ownServerName: this.opts.serverName,
        ownVersion: this.opts.version,
        ownDomains: this.opts.domains,
        ownCapabilities: this.opts.capabilities,
        ownCookieKeys: this.opts.cookieKeys,
        ownLocalStorageKeys: this.opts.localStorageKeys,
        ownSessionStorageKeys: this.opts.sessionStorageKeys,
        ownCaptureHeaders: this.opts.captureHeaders,
        ownIndexedDbScopes: this.opts.indexedDbScopes,
        ownLocalStoragePointers: this.opts.localStoragePointers,
        ownSessionStoragePointers: this.opts.sessionStoragePointers,
        ownDomSelectors: this.opts.domSelectors,
        ownGraphqlOps: this.opts.graphqlOps,
        onPairCode: this.opts.onPairCode,
      });
      this.hostHandle.onOwnInner((inner) => this.onInner(inner));
      this.hostHandle.onExtensionDisconnect(() => {
        this.stopKeepalive();
        this.rejectAllPending();
      });
      // 0.5.2+: the extension queued us for pairing; fail in-flight tool
      // calls fast with an actionable error including the joint pair code
      // so the chat shows the same XXX-XXX the popup is displaying.
      this.hostHandle.onPendingPair((code) => {
        this.rejectAllPending(this.pairingErrorMessage(code));
      });
    } else {
      this.role = 'peer';
      this.peerHandle = await startPeer({
        host: this.opts.host,
        port: this.opts.port,
        identity,
        mcpId,
        serverName: this.opts.serverName,
        version: this.opts.version,
        domains: this.opts.domains,
        capabilities: this.opts.capabilities,
        cookieKeys: this.opts.cookieKeys,
        localStorageKeys: this.opts.localStorageKeys,
        sessionStorageKeys: this.opts.sessionStorageKeys,
        captureHeaders: this.opts.captureHeaders,
        indexedDbScopes: this.opts.indexedDbScopes,
        localStoragePointers: this.opts.localStoragePointers,
        sessionStoragePointers: this.opts.sessionStoragePointers,
        domSelectors: this.opts.domSelectors,
        graphqlOps: this.opts.graphqlOps,
      });
      this.peerHandle.onInner((inner) => this.onInner(inner));
      // Mirror the host's onExtensionDisconnect → rejectAllPending wiring.
      // The peer's analogue is "I just renegotiated my session, so any
      // in-flight requests under the old key are unreachable" — same blast
      // radius, same recovery: fail pending awaiters with a clear error.
      this.peerHandle.onRenegotiate(() => {
        this.stopKeepalive();
        this.rejectAllPending();
      });
      // 0.5.2+: pair-pending from the extension. Same actionable error
      // treatment as the host path so the chat sees the pair code instead
      // of a generic MCP-level timeout.
      this.peerHandle.onPendingPair((code) => {
        this.rejectAllPending(this.pairingErrorMessage(code));
      });
      // 0.5.2+: invoke the caller's onPairCode for the peer path too, so
      // an MCP that wants to log the code to stderr (or surface it via an
      // MCP logging notification) gets the same hook on both roles.
      if (this.opts.onPairCode) {
        const cb = this.opts.onPairCode;
        this.peerHandle.onPendingPair((code) => cb(code));
      }
      // 0.13.0+: the host process died (or otherwise dropped our upstream
      // WS). Tear down this stranded peer handle and reset role so the next
      // verb call re-elects — becoming the new host if the port is now free,
      // or a peer of whoever grabbed it. `closing` suppresses this during an
      // intentional `close()`; the `peerHandle` null-check guards against a
      // late close event from a previous socket clobbering a fresh handle.
      this.peerHandle.onClose(() => {
        if (this.closing || this.peerHandle === null) return;
        this.stopKeepalive();
        this.rejectAllPending();
        this.peerHandle = null;
        this.role = null;
      });
    }
  }

  private pairingErrorMessage(code: string): string {
    return (
      `fetchproxy transport error: pairing required for ${this.opts.serverName}. ` +
      `Tell the user to open the Transporter browser extension popup and approve the pair request. ` +
      `The pair code is: ${code} — display this code to the user so they can verify it matches.`
    );
  }

  /**
   * Raw single-shot fetch through the bridge. Most callers should prefer
   * the verb shortcuts (`get` / `post` / `getJson` / `postJson` / `getHtml`)
   * — they build the URL from a path, default sensible status checks, and
   * map non-2xx into typed errors. This entry point is here for the cases
   * where you already have a `FetchInit` ready (or need to fully control
   * `tabUrl` independently of the request URL).
   *
   * Returns a discriminated union: `{ ok: true, status, url, body }` on a
   * successful upstream HTTP response (any 2xx/3xx/4xx/5xx — the upstream
   * STATUS does not turn this into `ok: false`); `{ ok: false, error }`
   * only when the bridge itself failed (no signed-in tab, extension
   * offline, etc.).
   */
  async fetch(init: FetchInit): Promise<FetchResult | FetchResultError> {
    // 0.5.3+: connect lazily on first verb call. `listen()` only loads
    // identity now; the bridge port bind / WS dial happens here so a
    // configured-but-unused MCP doesn't tie up resources at boot.
    await this.ensureConnected();
    // 0.5.2+: if the extension has us queued for pairing, fail this call
    // immediately with the actionable pair-code error rather than sealing
    // a frame the extension can't process until the user approves.
    const pendingCode = this.currentPendingPairCode();
    if (pendingCode !== null) {
      const error = this.pairingErrorMessage(pendingCode);
      return {
        ok: false,
        error,
        kind: classifyFetchError(error),
        retryAttempted: false,
      };
    }
    const first = await this._fetchOnceWithTimeout(init);
    // 0.8.0+: lazy-revive on SW eviction. One-shot retry after the
    // configured delay; the SW typically wakes on the next inbound
    // WS frame within ~1-2s. The retry context (`retryAttempted`)
    // rides on the result envelope itself — per-call local state, no
    // shared instance slot, race-safe across concurrent calls.
    const reviveMs = this.opts.bridgeReviveDelayMs;
    // #90 (P1-1): a fully-cold worker surfaces the first post-idle call
    // EITHER as `content_script_unreachable` (the matched tab's content
    // script answered before Chrome finished evicting, then the SW died)
    // OR as a `timeout` (Chrome is still spinning the SW up and the
    // round-trip exceeds `fetchTimeoutMs`). 0.8.0 only revived the
    // former, so the timeout cold-start sailed straight to the caller —
    // the "batch timeout-then-warm-retry" / "Redfin row timing out then
    // succeeding on retry" symptom in the report. Both kinds are now the
    // eviction signal that arms the one-shot warm-and-retry.
    const isColdStartSymptom =
      !first.ok &&
      (first.kind === 'content_script_unreachable' ||
        first.kind === 'timeout');
    // 0.10.0+ (#73): stamp eviction-detection counter on the cold-start
    // symptom regardless of whether the retry path is enabled — the
    // symptom is the eviction signal, the retry is the response.
    if (isColdStartSymptom) {
      this.lastEvictionDetectedAt = Date.now();
    }
    if (isColdStartSymptom && reviveMs !== undefined && reviveMs > 0) {
      this.lazyReviveAttempts += 1;
      await new Promise((r) => setTimeout(r, reviveMs));
      const second = await this._fetchOnceWithTimeout(init);
      // Record the user-visible outcome (so one tool call only ticks
      // consecutiveFailures by 1 regardless of the internal retry).
      if (second.ok) {
        this.lazyReviveSuccesses += 1;
        this.recordSuccess();
      } else this.recordFailure(`${second.kind ?? 'other'}: ${second.error}`);
      return { ...second, retryAttempted: true };
    }
    if (first.ok) this.recordSuccess();
    else this.recordFailure(`${first.kind ?? 'other'}: ${first.error}`);
    return { ...first, retryAttempted: false };
  }

  /**
   * 0.8.0+: snapshot of the bridge's process-wide freshness counters,
   * suitable for surfacing through a downstream MCP's healthcheck tool.
   * Counters reset on a success (consecutiveFailures), accumulate
   * across the process lifetime otherwise. Replaces the per-MCP
   * duplication the realty cohort had been rolling in their adapters.
   * `lastExtensionMessageAt` is updated whenever ANY inner frame
   * arrives from the extension — gives extension-side liveness
   * distinct from server-side success/failure of the user-visible
   * call (addresses #23 ask 4).
   */
  bridgeHealth(): BridgeHealth {
    const intervalMs = this.opts.keepAliveIntervalMs;
    const maxIdleMs = this.opts.keepAliveMaxIdleMs;
    const idleSinceMs =
      this.lastActiveAt === null ? null : Date.now() - this.lastActiveAt;
    return {
      role: this.role,
      port: this.opts.port,
      serverVersion: this.opts.version,
      fetchTimeoutMs: this.opts.fetchTimeoutMs ?? 0,
      bridgeReviveDelayMs: this.opts.bridgeReviveDelayMs ?? 0,
      lastSuccessAt: this.lastSuccessAt,
      lastFailureAt: this.lastFailureAt,
      lastFailureReason: this.lastFailureReason,
      consecutiveFailures: this.consecutiveFailures,
      lastExtensionMessageAt: this.lastExtensionMessageAt,
      keepAlive: {
        enabled: intervalMs > 0,
        intervalMs,
        maxIdleMs,
        lastPingAt: this.lastPingAt,
        totalPings: this.totalPings,
        idleSinceMs,
      },
      swEviction: {
        lazyReviveAttempts: this.lazyReviveAttempts,
        lazyReviveSuccesses: this.lazyReviveSuccesses,
        lastEvictionDetectedAt: this.lastEvictionDetectedAt,
      },
    };
  }

  private recordSuccess(): void {
    this.lastSuccessAt = Date.now();
    this.consecutiveFailures = 0;
    this.noteActivityForKeepalive();
  }

  private recordFailure(reason: string): void {
    this.lastFailureAt = Date.now();
    this.lastFailureReason = reason;
    this.consecutiveFailures += 1;
    this.noteActivityForKeepalive();
  }

  /**
   * 0.8.1+ (#67): caller-side hint that work is happening or about to
   * happen — bumps the keep-alive idle gate so the server keeps pinging
   * the extension. Useful for MCPs that do a chain of side-effectful
   * work between bridge calls and don't want the SW to evict in the
   * gap (e.g. server-side parsing of a previous response that takes
   * tens of seconds). No-op when `keepAliveIntervalMs` is `0`.
   */
  markActive(): void {
    this.noteActivityForKeepalive();
  }

  private noteActivityForKeepalive(): void {
    // Match the gate `startKeepaliveIfIdle` uses (<= 0 disables) so a
    // caller passing `keepAliveIntervalMs: 0` doesn't stamp `lastActiveAt`
    // for a feature that will never fire.
    const intervalMs = this.opts.keepAliveIntervalMs;
    if (intervalMs <= 0) return;
    this.lastActiveAt = Date.now();
    this.startKeepaliveIfIdle();
  }

  private startKeepaliveIfIdle(): void {
    if (this.keepAliveTimer !== null) return;
    const intervalMs = this.opts.keepAliveIntervalMs;
    if (intervalMs <= 0) return;
    this.keepAliveTimer = setInterval(() => {
      const now = Date.now();
      if (
        this.lastActiveAt === null ||
        now - this.lastActiveAt > this.opts.keepAliveMaxIdleMs
      ) {
        this.stopKeepalive();
        return;
      }
      // 0.10.0+ (#73): observability counters for downstream healthcheck
      // tools. Stamped before the actual send so a transient send error
      // doesn't lose the tick — `totalPings` reflects ticks the gate
      // permitted, `lastPingAt` reflects when the most-recent attempt
      // happened.
      this.totalPings += 1;
      this.lastPingAt = now;
      // Fire-and-forget; the extension answers with `pong` which we
      // ignore (the `onInner` handler already drops pong frames).
      // Swallow errors — a transient bridge hiccup shouldn't crash the
      // host process via an unhandled rejection.
      void this.sendKeepalivePing();
    }, intervalMs);
  }

  private async sendKeepalivePing(): Promise<void> {
    try {
      const inner: InnerFrame = { type: 'ping' };
      if (this.hostHandle) {
        await this.hostHandle.sendOwnInner(inner);
      } else if (this.peerHandle) {
        await this.peerHandle.sendInner(inner);
      }
    } catch (e) {
      // Best-effort — keepalive is opportunistic. Use stderr (console.error)
      // not stdout — MCPs speak JSON-RPC over stdio; any stray stdout byte
      // corrupts the protocol stream. Mirrors host.ts's logging convention.
      // eslint-disable-next-line no-console
      console.error('[fetchproxy] keepalive ping send failed:', e);
    }
  }

  private stopKeepalive(): void {
    if (this.keepAliveTimer !== null) {
      clearInterval(this.keepAliveTimer);
      this.keepAliveTimer = null;
    }
  }

  /**
   * Send an inner request frame via whichever bridge handle is active. If the
   * send throws (e.g. `FetchproxySessionNotReadyError` — the session never
   * confirmed), the frame never reached the bridge, so no reply will arrive:
   * drop the just-registered pending resolver for this id (it lives in exactly
   * one of the op maps — request ids are unique) so it doesn't leak until the
   * server closes, then rethrow.
   */
  private async sendInnerFrame(inner: InnerFrame): Promise<void> {
    try {
      if (this.hostHandle) {
        await this.hostHandle.sendOwnInner(inner);
      } else if (this.peerHandle) {
        await this.peerHandle.sendInner(inner);
      }
    } catch (err) {
      if ('id' in inner && typeof inner.id === 'number') {
        const { id } = inner;
        this.pending.delete(id);
        this.pendingReadCookies.delete(id);
        this.pendingStorage.delete(id);
        this.pendingCapture.delete(id);
        this.pendingRedirect.delete(id);
        this.pendingDownload.delete(id);
        this.pendingIdb.delete(id);
        this.pendingGraphql.delete(id);
      }
      throw err;
    }
  }

  /**
   * Single bridge round-trip, wrapped by `fetchTimeoutMs` when set.
   * On timeout returns the `{ok:false, kind:'timeout'}` envelope —
   * the throwing surface is the convenience methods.
   */
  private async _fetchOnceWithTimeout(
    init: FetchInit,
  ): Promise<FetchResult | FetchResultError> {
    const id = this.nextRequestId++;
    const inner: InnerFrame = { type: 'request', id, op: 'fetch', init };
    const pending = new Promise<FetchResult | FetchResultError>((resolve) => {
      this.pending.set(id, resolve);
    });
    await this.sendInnerFrame(inner);
    const timeoutMs = this.opts.fetchTimeoutMs;
    if (timeoutMs === undefined || timeoutMs <= 0) return pending;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const start = Date.now();
    try {
      return await Promise.race([
        pending,
        new Promise<FetchResultError>((resolve) => {
          timer = setTimeout(() => {
            // Drop the pending resolver so a late bridge response doesn't
            // become an unhandled promise that crashes the host.
            this.pending.delete(id);
            const elapsedMs = Date.now() - start;
            const error = `fetchproxy: ${init.url} did not respond within ${timeoutMs}ms`;
            // retryAttempted is overwritten by the caller (fetch())
            // when it wraps with `...result, retryAttempted: x`. We
            // emit `false` here as the inner default since the timeout
            // never triggers the SW-eviction retry path.
            resolve({
              ok: false,
              error,
              kind: 'timeout',
              retryAttempted: false,
              elapsedMs,
            });
          }, timeoutMs);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * FP-B2: bound a non-`fetch` verb's reply wait by `fetchTimeoutMs`.
   *
   * Before this, only `fetch()` raced its `pending` reply against a timer
   * (`_fetchOnceWithTimeout`); `readCookies`, the storage reads,
   * `capture_request_header`, `capture_redirect`, `download`, and
   * `read_indexed_db` awaited their `pending` promise with no race, so a
   * wedged extension hung the tool call indefinitely.
   *
   * `pending` is the already-registered reply promise. `pendingMap`/`id`
   * point at the op-specific map entry so we can drop it on expiry exactly
   * as `_fetchOnceWithTimeout` does — otherwise a late bridge reply would
   * resolve into a stale resolver / leak. On timeout we reject with a
   * `FetchproxyTimeoutError` (the same throwable the convenience methods
   * already surface for fetch timeouts). `0`/unset opts out (unbounded),
   * matching the fetch path.
   */
  private async _withVerbTimeout<T>(
    pending: Promise<T>,
    pendingMap: Map<number, unknown>,
    id: number,
    url: string,
  ): Promise<T> {
    const timeoutMs = this.opts.fetchTimeoutMs;
    if (timeoutMs === undefined || timeoutMs <= 0) return pending;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const start = Date.now();
    try {
      return await Promise.race([
        pending,
        new Promise<T>((_resolve, reject) => {
          timer = setTimeout(() => {
            // Drop the pending resolver so a late bridge response doesn't
            // become an unhandled promise that crashes the host.
            pendingMap.delete(id);
            reject(
              new FetchproxyTimeoutError({
                url,
                timeoutMs,
                role: this.role,
                port: this.opts.port,
                elapsedMs: Date.now() - start,
                retryAttempted: false,
              }),
            );
          }, timeoutMs);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * Map an `ok:false` fetch result to its typed throwable. Centralizes
   * the kind-to-error-class switch so `request()` and (via the same
   * logic re-implemented inline) `captureRequestHeader()` agree on what
   * to throw.
   */
  private _typedErrorFor(
    result: FetchResultError,
    url: string,
    op: 'fetch' | 'capture_request_header',
    retryAttempted: boolean,
  ): Error {
    if (result.kind === 'timeout') {
      return new FetchproxyTimeoutError({
        url,
        timeoutMs: this.opts.fetchTimeoutMs ?? 0,
        role: this.role,
        port: this.opts.port,
        elapsedMs: result.elapsedMs,
        retryAttempted,
      });
    }
    if (result.kind === 'content_script_unreachable') {
      return new FetchproxyBridgeDownError({
        originalError: result.error,
        retryAttempted,
        op,
        url,
        role: this.role,
        port: this.opts.port,
      });
    }
    return new FetchproxyProtocolError(result.error);
  }

  /**
   * Convenience wrapper around `fetch()`. Builds the URL from a path
   * + optional subdomain + optional domain selector, throws on
   * protocol errors, optionally asserts on the response status.
   *
   * Path resolution:
   *  - Absolute URL (`https://...`) → used as-is (still guarded against
   *    leaving the declared domain set).
   *  - Relative path → joined with `https://${subdomain}.${baseDomain}`
   *    (or `https://${baseDomain}` if no subdomain is given).
   *
   * Base-domain selection:
   *  - Single-domain MCP (`domains: ['x.com']`): `opts.domain` is optional;
   *    `domains[0]` is used by default.
   *  - Multi-domain MCP: `opts.domain` is required and must equal one of
   *    the declared domains exactly.
   */
  async request(
    method: string,
    path: string,
    opts: RequestOpts = {},
  ): Promise<HttpResponse> {
    if (opts.subdomain !== undefined) assertSubdomainLabel(opts.subdomain);
    const baseDomain = this.resolveBaseDomain(opts.domain);
    const isAbsolute =
      path.startsWith('http://') || path.startsWith('https://');
    // 0.8.0+: when `path` is absolute, derive `tabUrl` from the URL's
    // own host — `opts.subdomain` applies only to relative paths
    // (where it acts as the default for building `https://{sub}.{base}`).
    // Before this, absolute paths inherited the subdomain's tabUrl and
    // the cohort had to conditionally spread `subdomain` based on the
    // path shape to avoid routing photos.x.com requests through a
    // www.x.com tab. Now they just always pass `subdomain` and the
    // server picks the right tabUrl per call.
    let host: string;
    if (isAbsolute) {
      try {
        host = new URL(path).host;
      } catch {
        throw new Error(
          `FetchproxyServer.request: absolute path is not a valid URL: ${JSON.stringify(path)}`,
        );
      }
    } else {
      host = opts.subdomain ? `${opts.subdomain}.${baseDomain}` : baseDomain;
    }
    const url = isAbsolute ? path : `https://${host}${path}`;
    // Guard: refuse to send any request whose resolved URL leaves the
    // declared domain set. The extension would refuse it anyway; this
    // gives the MCP author a clear error at the call site instead of a
    // generic "domain not allowed" from the bridge.
    assertUrlInDomains('request url', url, this.opts.domains);
    const init: FetchInit = {
      url,
      method,
      tabUrl: `https://${host}/`,
      headers: opts.headers,
      body: opts.body,
    };
    const result = await this.fetch(init);
    if (!result.ok) {
      // retryAttempted rides on the envelope — per-call local context,
      // so it's race-safe across concurrent calls. Test subclasses
      // overriding fetch() may not set the field; default to `false`
      // (the field is declared optional for that reason).
      throw this._typedErrorFor(
        result,
        init.url,
        'fetch',
        result.retryAttempted ?? false,
      );
    }
    const response: HttpResponse = {
      status: result.status,
      body: result.body,
      url: result.url,
    };
    if (opts.expectStatus !== undefined) {
      const expected = opts.expectStatus;
      const matched = Array.isArray(expected)
        ? expected.includes(response.status)
        : response.status === expected;
      if (!matched) {
        throw new FetchproxyHttpError(response);
      }
    }
    return response;
  }

  /** Issue a GET against `path` (resolved via `request()` rules). */
  get(path: string, opts: BodylessRequestOpts = {}): Promise<HttpResponse> {
    return this.request('GET', path, opts);
  }

  /** Issue a POST with optional string body. */
  post(
    path: string,
    body?: string,
    opts: BodylessRequestOpts = {},
  ): Promise<HttpResponse> {
    return this.request('POST', path, { ...opts, body });
  }

  /** Issue a PUT with optional string body. */
  put(
    path: string,
    body?: string,
    opts: BodylessRequestOpts = {},
  ): Promise<HttpResponse> {
    return this.request('PUT', path, { ...opts, body });
  }

  /** Issue a PATCH with optional string body. */
  patch(
    path: string,
    body?: string,
    opts: BodylessRequestOpts = {},
  ): Promise<HttpResponse> {
    return this.request('PATCH', path, { ...opts, body });
  }

  /** Issue a DELETE. No body — bridge does not support DELETE-with-body. */
  delete(path: string, opts: BodylessRequestOpts = {}): Promise<HttpResponse> {
    return this.request('DELETE', path, opts);
  }

  /**
   * GET a path and parse the response body as JSON. Throws
   * `FetchproxyHttpError` if the status is outside the default 2xx
   * happy-path set (`[200, 201, 202, 204]`); pass a custom
   * `expectStatus` to override.
   */
  async getJson<T = unknown>(
    path: string,
    opts: BodylessRequestOpts = {},
  ): Promise<T> {
    const response = await this.get(path, this.applyJsonDefaults(opts));
    return JSON.parse(response.body) as T;
  }

  /**
   * POST a JSON body and parse the response body as JSON. The body is
   * `JSON.stringify`'d; `Content-Type: application/json` is set unless
   * the caller already provided one. Defaults `expectStatus` to the 2xx
   * happy-path set.
   */
  async postJson<T = unknown>(
    path: string,
    body?: unknown,
    opts: BodylessRequestOpts = {},
  ): Promise<T> {
    const headers = { ...(opts.headers ?? {}) };
    if (body !== undefined && !this.hasContentType(headers)) {
      headers['Content-Type'] = 'application/json';
    }
    const response = await this.request('POST', path, {
      ...this.applyJsonDefaults(opts),
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return JSON.parse(response.body) as T;
  }

  /**
   * GET a path and return the response body as a string. Throws
   * `FetchproxyHttpError` if the status is outside the default 2xx
   * happy-path set.
   */
  async getHtml(
    path: string,
    opts: BodylessRequestOpts = {},
  ): Promise<string> {
    const response = await this.get(path, this.applyJsonDefaults(opts));
    return response.body;
  }

  /**
   * 0.11.0+: method-generic JSON convenience helper. Generalizes the
   * `fetchJson<T>(path, { method, headers, body })` that
   * zillow/redfin/compass/homes hand-rolled char-for-char in their
   * `src/client.ts`:
   *
   *  - sets `Accept: application/json`;
   *  - adds `Content-Type: application/json` only for a non-GET request
   *    that carries a `body` (and only if the caller didn't set one);
   *  - `JSON.stringify`s the body (GET / no-body sends nothing);
   *  - treats a `204` or an empty body as `data: null` (no parse);
   *  - otherwise `JSON.parse`s the body.
   *
   * Scope is serialization + header defaults + 204-handling +
   * JSON.parse ONLY. It deliberately does NOT assert on the HTTP status
   * or look for a sign-in interstitial — those guards differ per site
   * (Zillow's `captcha-delivery`, Redfin's AWS-WAF challenge, …), so it
   * returns BOTH the parsed `data` and the raw `FetchResult` and leaves
   * the consumer to run its own `throwIfNotOk` / `throwIfSignInPage`
   * over `result`.
   *
   * Bridge-level failures (no signed-in tab, SW down, timeout) still
   * throw the typed errors via `request()`, exactly like the verb
   * helpers — only successful round-trips (any HTTP status) return.
   */
  async requestJson<T = unknown>(
    method: string,
    path: string,
    opts: {
      subdomain?: string;
      domain?: string;
      headers?: Record<string, string>;
      body?: unknown;
    } = {},
  ): Promise<{ data: T | null; result: FetchResult }> {
    const isGet = method.toUpperCase() === 'GET';
    const sendBody = !isGet && opts.body !== undefined;
    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...(sendBody && !this.hasContentType(opts.headers ?? {})
        ? { 'Content-Type': 'application/json' }
        : {}),
      ...(opts.headers ?? {}),
    };
    const response = await this.request(method, path, {
      headers,
      body: sendBody ? JSON.stringify(opts.body) : undefined,
      ...(opts.subdomain !== undefined ? { subdomain: opts.subdomain } : {}),
      ...(opts.domain !== undefined ? { domain: opts.domain } : {}),
    });
    // Re-expose the success-arm FetchResult so callers keep their
    // per-site guards. `request()` already threw on any bridge failure,
    // so reaching here means a delivered HTTP response (`ok: true`).
    const result: FetchResult = {
      ok: true,
      status: response.status,
      url: response.url,
      body: response.body,
    };
    if (response.status === 204 || response.body === '') {
      return { data: null, result };
    }
    let data: T;
    try {
      data = JSON.parse(response.body) as T;
    } catch (e) {
      throw new Error(
        `fetchproxy ${method} ${path} — response was not JSON: ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    }
    return { data, result };
  }

  /**
   * 0.11.0+: run a single healthcheck probe through `fetchFn`, measure
   * the elapsed round-trip, classify any thrown error, and project the
   * post-probe `bridgeHealth()` into a snake-cased `bridge` sub-object.
   *
   * This is the transport half of the probe loop zillow/redfin/homes
   * had duplicated verbatim in `src/tools/healthcheck.ts`. The MCP
   * supplies its own probe call (`(path) => client.fetchHtml(path)`)
   * and probe path (e.g. `'/robots.txt'`); the tool registration and
   * the site-specific plain-English hint text STAY in the consumer.
   *
   * `bridgeHealth()` is read AFTER the probe so its freshness counters
   * (`lastSuccessAt` / `consecutiveFailures` / …) reflect this very
   * round-trip rather than a stale pre-probe snapshot.
   */
  async runProbe(
    fetchFn: (path: string) => Promise<unknown>,
    probePath: string,
  ): Promise<BridgeProbeResult> {
    const start = Date.now();
    let ok = false;
    let error: BridgeProbeResult['error'];
    try {
      await fetchFn(probePath);
      ok = true;
    } catch (e) {
      error = {
        kind: classifyBridgeError(e),
        message: e instanceof Error ? e.message : String(e),
      };
    }
    const elapsed_ms = Date.now() - start;
    // Read after the probe so the freshness counters include this call.
    const health = this.bridgeHealth();
    return {
      ok,
      elapsed_ms,
      bridge: {
        role: health.role,
        port: health.port,
        server_version: health.serverVersion,
        fetch_timeout_ms: health.fetchTimeoutMs,
        last_success_at: health.lastSuccessAt,
        last_failure_at: health.lastFailureAt,
        last_failure_reason: health.lastFailureReason,
        consecutive_failures: health.consecutiveFailures,
      },
      ...(error ? { error } : {}),
    };
  }

  /**
   * Snapshot the user's non-HttpOnly cookies for the chosen domain.
   *
   * Requires `'read_cookies'` in `FetchproxyServerOpts.capabilities`.
   * Throws a developer-facing `Error` at the call site if the MCP did
   * not declare the capability — this is a programming mistake, not a
   * runtime condition.
   *
   * The returned string is the raw `document.cookie` value (semicolon-
   * separated `k=v` pairs). HttpOnly cookies are NOT visible to page JS
   * and are therefore not included; the underlying threat model assumes
   * the cookies that matter for the auth bootstrap (session tokens, csrf
   * cookies that the page itself reads) are non-HttpOnly.
   *
   * Throws `FetchproxyProtocolError` if the bridge could not deliver
   * the request (no signed-in tab, extension offline, etc.).
   */
  async readCookies(
    opts: { domain?: string; subdomain?: string; keys?: string[] } = {},
  ): Promise<string> {
    if (!this.opts.capabilities.includes('read_cookies')) {
      throw new Error(
        'FetchproxyServer.readCookies(): MCP did not declare "read_cookies" in capabilities — add it to FetchproxyServerOpts.capabilities to enable this verb',
      );
    }
    // 0.5.3+: lazy connect — see the doc comment on `ensureConnected`.
    await this.ensureConnected();
    this.throwIfPendingPair();
    if (opts.subdomain !== undefined) assertSubdomainLabel(opts.subdomain);
    const baseDomain = this.resolveBaseDomain(opts.domain);
    const host = opts.subdomain ? `${opts.subdomain}.${baseDomain}` : baseDomain;
    const id = this.nextRequestId++;
    let inner: InnerFrame;
    if (opts.keys !== undefined) {
      // 0.3.0 shape: origin + keys → values. Enforce keys ⊆ declared
      // cookieKeys at the call site (gate #1). Extension re-checks on
      // its end (gate #2).
      this.assertScopeSubset(opts.keys, this.opts.cookieKeys, 'cookieKeys');
      const initV3: ReadCookiesInitV3 = {
        origin: `https://${host}`,
        keys: [...opts.keys],
      };
      inner = { type: 'request', id, op: 'read_cookies', init: initV3 };
    } else {
      // Legacy 0.2.0 shape — kept for back-compat with callers that
      // don't pass `keys`. The extension routes this through the
      // document.cookie path (non-HttpOnly only).
      const tabUrl = `https://${host}/`;
      inner = { type: 'request', id, op: 'read_cookies', init: { tabUrl } };
    }
    const pending = new Promise<ReadCookiesResult | ReadCookiesResultError>((resolve) => {
      this.pendingReadCookies.set(id, resolve);
    });
    await this.sendInnerFrame(inner);
    const result = await this._withVerbTimeout(
      pending,
      this.pendingReadCookies,
      id,
      `https://${host}`,
    );
    if (!result.ok) {
      throw new FetchproxyProtocolError(result.error);
    }
    return result.cookies;
  }

  /**
   * 0.3.0+: read declared localStorage keys from the user's signed-in
   * tab. Requires `'read_local_storage'` in capabilities AND each key
   * to be in declared `localStorageKeys`. Returns a `Record<string, string>`
   * including only keys that exist in storage.
   *
   * 0.4.0+: optional `pointers` map. Each entry `{ outputKey: { storageKey, jsonPointer } }`
   * extracts a node from the JSON-parsed value at `storageKey`. The
   * `(storageKey, jsonPointer)` pair must match a declared
   * `localStoragePointers` entry on the server hello.
   */
  async readLocalStorage(opts: {
    domain?: string;
    subdomain?: string;
    keys: string[];
    pointers?: Record<string, { storageKey: string; jsonPointer: string }>;
  }): Promise<Record<string, string>> {
    return this.readStorageImpl(
      'read_local_storage',
      this.opts.localStorageKeys,
      this.opts.localStoragePointers,
      opts,
      'localStorageKeys',
      'localStoragePointers',
    );
  }

  /**
   * 0.3.0+: read declared sessionStorage keys. Identical shape to
   * `readLocalStorage` but against sessionStorage.
   */
  async readSessionStorage(opts: {
    domain?: string;
    subdomain?: string;
    keys: string[];
    pointers?: Record<string, { storageKey: string; jsonPointer: string }>;
  }): Promise<Record<string, string>> {
    return this.readStorageImpl(
      'read_session_storage',
      this.opts.sessionStorageKeys,
      this.opts.sessionStoragePointers,
      opts,
      'sessionStorageKeys',
      'sessionStoragePointers',
    );
  }

  private async readStorageImpl(
    op: 'read_local_storage' | 'read_session_storage',
    declaredKeys: string[],
    declaredPointers: StoragePointerDecl[],
    opts: {
      domain?: string;
      subdomain?: string;
      keys: string[];
      pointers?: Record<string, { storageKey: string; jsonPointer: string }>;
    },
    declLabel: string,
    pointersDeclLabel: string,
  ): Promise<Record<string, string>> {
    if (!this.opts.capabilities.includes(op)) {
      throw new Error(
        `FetchproxyServer.${op === 'read_local_storage' ? 'readLocalStorage' : 'readSessionStorage'}(): MCP did not declare ${JSON.stringify(op)} in capabilities`,
      );
    }
    // 0.5.3+: lazy connect — see the doc comment on `ensureConnected`.
    await this.ensureConnected();
    this.throwIfPendingPair();
    if (!Array.isArray(opts.keys) || opts.keys.length === 0) {
      throw new Error(`FetchproxyServer.${op}: opts.keys must be a non-empty array`);
    }
    this.assertScopeSubset(opts.keys, declaredKeys, declLabel);
    if (opts.pointers) {
      for (const [outputKey, p] of Object.entries(opts.pointers)) {
        const match = declaredPointers.find(
          (d) => d.key === p.storageKey && d.jsonPointer === p.jsonPointer,
        );
        if (!match) {
          throw new Error(
            `FetchproxyServer.${op}: pointer (${JSON.stringify(p.storageKey)}, ${JSON.stringify(p.jsonPointer)}) for outputKey=${JSON.stringify(outputKey)} not in declared ${pointersDeclLabel}`,
          );
        }
        if (!opts.keys.includes(p.storageKey)) {
          throw new Error(
            `FetchproxyServer.${op}: pointer storageKey ${JSON.stringify(p.storageKey)} not in opts.keys`,
          );
        }
      }
    }
    if (opts.subdomain !== undefined) assertSubdomainLabel(opts.subdomain);
    const baseDomain = this.resolveBaseDomain(opts.domain);
    const host = opts.subdomain ? `${opts.subdomain}.${baseDomain}` : baseDomain;
    const id = this.nextRequestId++;
    const inner: InnerFrame = {
      type: 'request',
      id,
      op,
      init: {
        origin: `https://${host}`,
        keys: [...opts.keys],
        ...(opts.pointers ? { pointers: { ...opts.pointers } } : {}),
      },
    };
    const pending = new Promise<Record<string, string>>((resolve, reject) => {
      this.pendingStorage.set(id, { resolve, reject });
    });
    await this.sendInnerFrame(inner);
    return this._withVerbTimeout(pending, this.pendingStorage, id, `https://${host}`);
  }

  /**
   * 0.3.0+: snapshot the next outgoing request's named header. Single-
   * shot: the extension registers a one-time `webRequest` listener
   * filtered on `https://${host}${path ?? '/*'}`, captures the named
   * header on the first match, removes itself, and resolves with the
   * value. Times out after `timeoutMs` (default 30s on the extension).
   *
   * `(host, path?, headerName)` must match a declared entry in
   * `FetchproxyServerOpts.captureHeaders` (omitted path ≡ `/*`).
   */
  async captureRequestHeader(opts?: {
    host?: string;
    path?: string;
    headerName?: string;
    timeoutMs?: number;
  }): Promise<string> {
    if (!this.opts.capabilities.includes('capture_request_header')) {
      throw new Error(
        'FetchproxyServer.captureRequestHeader(): MCP did not declare "capture_request_header" in capabilities',
      );
    }
    // 0.5.3+: lazy connect — see the doc comment on `ensureConnected`.
    await this.ensureConnected();
    this.throwIfPendingPair();
    // 0.8.0+: resolve to the declared entry. If the caller supplied
    // both host + headerName, require a declared match (omitted path ≡
    // `/*`). If neither is supplied, default to the sole declared
    // entry; throw if 0 or >1 are declared so the ambiguity surfaces at
    // the call site, not silently as the wrong capture. Supplying only
    // one of the pair is rejected — it would otherwise silently pair
    // against a different declared entry.
    const decls = this.opts.captureHeaders;
    const normPath = (p: string | undefined): string => p ?? '/*';
    let resolved: CaptureHeaderDecl;
    if (opts?.host !== undefined && opts?.headerName !== undefined) {
      const found = decls.find(
        (d) =>
          d.host === opts.host &&
          normPath(d.path) === normPath(opts.path) &&
          d.headerName === opts.headerName,
      );
      if (!found) {
        throw new Error(
          `FetchproxyServer.captureRequestHeader: (host=${JSON.stringify(opts.host)}, path=${JSON.stringify(normPath(opts.path))}, headerName=${JSON.stringify(opts.headerName)}) not declared in captureHeaders`,
        );
      }
      resolved = found;
    } else if (opts?.host === undefined && opts?.headerName === undefined) {
      if (decls.length === 0) {
        throw new Error(
          'FetchproxyServer.captureRequestHeader: no captureHeaders declared on this server — declare at least one entry in FetchproxyServerOpts.captureHeaders, or pass {host, headerName} explicitly',
        );
      }
      if (decls.length > 1) {
        const list = decls
          .map((d) => `${JSON.stringify(d.host)}${JSON.stringify(normPath(d.path))}/${JSON.stringify(d.headerName)}`)
          .join(', ');
        throw new Error(
          `FetchproxyServer.captureRequestHeader: multiple captureHeaders declared (${decls.length}: ${list}); pass {host, headerName} to disambiguate`,
        );
      }
      resolved = decls[0]!;
    } else {
      throw new Error(
        'FetchproxyServer.captureRequestHeader: pass both host AND headerName, or neither (which defaults to the single declared entry)',
      );
    }
    const callOpts = { ...resolved, ...(opts?.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}) };
    try {
      const result = await this._captureRequestHeaderOnce(callOpts);
      this.recordSuccess();
      return result;
    } catch (err) {
      const swDown =
        err instanceof FetchproxyProtocolError &&
        classifyFetchError(err.message) === 'content_script_unreachable';
      if (!swDown) {
        this.recordFailure(
          `capture_request_header: ${(err as Error).message ?? String(err)}`,
        );
        throw err;
      }
      // 0.10.0+ (#73): mirror fetch()'s eviction-detection stamp — the
      // SW-eviction symptom counter ticks regardless of the retry knob.
      this.lastEvictionDetectedAt = Date.now();
      const reviveMs = this.opts.bridgeReviveDelayMs ?? 0;
      // 0.8.0+: lazy-revive — give Chrome a moment to wake the SW.
      if (reviveMs > 0) {
        this.lazyReviveAttempts += 1;
        await new Promise((r) => setTimeout(r, reviveMs));
        try {
          const result = await this._captureRequestHeaderOnce(callOpts);
          this.lazyReviveSuccesses += 1;
          this.recordSuccess();
          return result;
        } catch (retryErr) {
          const stillDown =
            retryErr instanceof FetchproxyProtocolError &&
            classifyFetchError(retryErr.message) === 'content_script_unreachable';
          if (!stillDown) {
            this.recordFailure(
              `capture_request_header: ${(retryErr as Error).message ?? String(retryErr)}`,
            );
            throw retryErr;
          }
          this.recordFailure(
            `capture_request_header bridge-down: ${(retryErr as Error).message}`,
          );
          throw new FetchproxyBridgeDownError({
            originalError: (retryErr as Error).message,
            retryAttempted: true,
            op: 'capture_request_header',
            url: `https://${resolved.host}${resolved.path ?? '/*'}`,
            role: this.role,
            port: this.opts.port,
          });
        }
      }
      this.recordFailure(
        `capture_request_header bridge-down: ${(err as Error).message}`,
      );
      throw new FetchproxyBridgeDownError({
        originalError: (err as Error).message,
        retryAttempted: false,
        op: 'capture_request_header',
        url: `https://${resolved.host}${resolved.path ?? '/*'}`,
        role: this.role,
        port: this.opts.port,
      });
    }
  }

  private async _captureRequestHeaderOnce(opts: {
    host: string;
    path?: string;
    headerName: string;
    timeoutMs?: number;
  }): Promise<string> {
    const id = this.nextRequestId++;
    const inner: InnerFrame = {
      type: 'request',
      id,
      op: 'capture_request_header',
      init: {
        host: opts.host,
        ...(opts.path !== undefined ? { path: opts.path } : {}),
        headerName: opts.headerName,
        ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
      },
    };
    const pending = new Promise<string>((resolve, reject) => {
      this.pendingCapture.set(id, { resolve, reject });
    });
    await this.sendInnerFrame(inner);
    return this._withVerbTimeout(
      pending,
      this.pendingCapture,
      id,
      `https://${opts.host}${opts.path ?? '/*'}`,
    );
  }

  /**
   * Snapshot the redirect target URL of the next request the browser
   * makes to `(host, path?)`. Single-shot: the extension registers a
   * one-time `chrome.webRequest.onBeforeRedirect` listener filtered on
   * `https://${host}${path ?? '/*'}`, captures `details.redirectUrl` on
   * the first match, removes itself, and resolves with the URL. Times out
   * after `timeoutMs` (default 30s on the extension).
   *
   * Use case: a Cloudflare-walled endpoint that 302-redirects cross-origin
   * to a presigned URL — a page-level fetch sees only an opaque redirect,
   * but `onBeforeRedirect` exposes the target. Capture is limited to the
   * MCP's own declared `domains`; no per-entry declared scope is required.
   */
  async captureRedirect(opts: {
    host: string;
    path?: string;
    timeoutMs?: number;
  }): Promise<string> {
    if (!this.opts.capabilities.includes('capture_redirect')) {
      throw new Error(
        'FetchproxyServer.captureRedirect(): MCP did not declare "capture_redirect" in capabilities',
      );
    }
    // 0.5.3+: lazy connect — see the doc comment on `ensureConnected`.
    await this.ensureConnected();
    this.throwIfPendingPair();
    try {
      const result = await this._captureRedirectOnce(opts);
      this.recordSuccess();
      return result;
    } catch (err) {
      const swDown =
        err instanceof FetchproxyProtocolError &&
        classifyFetchError(err.message) === 'content_script_unreachable';
      if (!swDown) {
        this.recordFailure(`capture_redirect: ${(err as Error).message ?? String(err)}`);
        throw err;
      }
      // 0.10.0+ (#73): mirror fetch()'s eviction-detection stamp.
      this.lastEvictionDetectedAt = Date.now();
      const reviveMs = this.opts.bridgeReviveDelayMs ?? 0;
      if (reviveMs > 0) {
        this.lazyReviveAttempts += 1;
        await new Promise((r) => setTimeout(r, reviveMs));
        try {
          const result = await this._captureRedirectOnce(opts);
          this.lazyReviveSuccesses += 1;
          this.recordSuccess();
          return result;
        } catch (retryErr) {
          const stillDown =
            retryErr instanceof FetchproxyProtocolError &&
            classifyFetchError(retryErr.message) === 'content_script_unreachable';
          if (!stillDown) {
            this.recordFailure(
              `capture_redirect: ${(retryErr as Error).message ?? String(retryErr)}`,
            );
            throw retryErr;
          }
          this.recordFailure(`capture_redirect bridge-down: ${(retryErr as Error).message}`);
          throw new FetchproxyBridgeDownError({
            originalError: (retryErr as Error).message,
            retryAttempted: true,
            op: 'capture_redirect',
            url: `https://${opts.host}${opts.path ?? '/*'}`,
            role: this.role,
            port: this.opts.port,
          });
        }
      }
      this.recordFailure(`capture_redirect bridge-down: ${(err as Error).message}`);
      throw new FetchproxyBridgeDownError({
        originalError: (err as Error).message,
        retryAttempted: false,
        op: 'capture_redirect',
        url: `https://${opts.host}${opts.path ?? '/*'}`,
        role: this.role,
        port: this.opts.port,
      });
    }
  }

  private async _captureRedirectOnce(opts: {
    host: string;
    path?: string;
    timeoutMs?: number;
  }): Promise<string> {
    const id = this.nextRequestId++;
    const inner: InnerFrame = {
      type: 'request',
      id,
      op: 'capture_redirect',
      init: {
        host: opts.host,
        ...(opts.path !== undefined ? { path: opts.path } : {}),
        ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
      },
    };
    const pending = new Promise<string>((resolve, reject) => {
      this.pendingRedirect.set(id, { resolve, reject });
    });
    await this.sendInnerFrame(inner);
    return this._withVerbTimeout(
      pending,
      this.pendingRedirect,
      id,
      `https://${opts.host}${opts.path ?? '/*'}`,
    );
  }

  /**
   * Download `url` through the BROWSER's own network stack via
   * `chrome.downloads` (real cookies + TLS/JA3 fingerprint). Unlike a
   * page-level `fetch()` (cors mode), this clears a Cloudflare bot-challenge
   * on the endpoint and follows the cross-origin redirect to the final file.
   * Resolves the saved local file path + size; the bridge is loopback-only /
   * single-host, so the MCP reads the bytes from the same disk. Requires
   * `'download'` in capabilities and the `url` host to be a declared `domain`.
   */
  async download(opts: {
    url: string;
    filename?: string;
    timeoutMs?: number;
  }): Promise<DownloadResult> {
    if (!this.opts.capabilities.includes('download')) {
      throw new Error(
        'FetchproxyServer.download(): MCP did not declare "download" in capabilities',
      );
    }
    // Fail fast on an out-of-domain URL (mirrors request()) — a clean local
    // error rather than a full bridge round-trip that the extension rejects.
    assertUrlInDomains('download url', opts.url, this.opts.domains);
    await this.ensureConnected();
    this.throwIfPendingPair();
    try {
      const result = await this._downloadOnce(opts);
      this.recordSuccess();
      return result;
    } catch (err) {
      const swDown =
        err instanceof FetchproxyProtocolError &&
        classifyFetchError(err.message) === 'content_script_unreachable';
      if (!swDown) {
        this.recordFailure(`download: ${(err as Error).message ?? String(err)}`);
        throw err;
      }
      // Mirror fetch()/capture_redirect's lazy-revive on SW eviction.
      this.lastEvictionDetectedAt = Date.now();
      const reviveMs = this.opts.bridgeReviveDelayMs ?? 0;
      if (reviveMs > 0) {
        this.lazyReviveAttempts += 1;
        await new Promise((r) => setTimeout(r, reviveMs));
        try {
          const result = await this._downloadOnce(opts);
          this.lazyReviveSuccesses += 1;
          this.recordSuccess();
          return result;
        } catch (retryErr) {
          const stillDown =
            retryErr instanceof FetchproxyProtocolError &&
            classifyFetchError(retryErr.message) === 'content_script_unreachable';
          if (!stillDown) {
            this.recordFailure(`download: ${(retryErr as Error).message ?? String(retryErr)}`);
            throw retryErr;
          }
          this.recordFailure(`download bridge-down: ${(retryErr as Error).message}`);
          throw new FetchproxyBridgeDownError({
            originalError: (retryErr as Error).message,
            retryAttempted: true,
            op: 'download',
            url: opts.url,
            role: this.role,
            port: this.opts.port,
          });
        }
      }
      this.recordFailure(`download bridge-down: ${(err as Error).message}`);
      throw new FetchproxyBridgeDownError({
        originalError: (err as Error).message,
        retryAttempted: false,
        op: 'download',
        url: opts.url,
        role: this.role,
        port: this.opts.port,
      });
    }
  }

  private async _downloadOnce(opts: {
    url: string;
    filename?: string;
    timeoutMs?: number;
  }): Promise<DownloadResult> {
    const id = this.nextRequestId++;
    const inner: InnerFrame = {
      type: 'request',
      id,
      op: 'download',
      init: {
        url: opts.url,
        ...(opts.filename !== undefined ? { filename: opts.filename } : {}),
        ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
      },
    };
    const pending = new Promise<DownloadResult>((resolve, reject) => {
      this.pendingDownload.set(id, { resolve, reject });
    });
    await this.sendInnerFrame(inner);
    return this._withVerbTimeout(pending, this.pendingDownload, id, opts.url);
  }

  /**
   * 0.4.0+: read declared IndexedDB keys from the user's signed-in
   * tab. Requires `'read_indexed_db'` in capabilities AND the
   * `(database, store, keys)` triple to subset-match a declared
   * `indexedDbScopes` entry on the same origin.
   *
   * Returns a `Record<string, unknown>` of the JSON-typed values, with
   * missing keys omitted. Throws `FetchproxyProtocolError` on bridge
   * failures (no tab, extension offline, etc.) and a plain `Error`
   * on developer mistakes (undeclared capability, undeclared scope).
   */
  async readIndexedDb(opts: {
    domain?: string;
    subdomain?: string;
    database: string;
    store: string;
    keys: string[];
  }): Promise<Record<string, unknown>> {
    if (!this.opts.capabilities.includes('read_indexed_db')) {
      throw new Error(
        'FetchproxyServer.readIndexedDb(): MCP did not declare "read_indexed_db" in capabilities',
      );
    }
    // 0.5.3+: lazy connect — see the doc comment on `ensureConnected`.
    await this.ensureConnected();
    this.throwIfPendingPair();
    if (!Array.isArray(opts.keys) || opts.keys.length === 0) {
      throw new Error('FetchproxyServer.readIndexedDb: opts.keys must be a non-empty array');
    }
    if (opts.subdomain !== undefined) assertSubdomainLabel(opts.subdomain);
    const baseDomain = this.resolveBaseDomain(opts.domain);
    const host = opts.subdomain ? `${opts.subdomain}.${baseDomain}` : baseDomain;
    const origin = `https://${host}`;
    // Find the matching declared scope. Must be exact on (origin,
    // database, store); keys must be a subset.
    const decl = this.opts.indexedDbScopes.find(
      (d) => d.origin === origin && d.database === opts.database && d.store === opts.store,
    );
    if (!decl) {
      throw new Error(
        `FetchproxyServer.readIndexedDb: (origin=${origin}, database=${JSON.stringify(opts.database)}, store=${JSON.stringify(opts.store)}) not declared in indexedDbScopes`,
      );
    }
    this.assertScopeSubset(opts.keys, decl.keys, 'indexedDbScopes.keys');
    const id = this.nextRequestId++;
    const inner: InnerFrame = {
      type: 'request',
      id,
      op: 'read_indexed_db',
      init: {
        origin,
        database: opts.database,
        store: opts.store,
        keys: [...opts.keys],
      },
    };
    const pending = new Promise<Record<string, unknown>>((resolve, reject) => {
      this.pendingIdb.set(id, { resolve, reject });
    });
    await this.sendInnerFrame(inner);
    return this._withVerbTimeout(pending, this.pendingIdb, id, origin);
  }

  /**
   * 1.4.0+: read declared DOM values from the user's signed-in tab.
   * Requires `'read_dom'` in capabilities AND every requested `name` to
   * match a declared `domSelectors` entry. The extension reads each
   * declared selector from the matched tab's DOM (isolated-world
   * `querySelector`, value or attribute) — no page-JS execution.
   *
   * Returns a `Record<string, string>` of `name → value`, with names
   * whose element (or attribute) was absent omitted. Throws
   * `FetchproxyProtocolError` on bridge failures and a plain `Error` on
   * developer mistakes (undeclared capability, undeclared name).
   */
  async readDom(opts: {
    domain?: string;
    subdomain?: string;
    names: string[];
  }): Promise<Record<string, string>> {
    if (!this.opts.capabilities.includes('read_dom')) {
      throw new Error(
        'FetchproxyServer.readDom(): MCP did not declare "read_dom" in capabilities',
      );
    }
    await this.ensureConnected();
    this.throwIfPendingPair();
    if (!Array.isArray(opts.names) || opts.names.length === 0) {
      throw new Error('FetchproxyServer.readDom: opts.names must be a non-empty array');
    }
    this.assertScopeSubset(
      opts.names,
      this.opts.domSelectors.map((d) => d.name),
      'domSelectors',
    );
    if (opts.subdomain !== undefined) assertSubdomainLabel(opts.subdomain);
    const baseDomain = this.resolveBaseDomain(opts.domain);
    const host = opts.subdomain ? `${opts.subdomain}.${baseDomain}` : baseDomain;
    const origin = `https://${host}`;
    const id = this.nextRequestId++;
    const inner: InnerFrame = {
      type: 'request',
      id,
      op: 'read_dom',
      init: { origin, names: [...opts.names] },
    };
    const pending = new Promise<Record<string, string>>((resolve, reject) => {
      this.pendingStorage.set(id, { resolve, reject });
    });
    await this.sendInnerFrame(inner);
    return this._withVerbTimeout(pending, this.pendingStorage, id, origin);
  }

  /**
   * 1.x+: run a declared GraphQL operation through the page's own Apollo
   * client (`window.__APOLLO_CLIENT__`) in the signed-in tab's MAIN world.
   * Requires `'graphql'` in capabilities AND `name` to match a declared
   * `graphqlOps` entry. The extension resolves `name` → `operationName` →
   * the live DocumentNode the page already observed, then invokes
   * `client.query({ query, variables })` — the site's own request path, so
   * per-request bot telemetry (Akamai etc.) runs automatically.
   *
   * Returns the GraphQL `data` object on success (shape is
   * operation-specific; the caller narrows). Throws a plain `Error` on
   * developer mistakes (undeclared capability, undeclared name) and a
   * descriptive `Error` on the `ok:false` bridge path — which includes the
   * typed "operation not yet observed on this tab" case (open the site's
   * page and retry).
   */
  async graphqlQuery(opts: {
    name: string;
    variables: Record<string, unknown>;
    tabUrl?: string;
  }): Promise<unknown> {
    if (!this.opts.capabilities.includes('graphql')) {
      throw new Error(
        'FetchproxyServer.graphqlQuery(): MCP did not declare "graphql" in capabilities',
      );
    }
    if (typeof opts.name !== 'string' || opts.name.length === 0) {
      throw new Error('FetchproxyServer.graphqlQuery: opts.name must be a non-empty string');
    }
    const declaredNames = this.opts.graphqlOps.map((d) => d.name);
    if (!declaredNames.includes(opts.name)) {
      throw new Error(
        `FetchproxyServer.graphqlQuery: operation ${JSON.stringify(opts.name)} not in declared graphqlOps [${declaredNames
          .map((n) => JSON.stringify(n))
          .join(', ')}]`,
      );
    }
    await this.ensureConnected();
    this.throwIfPendingPair();
    const id = this.nextRequestId++;
    const inner: InnerFrame = {
      type: 'request',
      id,
      op: 'graphql_query',
      init: {
        name: opts.name,
        variables: opts.variables,
        ...(opts.tabUrl !== undefined ? { tabUrl: opts.tabUrl } : {}),
      },
    };
    const pending = new Promise<unknown>((resolve, reject) => {
      this.pendingGraphql.set(id, { resolve, reject });
    });
    await this.sendInnerFrame(inner);
    return this._withVerbTimeout(pending, this.pendingGraphql, id, opts.name);
  }

  private assertScopeSubset(
    requested: readonly string[],
    declared: readonly string[],
    label: string,
  ): void {
    // 0.4.0: declared array may contain trailing-* glob patterns
    // (e.g. `feh--*`). `undeclaredKeys` handles literal + glob match
    // uniformly so the call-site error message is the same shape.
    const undeclared = undeclaredKeys(requested, declared);
    if (undeclared.length > 0) {
      throw new Error(
        `FetchproxyServer: requested key(s) [${undeclared
          .map((k) => JSON.stringify(k))
          .join(', ')}] not in declared ${label} [${declared.map((k) => JSON.stringify(k)).join(', ')}]`,
      );
    }
  }

  private resolveBaseDomain(domain: string | undefined): string {
    if (domain !== undefined) {
      if (!this.opts.domains.includes(domain)) {
        const declared = this.opts.domains.map((d) => JSON.stringify(d)).join(', ');
        throw new Error(
          `FetchproxyServer: opts.domain ${JSON.stringify(domain)} is not in the declared domains [${declared}]`,
        );
      }
      return domain;
    }
    if (this.opts.domains.length === 1) {
      // Safe: length-checked above. Non-null assertion is required because
      // noUncheckedIndexedAccess types this as `string | undefined`.
      return this.opts.domains[0]!;
    }
    const declared = this.opts.domains.map((d) => JSON.stringify(d)).join(', ');
    throw new Error(
      `FetchproxyServer: this MCP declared multiple domains [${declared}] — pass { domain: '<one of them>' } on every per-call request`,
    );
  }

  private applyJsonDefaults(opts: BodylessRequestOpts): BodylessRequestOpts {
    if (Object.prototype.hasOwnProperty.call(opts, 'expectStatus')) return opts;
    return { ...opts, expectStatus: [...DEFAULT_JSON_OK_STATUSES] };
  }

  private hasContentType(headers: Record<string, string>): boolean {
    for (const key of Object.keys(headers)) {
      if (key.toLowerCase() === 'content-type') return true;
    }
    return false;
  }

  private onInner(inner: InnerFrame): void {
    if (inner.type !== 'response') return;
    // 0.8.0+ (#23 ask 4): every response frame counts as extension
    // liveness, regardless of which awaiter it routes to.
    this.lastExtensionMessageAt = Date.now();
    // Inner request ids are unique across both pending maps. Look up the
    // right one by the id rather than by op: an error response (`ok: false`)
    // for a read_cookies request may carry no op echo, and we still need
    // to wake the right awaiter.
    const fetchCb = this.pending.get(inner.id);
    if (fetchCb) {
      this.pending.delete(inner.id);
      if (inner.ok) {
        // Either a fetch response (with status/url/body) or, in theory, a
        // read_cookies one — but read_cookies ids are in the other map, so
        // anything that lands here is a fetch.
        // The id-routed pending maps own dispatch, so anything that lands
        // here is supposed to be a fetch response. Defensively reject any
        // non-fetch op echo so a wire-misroute can't smuggle a storage /
        // capture payload into a fetch awaiter.
        if (inner.op === undefined || inner.op === 'fetch') {
          fetchCb({
            ok: true,
            status: inner.status,
            url: inner.url,
            body: inner.body,
            retryAttempted: false,
          });
        } else {
          const error = `unexpected ${inner.op} response on fetch awaiter`;
          fetchCb({
            ok: false,
            error,
            kind: classifyFetchError(error),
            retryAttempted: false,
          });
        }
      } else {
        fetchCb({
          ok: false,
          error: inner.error,
          kind: classifyFetchError(inner.error),
          retryAttempted: false,
        });
      }
      return;
    }
    const storageCb = this.pendingStorage.get(inner.id);
    if (storageCb) {
      this.pendingStorage.delete(inner.id);
      if (inner.ok) {
        if (
          (inner.op === 'read_local_storage' ||
            inner.op === 'read_session_storage' ||
            inner.op === 'read_dom') &&
          inner.values
        ) {
          storageCb.resolve({ ...inner.values });
        } else {
          storageCb.reject(
            new FetchproxyProtocolError(
              `unexpected ${String(inner.op)} response on storage awaiter`,
            ),
          );
        }
      } else {
        storageCb.reject(new FetchproxyProtocolError(inner.error));
      }
      return;
    }
    const captureCb = this.pendingCapture.get(inner.id);
    if (captureCb) {
      this.pendingCapture.delete(inner.id);
      if (inner.ok) {
        if (inner.op === 'capture_request_header' && typeof inner.value === 'string') {
          captureCb.resolve(inner.value);
        } else {
          captureCb.reject(
            new FetchproxyProtocolError(
              `unexpected ${String(inner.op)} response on capture awaiter`,
            ),
          );
        }
      } else {
        captureCb.reject(new FetchproxyProtocolError(inner.error));
      }
      return;
    }
    const redirectCb = this.pendingRedirect.get(inner.id);
    if (redirectCb) {
      this.pendingRedirect.delete(inner.id);
      if (inner.ok) {
        if (inner.op === 'capture_redirect' && typeof inner.value === 'string') {
          redirectCb.resolve(inner.value);
        } else {
          redirectCb.reject(
            new FetchproxyProtocolError(
              `unexpected ${String(inner.op)} response on capture_redirect awaiter`,
            ),
          );
        }
      } else {
        redirectCb.reject(new FetchproxyProtocolError(inner.error));
      }
      return;
    }
    const idbCb = this.pendingIdb.get(inner.id);
    if (idbCb) {
      this.pendingIdb.delete(inner.id);
      if (inner.ok) {
        if (inner.op === 'read_indexed_db' && inner.values) {
          idbCb.resolve({ ...inner.values });
        } else {
          idbCb.reject(
            new FetchproxyProtocolError(
              `unexpected ${String(inner.op)} response on read_indexed_db awaiter`,
            ),
          );
        }
      } else {
        idbCb.reject(new FetchproxyProtocolError(inner.error));
      }
      return;
    }
    const downloadCb = this.pendingDownload.get(inner.id);
    if (downloadCb) {
      this.pendingDownload.delete(inner.id);
      if (inner.ok) {
        if (inner.op === 'download' && inner.value && typeof inner.value === 'object') {
          downloadCb.resolve({ ...inner.value });
        } else {
          downloadCb.reject(
            new FetchproxyProtocolError(
              `unexpected ${String(inner.op)} response on download awaiter`,
            ),
          );
        }
      } else {
        downloadCb.reject(new FetchproxyProtocolError(inner.error));
      }
      return;
    }
    const graphqlCb = this.pendingGraphql.get(inner.id);
    if (graphqlCb) {
      this.pendingGraphql.delete(inner.id);
      if (inner.ok) {
        if (inner.op === 'graphql_query') {
          graphqlCb.resolve(inner.data);
        } else {
          graphqlCb.reject(
            new FetchproxyProtocolError(
              `unexpected ${String(inner.op)} response on graphql_query awaiter`,
            ),
          );
        }
      } else {
        graphqlCb.reject(new FetchproxyProtocolError(inner.error));
      }
      return;
    }
    const cookiesCb = this.pendingReadCookies.get(inner.id);
    if (cookiesCb) {
      this.pendingReadCookies.delete(inner.id);
      if (inner.ok) {
        if (inner.op === 'read_cookies') {
          // Two response shapes accepted: legacy `cookies: string` (0.2.0
          // extension) and new `values: Record<string,string>` (0.3.0+).
          // Normalize to a string so the public `readCookies(): Promise<string>`
          // surface stays back-compat.
          if (typeof inner.cookies === 'string') {
            cookiesCb({ ok: true, cookies: inner.cookies });
          } else if (inner.values) {
            const joined = Object.entries(inner.values)
              .map(([k, v]) => `${k}=${v}`)
              .join('; ');
            cookiesCb({ ok: true, cookies: joined });
          } else {
            cookiesCb({ ok: false, error: 'read_cookies response carried neither cookies nor values' });
          }
        } else {
          cookiesCb({ ok: false, error: 'unexpected fetch response on read_cookies awaiter' });
        }
      } else {
        cookiesCb({ ok: false, error: inner.error });
      }
    }
  }

  private rejectAllPending(reason: string = 'extension disconnected'): void {
    const err = new FetchproxyProtocolError(reason);
    for (const cb of this.pending.values()) {
      cb({
        ok: false,
        error: err.message,
        kind: classifyFetchError(err.message),
        retryAttempted: false,
      });
    }
    this.pending.clear();
    for (const cb of this.pendingReadCookies.values()) {
      cb({ ok: false, error: err.message });
    }
    this.pendingReadCookies.clear();
    for (const { reject } of this.pendingStorage.values()) reject(err);
    this.pendingStorage.clear();
    for (const { reject } of this.pendingCapture.values()) reject(err);
    this.pendingCapture.clear();
    for (const { reject } of this.pendingRedirect.values()) reject(err);
    this.pendingRedirect.clear();
    for (const { reject } of this.pendingIdb.values()) reject(err);
    this.pendingIdb.clear();
    for (const { reject } of this.pendingDownload.values()) reject(err);
    this.pendingDownload.clear();
    for (const { reject } of this.pendingGraphql.values()) reject(err);
    this.pendingGraphql.clear();
  }

  /**
   * 0.5.2+: read the current pair-pending pair code from whichever handle
   * is active, returning null when none is pending. Public verbs call this
   * at the top so that a tool invoked while the bridge is waiting on user
   * approval fails fast with the actionable error rather than hanging on a
   * sealed frame the extension will never process.
   */
  private currentPendingPairCode(): string | null {
    if (this.hostHandle) return this.hostHandle.pendingPairCode();
    if (this.peerHandle) return this.peerHandle.pendingPairCode();
    return null;
  }

  /**
   * 0.5.2+: throw `FetchproxyProtocolError` with the actionable pair-code
   * message if the bridge is waiting on user approval. Used by the verb
   * methods (readCookies, readLocalStorage, etc.) that surface errors via
   * thrown exceptions rather than `ok:false` discriminated unions.
   */
  private throwIfPendingPair(): void {
    const code = this.currentPendingPairCode();
    if (code !== null) {
      throw new FetchproxyProtocolError(this.pairingErrorMessage(code));
    }
  }

  /**
   * Shut down the bridge. Host: terminates the WebSocket server and any
   * still-attached extension/peer clients. Peer: closes the upstream
   * connection to the host. Safe to call before `listen()` (no-op) or
   * twice in a row.
   */
  async close(): Promise<void> {
    // 0.13.0+: latch the host-death guard so the peer's WS close (which
    // fires asynchronously, possibly after this method returns) is treated
    // as an intentional shutdown, not a host dying. Re-armed by doConnect().
    this.closing = true;
    this.stopKeepalive();
    this.rejectAllPending();
    // 0.5.3+: if a verb call has triggered `doConnect()` but the handle
    // hasn't been written yet, wait it out before we tear things down.
    // Otherwise `close()` would observe `hostHandle == null`, return
    // without calling its `.close()`, and `doConnect()` would then
    // write `this.hostHandle = <live handle>` after we'd already
    // returned — leaking the socket. Swallow the rejection: if the
    // election itself failed, there's nothing to tear down.
    if (this.connectingPromise) {
      await this.connectingPromise.catch(() => undefined);
    }
    if (this.hostHandle) await this.hostHandle.close();
    if (this.peerHandle) this.peerHandle.close();
    this.hostHandle = null;
    this.peerHandle = null;
    this.role = null;
    // Match the `finally` in `ensureConnected` so a subsequent
    // `listen()` + `connect()` after `close()` doesn't observe a stale
    // promise reference.
    this.connectingPromise = null;
  }
}
