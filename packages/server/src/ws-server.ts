import { generateMcpId, KNOWN_CAPABILITIES, undeclaredKeys } from '@fetchproxy/protocol';
import type {
  Capability,
  CaptureHeaderDecl,
  IndexedDbScopeDecl,
  StoragePointerDecl,
  InnerFrame,
  FetchInit,
  ReadCookiesInitV3,
} from '@fetchproxy/protocol';
import { electRole } from './election.js';
import { startHost, type HostHandle } from './host.js';
import { startPeer, type PeerHandle } from './peer.js';
import { loadOrCreateIdentity, type Identity } from './identity.js';
import { classifyFetchError, type FetchErrorKind } from './error-kind.js';

export interface FetchproxyServerOpts {
  port?: number;
  host?: string;
  serverName: string;
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
  /** 0.3.0+: declared (urlPattern, headerName) pairs for `captureRequestHeader`. */
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
  identityDir?: string;
  /**
   * 0.4.0+: invoked once on receipt of the extension hello, with the
   * joint pair code derived from `SHA256(mcpPub || extPub)`. Used by
   * MCPs that need to surface the code on stderr or similar for the
   * user to verify against the browser popup. Optional — fetch-only
   * MCPs that don't need to print can omit it.
   */
  onPairCode?: (code: string) => void;
  /**
   * 0.8.0+: per-request timeout (ms) for `fetch()`. The bridge has
   * no native timeout, so without this a frozen tab / dropped
   * extension would hang the call indefinitely. When the timer fires,
   * `fetch()` returns `{ ok: false, kind: 'timeout', error: '…' }`
   * (back-compat result shape); convenience methods (`get`/`post`/
   * `request` etc.) throw `FetchproxyTimeoutError`. **Default 30000**
   * — pre-0.8.0 callers got no timer; the typical realty/dining MCPs
   * were already wrapping their own at this same value. Pass `0` to
   * opt back into the legacy hang-forever behavior.
   */
  fetchTimeoutMs?: number;
  /**
   * 0.8.0+: delay (ms) before the one-shot retry when `fetch()` or
   * `captureRequestHeader()` fail with `content_script_unreachable`.
   * Chrome MV3 evicts extension service workers after ~30s idle;
   * this gives Chrome a moment to wake the SW on the next inbound
   * frame. **Default 2000** — same value the zillow/onehome cohort
   * had been hand-rolling in their transport adapters. On retry-
   * exhaustion, convenience methods + capture throw
   * `FetchproxyBridgeDownError` with `retryAttempted: true`. Pass `0`
   * to disable the retry entirely (errors surface on the first
   * attempt with `retryAttempted: false`).
   */
  bridgeReviveDelayMs?: number;
}

export interface FetchResult {
  ok: true;
  status: number;
  url: string;
  body: string;
  /**
   * 0.8.0+: true when the server's lazy-revive retry path actually
   * fired for this call (a `content_script_unreachable` first attempt
   * followed by a successful retry). False on the no-retry path.
   * Always populated by the server in 0.8.0+; declared optional in the
   * type so downstream test code that constructs envelope literals
   * directly stays back-compat without code changes.
   */
  retryAttempted?: boolean;
}

export interface FetchResultError {
  ok: false;
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
   * disabled, or this isn't a `content_script_unreachable` failure
   * so retry didn't apply). Always populated by the server in 0.8.0+;
   * declared optional in the type so downstream test code that
   * constructs envelope literals directly stays back-compat.
   */
  retryAttempted?: boolean;
}

/** Public response shape returned by the convenience helpers. */
export interface HttpResponse {
  status: number;
  body: string;
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
  headers?: Record<string, string>;
  body?: string;
  /**
   * If provided, throws `FetchproxyHttpError` when the response status
   * does not match. A number is matched exactly; an array means "must be in this set".
   */
  expectStatus?: number | number[];
  /**
   * Optional subdomain label(s) to prepend to the chosen base domain.
   * E.g. with base `'opentable.com'`, `subdomain: 'www'` builds the
   * URL against `https://www.opentable.com`. May be a single label
   * (`'www'`) or dot-separated labels (`'auth.api'`).
   */
  subdomain?: string;
  /**
   * Optional base domain selector for multi-domain MCPs. Must match one
   * of the entries in `FetchproxyServerOpts.domains` exactly. Required
   * on every per-call request when the MCP declared multiple domains;
   * may be omitted when only one domain is declared.
   */
  domain?: string;
}

/** Options accepted by JSON/HTML shortcuts (no `body` — provided positionally). */
export interface BodylessRequestOpts {
  headers?: Record<string, string>;
  expectStatus?: number | number[];
  subdomain?: string;
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
  readonly op: 'fetch' | 'capture_request_header';
  readonly url?: string;
  readonly hint: string;

  constructor(args: {
    originalError: string;
    retryAttempted?: boolean;
    op?: 'fetch' | 'capture_request_header';
    url?: string;
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
      `Wake it by clicking the fetchproxy extension toolbar icon, then ` +
      `retry. If it keeps happening, reload the extension from ` +
      `chrome://extensions.`;
    super(
      `fetchproxy bridge down during ${op}${args.url ? ` (${args.url})` : ''}. ${hint}`,
    );
    this.name = 'FetchproxyBridgeDownError';
    this.originalError = args.originalError;
    this.retryAttempted = retryAttempted;
    this.op = op;
    if (args.url !== undefined) this.url = args.url;
    this.hint = hint;
  }
}

/**
 * 0.8.0+: thrown by convenience methods when `fetchTimeoutMs` fires.
 * The lower-level `fetch()` returns `{ ok: false, kind: 'timeout' }`
 * instead (back-compat with its result-envelope shape). Subclass of
 * `FetchproxyProtocolError` so existing callers still match.
 */
export class FetchproxyTimeoutError extends FetchproxyProtocolError {
  readonly url: string;
  readonly timeoutMs: number;

  constructor(args: { url: string; timeoutMs: number }) {
    super(
      `fetchproxy: ${args.url} did not respond within ${args.timeoutMs}ms`,
    );
    this.name = 'FetchproxyTimeoutError';
    this.url = args.url;
    this.timeoutMs = args.timeoutMs;
  }
}

/**
 * 0.8.0+: snapshot of the bridge's process-wide freshness counters,
 * returned by `FetchproxyServer.bridgeHealth()`. Downstream MCPs use
 * this to power their `healthcheck` tools without re-tracking the
 * same counters in their transport adapters.
 */
export interface BridgeHealth {
  role: 'host' | 'peer' | null;
  port: number;
  lastSuccessAt: number | null;
  lastFailureAt: number | null;
  lastFailureReason: string | null;
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
  fetchTimeoutMs?: number;
  bridgeReviveDelayMs?: number;
  identityDir?: string;
  onPairCode?: (code: string) => void;
}

const DEFAULT_JSON_OK_STATUSES: readonly number[] = [200, 201, 202, 204];

/** Result of a successful `read_cookies` call. */
export interface ReadCookiesResult {
  ok: true;
  cookies: string;
}

/** Result of a failed `read_cookies` call (transport / capability / no-tab). */
export interface ReadCookiesResultError {
  ok: false;
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
  // 0.4.0+: read_indexed_db awaiters resolve a JSON-typed values map.
  private pendingIdb = new Map<
    number,
    { resolve: (v: Record<string, unknown>) => void; reject: (e: Error) => void }
  >();
  private mcpId: string | null = null;
  private identity: Identity | null = null;
  // 0.5.3+: in-flight role-election / handle-start promise. Set the
  // first time a verb call runs `ensureConnected`, awaited by concurrent
  // callers, cleared once the connection is up. Single source of truth
  // for "we're connecting right now" so two parallel first-calls don't
  // race the port bind.
  private connectingPromise: Promise<void> | null = null;

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
        urlPattern: d.urlPattern,
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
      // 0.8.0+: timer + lazy-revive default to ON. Every realty MCP
      // adapter was about to set these to the same numbers anyway; the
      // back-door is `0` (explicit opt-out) if a caller genuinely wants
      // the legacy hang-forever / fail-once-on-SW-eviction behavior.
      fetchTimeoutMs: opts.fetchTimeoutMs ?? 30_000,
      bridgeReviveDelayMs: opts.bridgeReviveDelayMs ?? 2_000,
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
        onPairCode: this.opts.onPairCode,
      });
      this.hostHandle.onOwnInner((inner) => this.onInner(inner));
      this.hostHandle.onExtensionDisconnect(() => this.rejectAllPending());
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
      });
      this.peerHandle.onInner((inner) => this.onInner(inner));
      // Mirror the host's onExtensionDisconnect → rejectAllPending wiring.
      // The peer's analogue is "I just renegotiated my session, so any
      // in-flight requests under the old key are unreachable" — same blast
      // radius, same recovery: fail pending awaiters with a clear error.
      this.peerHandle.onRenegotiate(() => this.rejectAllPending());
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
    let final = first;
    if (
      !first.ok &&
      first.kind === 'content_script_unreachable' &&
      reviveMs !== undefined &&
      reviveMs > 0
    ) {
      await new Promise((r) => setTimeout(r, reviveMs));
      const second = await this._fetchOnceWithTimeout(init);
      // Record the user-visible outcome (so one tool call only ticks
      // consecutiveFailures by 1 regardless of the internal retry).
      if (second.ok) this.recordSuccess();
      else this.recordFailure(`${second.kind ?? 'other'}: ${second.error}`);
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
    return {
      role: this.role,
      port: this.opts.port,
      lastSuccessAt: this.lastSuccessAt,
      lastFailureAt: this.lastFailureAt,
      lastFailureReason: this.lastFailureReason,
      consecutiveFailures: this.consecutiveFailures,
      lastExtensionMessageAt: this.lastExtensionMessageAt,
    };
  }

  private recordSuccess(): void {
    this.lastSuccessAt = Date.now();
    this.consecutiveFailures = 0;
  }

  private recordFailure(reason: string): void {
    this.lastFailureAt = Date.now();
    this.lastFailureReason = reason;
    this.consecutiveFailures += 1;
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
    if (this.hostHandle) {
      await this.hostHandle.sendOwnInner(inner);
    } else if (this.peerHandle) {
      await this.peerHandle.sendInner(inner);
    }
    const timeoutMs = this.opts.fetchTimeoutMs;
    if (timeoutMs === undefined || timeoutMs <= 0) return pending;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        pending,
        new Promise<FetchResultError>((resolve) => {
          timer = setTimeout(() => {
            // Drop the pending resolver so a late bridge response doesn't
            // become an unhandled promise that crashes the host.
            this.pending.delete(id);
            const error = `fetchproxy: ${init.url} did not respond within ${timeoutMs}ms`;
            // retryAttempted is overwritten by the caller (fetch())
            // when it wraps with `...result, retryAttempted: x`. We
            // emit `false` here as the inner default since the timeout
            // never triggers the SW-eviction retry path.
            resolve({ ok: false, error, kind: 'timeout', retryAttempted: false });
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
      });
    }
    if (result.kind === 'content_script_unreachable') {
      return new FetchproxyBridgeDownError({
        originalError: result.error,
        retryAttempted,
        op,
        url,
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
    const host = opts.subdomain
      ? `${opts.subdomain}.${baseDomain}`
      : baseDomain;
    const url =
      path.startsWith('http://') || path.startsWith('https://')
        ? path
        : `https://${host}${path}`;
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
    if (this.hostHandle) {
      await this.hostHandle.sendOwnInner(inner);
    } else if (this.peerHandle) {
      await this.peerHandle.sendInner(inner);
    }
    const result = await pending;
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
    if (this.hostHandle) {
      await this.hostHandle.sendOwnInner(inner);
    } else if (this.peerHandle) {
      await this.peerHandle.sendInner(inner);
    }
    return pending;
  }

  /**
   * 0.3.0+: snapshot the next outgoing request's named header. Single-
   * shot: the extension registers a one-time `webRequest` listener
   * filtered on `urlPattern`, captures the named header on the first
   * match, removes itself, and resolves with the value. Times out
   * after `timeoutMs` (default 30s on the extension).
   *
   * `(urlPattern, headerName)` must exactly match a declared entry in
   * `FetchproxyServerOpts.captureHeaders`.
   */
  async captureRequestHeader(opts?: {
    urlPattern?: string;
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
    // both urlPattern + headerName, require an exact declared match
    // (the historical behavior). If neither is supplied, default to
    // the sole declared entry; throw if 0 or >1 are declared so the
    // ambiguity surfaces at the call site, not silently as the wrong
    // capture. Supplying only one of the pair is rejected — it would
    // otherwise silently pair against a different declared entry.
    const decls = this.opts.captureHeaders;
    let resolved: CaptureHeaderDecl;
    if (opts?.urlPattern !== undefined && opts?.headerName !== undefined) {
      const found = decls.find(
        (d) => d.urlPattern === opts.urlPattern && d.headerName === opts.headerName,
      );
      if (!found) {
        throw new Error(
          `FetchproxyServer.captureRequestHeader: (urlPattern=${JSON.stringify(opts.urlPattern)}, headerName=${JSON.stringify(opts.headerName)}) not declared in captureHeaders`,
        );
      }
      resolved = found;
    } else if (opts?.urlPattern === undefined && opts?.headerName === undefined) {
      if (decls.length === 0) {
        throw new Error(
          'FetchproxyServer.captureRequestHeader: no captureHeaders declared on this server — declare at least one entry in FetchproxyServerOpts.captureHeaders, or pass {urlPattern, headerName} explicitly',
        );
      }
      if (decls.length > 1) {
        const list = decls
          .map((d) => `${JSON.stringify(d.urlPattern)}/${JSON.stringify(d.headerName)}`)
          .join(', ');
        throw new Error(
          `FetchproxyServer.captureRequestHeader: multiple captureHeaders declared (${decls.length}: ${list}); pass {urlPattern, headerName} to disambiguate`,
        );
      }
      resolved = decls[0]!;
    } else {
      throw new Error(
        'FetchproxyServer.captureRequestHeader: pass both urlPattern AND headerName, or neither (which defaults to the single declared entry)',
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
      const reviveMs = this.opts.bridgeReviveDelayMs ?? 0;
      // 0.8.0+: lazy-revive — give Chrome a moment to wake the SW.
      if (reviveMs > 0) {
        await new Promise((r) => setTimeout(r, reviveMs));
        try {
          const result = await this._captureRequestHeaderOnce(callOpts);
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
            url: resolved.urlPattern,
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
        url: resolved.urlPattern,
      });
    }
  }

  private async _captureRequestHeaderOnce(opts: {
    urlPattern: string;
    headerName: string;
    timeoutMs?: number;
  }): Promise<string> {
    const id = this.nextRequestId++;
    const inner: InnerFrame = {
      type: 'request',
      id,
      op: 'capture_request_header',
      init: {
        urlPattern: opts.urlPattern,
        headerName: opts.headerName,
        ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
      },
    };
    const pending = new Promise<string>((resolve, reject) => {
      this.pendingCapture.set(id, { resolve, reject });
    });
    if (this.hostHandle) {
      await this.hostHandle.sendOwnInner(inner);
    } else if (this.peerHandle) {
      await this.peerHandle.sendInner(inner);
    }
    return pending;
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
    if (this.hostHandle) {
      await this.hostHandle.sendOwnInner(inner);
    } else if (this.peerHandle) {
      await this.peerHandle.sendInner(inner);
    }
    return pending;
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
          (inner.op === 'read_local_storage' || inner.op === 'read_session_storage') &&
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
    for (const { reject } of this.pendingIdb.values()) reject(err);
    this.pendingIdb.clear();
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
