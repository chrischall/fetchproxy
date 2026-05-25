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
}

export interface FetchResult {
  ok: true;
  status: number;
  url: string;
  body: string;
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
 * On `listen()`, the server races the configured port: if it binds,
 * the instance becomes the concentrator (role `'host'`) the extension
 * dials. If the port is already taken by another fetchproxy host, the
 * instance becomes a peer (role `'peer'`) and tunnels through that
 * host's existing WebSocket. Either way, callers issue `fetch()` (or
 * one of the verb shortcuts) and get the response from the user's
 * signed-in browser tab as if they'd run `window.fetch` there
 * themselves.
 *
 * Behavior is identical between host and peer roles — `role` is
 * surfaced mostly for testability and metrics. Callers should not
 * branch on it.
 */
export class FetchproxyServer {
  /** Set after `listen()` succeeds. Null while not listening. */
  public role: 'host' | 'peer' | null = null;

  private opts: ResolvedOpts;
  private hostHandle: HostHandle | null = null;
  private peerHandle: PeerHandle | null = null;
  private nextRequestId = 1;
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
      identityDir: opts.identityDir,
      onPairCode: opts.onPairCode,
    };
  }

  /**
   * Start the WebSocket bridge. Loads the long-term identity keypair
   * from disk (creating it on first call), elects the host-vs-peer
   * role by attempting to bind the configured port, and stands up the
   * matching handshake machinery. Idempotent only insofar as it leaves
   * `role` non-null on success; calling `listen()` twice without an
   * intervening `close()` is a programming error.
   */
  async listen(): Promise<void> {
    this.identity = await loadOrCreateIdentity(this.opts.serverName, this.opts.identityDir);
    this.mcpId = generateMcpId(this.opts.serverName, this.opts.version);
    const el = await electRole({ host: this.opts.host, port: this.opts.port });
    if (el.role === 'host') {
      this.role = 'host';
      this.hostHandle = await startHost({
        httpServer: el.server,
        ownIdentity: this.identity,
        ownMcpId: this.mcpId,
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
    } else {
      this.role = 'peer';
      this.peerHandle = await startPeer({
        host: this.opts.host,
        port: this.opts.port,
        identity: this.identity,
        mcpId: this.mcpId,
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
    }
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
    if (!this.hostHandle && !this.peerHandle) {
      throw new Error('FetchproxyServer.fetch called before listen() — not listening');
    }
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
    return pending;
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
      throw new FetchproxyProtocolError(result.error);
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
    if (!this.hostHandle && !this.peerHandle) {
      throw new Error('FetchproxyServer.readCookies called before listen() — not listening');
    }
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
    if (!this.hostHandle && !this.peerHandle) {
      throw new Error(`FetchproxyServer.${op} called before listen() — not listening`);
    }
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
  async captureRequestHeader(opts: {
    urlPattern: string;
    headerName: string;
    timeoutMs?: number;
  }): Promise<string> {
    if (!this.opts.capabilities.includes('capture_request_header')) {
      throw new Error(
        'FetchproxyServer.captureRequestHeader(): MCP did not declare "capture_request_header" in capabilities',
      );
    }
    if (!this.hostHandle && !this.peerHandle) {
      throw new Error('FetchproxyServer.captureRequestHeader called before listen() — not listening');
    }
    const declared = this.opts.captureHeaders.find(
      (d) => d.urlPattern === opts.urlPattern && d.headerName === opts.headerName,
    );
    if (!declared) {
      throw new Error(
        `FetchproxyServer.captureRequestHeader: (urlPattern=${JSON.stringify(opts.urlPattern)}, headerName=${JSON.stringify(opts.headerName)}) not declared in captureHeaders`,
      );
    }
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
    if (!this.hostHandle && !this.peerHandle) {
      throw new Error('FetchproxyServer.readIndexedDb called before listen() — not listening');
    }
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
          fetchCb({ ok: true, status: inner.status, url: inner.url, body: inner.body });
        } else {
          const error = `unexpected ${inner.op} response on fetch awaiter`;
          fetchCb({ ok: false, error, kind: classifyFetchError(error) });
        }
      } else {
        fetchCb({ ok: false, error: inner.error, kind: classifyFetchError(inner.error) });
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

  private rejectAllPending(): void {
    const err = new FetchproxyProtocolError('extension disconnected');
    for (const cb of this.pending.values()) {
      cb({ ok: false, error: err.message, kind: classifyFetchError(err.message) });
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
   * Shut down the bridge. Host: terminates the WebSocket server and any
   * still-attached extension/peer clients. Peer: closes the upstream
   * connection to the host. Safe to call before `listen()` (no-op) or
   * twice in a row.
   */
  async close(): Promise<void> {
    this.rejectAllPending();
    if (this.hostHandle) await this.hostHandle.close();
    if (this.peerHandle) this.peerHandle.close();
    this.hostHandle = null;
    this.peerHandle = null;
    this.role = null;
  }
}
