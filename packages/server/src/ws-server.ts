import { generateMcpId } from '@fetchproxy/protocol';
import type { InnerFrame, FetchInit } from '@fetchproxy/protocol';
import { electRole } from './election.js';
import { startHost, type HostHandle } from './host.js';
import { startPeer, type PeerHandle } from './peer.js';
import { loadOrCreateIdentity, type Identity } from './identity.js';

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
  identityDir?: string;
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
  identityDir?: string;
}

const DEFAULT_JSON_OK_STATUSES: readonly number[] = [200, 201, 202, 204];

export class FetchproxyServer {
  public role: 'host' | 'peer' | null = null;

  private opts: ResolvedOpts;
  private hostHandle: HostHandle | null = null;
  private peerHandle: PeerHandle | null = null;
  private nextRequestId = 1;
  private pending = new Map<number, (r: FetchResult | FetchResultError) => void>();
  private mcpId: string | null = null;
  private identity: Identity | null = null;

  constructor(opts: FetchproxyServerOpts) {
    if (!Array.isArray(opts.domains) || opts.domains.length === 0) {
      throw new Error(
        'FetchproxyServer: opts.domains must be a non-empty array of hostnames',
      );
    }
    this.opts = {
      port: opts.port ?? 37149,
      host: opts.host ?? '127.0.0.1',
      serverName: opts.serverName,
      version: opts.version,
      domains: [...opts.domains],
      identityDir: opts.identityDir,
    };
  }

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
      });
      this.hostHandle.onOwnInner((inner) => this.onInner(inner));
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
      });
      this.peerHandle.onInner((inner) => this.onInner(inner));
    }
  }

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

  get(path: string, opts: BodylessRequestOpts = {}): Promise<HttpResponse> {
    return this.request('GET', path, opts);
  }

  post(
    path: string,
    body?: string,
    opts: BodylessRequestOpts = {},
  ): Promise<HttpResponse> {
    return this.request('POST', path, { ...opts, body });
  }

  put(
    path: string,
    body?: string,
    opts: BodylessRequestOpts = {},
  ): Promise<HttpResponse> {
    return this.request('PUT', path, { ...opts, body });
  }

  patch(
    path: string,
    body?: string,
    opts: BodylessRequestOpts = {},
  ): Promise<HttpResponse> {
    return this.request('PATCH', path, { ...opts, body });
  }

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
    const cb = this.pending.get(inner.id);
    if (!cb) return;
    this.pending.delete(inner.id);
    if (inner.ok) {
      cb({ ok: true, status: inner.status, url: inner.url, body: inner.body });
    } else {
      cb({ ok: false, error: inner.error });
    }
  }

  async close(): Promise<void> {
    if (this.hostHandle) await this.hostHandle.close();
    if (this.peerHandle) this.peerHandle.close();
    this.hostHandle = null;
    this.peerHandle = null;
    this.role = null;
  }
}
