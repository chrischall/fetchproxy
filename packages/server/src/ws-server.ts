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
  domain: string;
  identityDir?: string;
  /** Full URL prefix prepended to relative paths. Defaults to `https://${domain}`. */
  origin?: string;
  /** Passed to the extension to pick which tab to fetch through. Defaults to `${origin}/`. */
  tabUrl?: string;
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

/** Options accepted by `request()` and the verb helpers. */
export interface RequestOpts {
  headers?: Record<string, string>;
  body?: string;
  /**
   * If provided, throws `FetchproxyHttpError` when the response status
   * does not match. A number is matched exactly; an array means "must be in this set".
   */
  expectStatus?: number | number[];
}

/** Options accepted by JSON/HTML shortcuts (no `body` — provided positionally). */
export interface BodylessRequestOpts {
  headers?: Record<string, string>;
  expectStatus?: number | number[];
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
 * Verify that `url`'s hostname is the declared `domain` or one of its
 * subdomains. Used at construction time on `origin` + `tabUrl` and at
 * call time on every resolved request URL. Throws on mismatch with a
 * developer-friendly message.
 */
function assertHostInDomain(field: string, url: string, domain: string): void {
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
  const expected = domain.toLowerCase();
  if (host !== expected && !host.endsWith('.' + expected)) {
    throw new Error(
      `FetchproxyServer: ${field} host "${host}" is outside declared domain "${expected}" — must be "${expected}" or "*.${expected}"`,
    );
  }
}

interface ResolvedOpts {
  port: number;
  host: string;
  serverName: string;
  version: string;
  domain: string;
  identityDir?: string;
  origin: string;
  tabUrl: string;
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
    const origin = opts.origin ?? `https://${opts.domain}`;
    const tabUrl = opts.tabUrl ?? `${origin}/`;
    // Guard: origin and tabUrl must resolve to a host that the declared
    // `domain` covers (exact match or subdomain). Catches misconfiguration
    // at construction time rather than letting every fetch get refused
    // by the extension's allowlist at runtime.
    assertHostInDomain('origin', origin, opts.domain);
    assertHostInDomain('tabUrl', tabUrl, opts.domain);
    this.opts = {
      port: opts.port ?? 37149,
      host: opts.host ?? '127.0.0.1',
      serverName: opts.serverName,
      version: opts.version,
      domain: opts.domain,
      identityDir: opts.identityDir,
      origin,
      tabUrl,
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
        ownDomain: this.opts.domain,
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
        domain: this.opts.domain,
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
   * Convenience wrapper around `fetch()` that resolves relative paths
   * against the configured `origin`, throws on protocol errors, and
   * optionally asserts on the response status.
   */
  async request(
    method: string,
    path: string,
    opts: RequestOpts = {},
  ): Promise<HttpResponse> {
    const url =
      path.startsWith('http://') || path.startsWith('https://')
        ? path
        : `${this.opts.origin}${path}`;
    // Guard: refuse to send any request whose resolved URL leaves the
    // declared domain. The extension would refuse it anyway; this gives
    // the MCP author a clear error at the call site instead of a generic
    // "domain not allowed" from the bridge.
    assertHostInDomain('request url', url, this.opts.domain);
    const init: FetchInit = {
      url,
      method,
      tabUrl: this.opts.tabUrl,
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
