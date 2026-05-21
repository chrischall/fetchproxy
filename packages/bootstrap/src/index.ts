/**
 * @fetchproxy/bootstrap — one-shot session-capture helper for MCPs that
 * follow Pattern A.
 *
 * Most MCPs need to authenticate once via the user's signed-in browser
 * tab, then operate from Node directly with `fetch()`. They don't need
 * a long-lived browser bridge; they need the cookies, localStorage
 * values, and request-header captures that prove the user is signed
 * in, copied into the MCP process once at startup.
 *
 * `bootstrap()` wraps that lifecycle: spin up a `FetchproxyServer`,
 * declare the scope, read each declared bucket, close. The caller
 * gets a single `Session` blob back. ~30 lines plus types.
 *
 * The MCP imports just `bootstrap` and `Session` — it never sees
 * `FetchproxyServer`.
 */
import { FetchproxyServer, type FetchproxyServerOpts } from '@fetchproxy/server';
import type { Capability, CaptureHeaderDecl } from '@fetchproxy/protocol';

export interface Declarations {
  /** Cookie names the MCP wants to snapshot (subset of declared `cookieKeys`). */
  cookies: string[];
  /** localStorage keys to snapshot. */
  localStorage: string[];
  /** sessionStorage keys to snapshot. */
  sessionStorage: string[];
  /** Header captures: each entry's first matching request supplies the value. */
  captureHeaders: CaptureHeaderDecl[];
}

export interface BootstrapOpts {
  serverName: string;
  version: string;
  domains: string[];
  declare: Declarations;
  /**
   * For tests only: inject a fake `FetchproxyServer` factory. The
   * default uses the real `FetchproxyServer` constructor + `.listen()`.
   * The opts object is the same shape `FetchproxyServer` accepts.
   *
   * The underscore prefix is a soft "internal" marker. Don't pass this
   * from MCP code.
   */
  _serverFactory?: BootstrapServerFactory;
}

/** Minimal surface `bootstrap()` actually calls on a `FetchproxyServer`. */
export interface BootstrapServer {
  listen(): Promise<void>;
  close(): Promise<void>;
  readCookies(opts: { keys: string[] }): Promise<string>;
  readLocalStorage(opts: { keys: string[] }): Promise<Record<string, string>>;
  readSessionStorage(opts: { keys: string[] }): Promise<Record<string, string>>;
  captureRequestHeader(opts: {
    urlPattern: string;
    headerName: string;
  }): Promise<string>;
}

export type BootstrapServerFactory = (opts: FetchproxyServerOpts) => BootstrapServer;

export interface Session {
  cookies: Record<string, string>;
  localStorage: Record<string, string>;
  sessionStorage: Record<string, string>;
  /** Captured headers, keyed by `headerName` (one entry per declared capture). */
  capturedHeaders: Record<string, string>;
}

const defaultFactory: BootstrapServerFactory = (opts) => new FetchproxyServer(opts);

/**
 * Bootstrap one MCP's session blob.
 *
 * Workflow:
 *   1. Construct a `FetchproxyServer` with the declared scope mapped
 *      onto its opts (capabilities derived from non-empty buckets).
 *   2. `listen()` — the bridge starts and the extension reconnects.
 *   3. Each declared bucket is read in turn. Empty buckets are skipped.
 *   4. `close()` runs in a finally block — the bridge shuts down even
 *      when one of the reads throws.
 *   5. Return the captured `Session`.
 *
 * The promise rejects on the first read that fails. The caller should
 * surface that error to the user (most often: "open <domain> in Chrome
 * and sign in, then retry").
 */
export async function bootstrap(opts: BootstrapOpts): Promise<Session> {
  const factory = opts._serverFactory ?? defaultFactory;
  const capabilities: Capability[] = ['fetch'];
  if (opts.declare.cookies.length > 0) capabilities.push('read_cookies');
  if (opts.declare.localStorage.length > 0) capabilities.push('read_local_storage');
  if (opts.declare.sessionStorage.length > 0) capabilities.push('read_session_storage');
  if (opts.declare.captureHeaders.length > 0) capabilities.push('capture_request_header');
  const server = factory({
    serverName: opts.serverName,
    version: opts.version,
    domains: [...opts.domains],
    capabilities,
    cookieKeys: [...opts.declare.cookies],
    localStorageKeys: [...opts.declare.localStorage],
    sessionStorageKeys: [...opts.declare.sessionStorage],
    captureHeaders: opts.declare.captureHeaders.map((d) => ({ ...d })),
  });
  try {
    await server.listen();
    const cookies: Record<string, string> = {};
    if (opts.declare.cookies.length > 0) {
      const joined = await server.readCookies({ keys: opts.declare.cookies });
      for (const piece of joined.split('; ')) {
        if (!piece) continue;
        const eq = piece.indexOf('=');
        if (eq < 0) continue;
        cookies[piece.slice(0, eq)] = piece.slice(eq + 1);
      }
    }
    const localStorage =
      opts.declare.localStorage.length > 0
        ? await server.readLocalStorage({ keys: opts.declare.localStorage })
        : {};
    const sessionStorage =
      opts.declare.sessionStorage.length > 0
        ? await server.readSessionStorage({ keys: opts.declare.sessionStorage })
        : {};
    const capturedHeaders: Record<string, string> = {};
    for (const h of opts.declare.captureHeaders) {
      capturedHeaders[h.headerName] = await server.captureRequestHeader({
        urlPattern: h.urlPattern,
        headerName: h.headerName,
      });
    }
    return { cookies, localStorage, sessionStorage, capturedHeaders };
  } finally {
    // Best-effort cleanup. If close() throws, swallow it — the original
    // failure (or success) is the interesting result to surface.
    try {
      await server.close();
    } catch {
      // ignore
    }
  }
}
