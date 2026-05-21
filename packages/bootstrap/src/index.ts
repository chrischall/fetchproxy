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
import type { Capability, CaptureHeaderDecl, IndexedDbScopeDecl } from '@fetchproxy/protocol';

// Bootstrap doesn't depend on @types/node; declare just enough of
// `process.env` to read the disable-fetchproxy env var. At runtime
// the global is provided by Node (the only platform this package
// targets).
declare const process: { env: Record<string, string | undefined> };

export interface Declarations {
  /** Cookie names the MCP wants to snapshot (subset of declared `cookieKeys`). */
  cookies: string[];
  /** localStorage keys to snapshot. */
  localStorage: string[];
  /** sessionStorage keys to snapshot. */
  sessionStorage: string[];
  /** Header captures: each entry's first matching request supplies the value. */
  captureHeaders: CaptureHeaderDecl[];
  /**
   * 0.4.0+: IndexedDB scopes to snapshot. Each entry declares
   * `(origin, database, store, keys)`. Defaults to `[]` for MCPs
   * that don't use IDB.
   */
  indexedDb?: IndexedDbScopeDecl[];
}

export interface BootstrapOpts {
  serverName: string;
  version: string;
  domains: string[];
  declare: Declarations;
  /**
   * 0.4.0+: invoked once on receipt of the extension hello with the
   * joint pair code. Used by MCPs that need to surface the code on
   * stderr or via a chat notification for the user to verify against
   * the browser popup. Optional.
   */
  onPairCode?: (code: string) => void;
  /**
   * 0.4.0+: invoked when bootstrap is about to wait on a step that
   * requires user interaction in the browser (e.g. capturing a
   * request header for an endpoint the user must trigger). The
   * `hint` is human-readable and identifies the action expected.
   */
  onWaiting?: (hint: string) => void;
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
  readIndexedDb?(opts: {
    database: string;
    store: string;
    keys: string[];
  }): Promise<Record<string, unknown>>;
}

export type BootstrapServerFactory = (opts: FetchproxyServerOpts) => BootstrapServer;

export interface Session {
  cookies: Record<string, string>;
  localStorage: Record<string, string>;
  sessionStorage: Record<string, string>;
  /** Captured headers, keyed by `headerName` (one entry per declared capture). */
  capturedHeaders: Record<string, string>;
  /**
   * 0.4.0+: snapshotted IndexedDB values, keyed by
   * `database/store`. Each inner map keys by IDB key → its
   * JSON-deserialized value.
   */
  indexedDb: Record<string, Record<string, unknown>>;
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
  // 0.4.0: an MCP can opt out of fetchproxy entirely by setting
  // ${SERVER_NAME}_DISABLE_FETCHPROXY=1 in the environment. This is
  // the well-known "don't run the bridge, I'll handle auth myself"
  // escape hatch — without it, every downstream MCP would have to
  // plumb its own env-var check around `bootstrap()`.
  //
  // Scoped serverNames (`@scope/foo`) collapse to `SCOPE_FOO_…` —
  // strip leading underscores so the env-var name doesn't start with
  // one (shells handle leading `_` but it's ugly to look at).
  const envVar =
    opts.serverName
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, '_')
      .replace(/^_+/, '') + '_DISABLE_FETCHPROXY';
  const envVal = process.env[envVar];
  if (envVal !== undefined && envVal !== '' && envVal !== '0' && envVal !== 'false') {
    throw new BootstrapDisabledError(opts.serverName, envVar);
  }

  const factory = opts._serverFactory ?? defaultFactory;
  const indexedDb = opts.declare.indexedDb ?? [];
  const capabilities: Capability[] = ['fetch'];
  if (opts.declare.cookies.length > 0) capabilities.push('read_cookies');
  if (opts.declare.localStorage.length > 0) capabilities.push('read_local_storage');
  if (opts.declare.sessionStorage.length > 0) capabilities.push('read_session_storage');
  if (opts.declare.captureHeaders.length > 0) capabilities.push('capture_request_header');
  if (indexedDb.length > 0) capabilities.push('read_indexed_db');
  const server = factory({
    serverName: opts.serverName,
    version: opts.version,
    domains: [...opts.domains],
    capabilities,
    cookieKeys: [...opts.declare.cookies],
    localStorageKeys: [...opts.declare.localStorage],
    sessionStorageKeys: [...opts.declare.sessionStorage],
    captureHeaders: opts.declare.captureHeaders.map((d) => ({ ...d })),
    indexedDbScopes: indexedDb.map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    })),
    onPairCode: opts.onPairCode,
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
      // capture_request_header is the only step that genuinely blocks
      // on user action — fire onWaiting just before we hand it off to
      // the extension so the MCP can surface a hint.
      if (opts.onWaiting) {
        try {
          const url = new URL(h.urlPattern.replace(/\*+/g, 'placeholder'));
          opts.onWaiting(
            `waiting for next request to ${url.host} to capture ${h.headerName} — interact with the page in your browser`,
          );
        } catch {
          opts.onWaiting(`waiting to capture ${h.headerName} — interact with the page in your browser`);
        }
      }
      capturedHeaders[h.headerName] = await server.captureRequestHeader({
        urlPattern: h.urlPattern,
        headerName: h.headerName,
      });
    }
    const indexedDbBucket: Record<string, Record<string, unknown>> = {};
    for (const d of indexedDb) {
      if (!server.readIndexedDb) {
        throw new Error(
          'bootstrap: server factory does not implement readIndexedDb (declared indexedDb but server stub omits it)',
        );
      }
      const values = await server.readIndexedDb({
        database: d.database,
        store: d.store,
        keys: [...d.keys],
      });
      indexedDbBucket[`${d.database}/${d.store}`] = values;
    }
    return {
      cookies,
      localStorage,
      sessionStorage,
      capturedHeaders,
      indexedDb: indexedDbBucket,
    };
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

/**
 * 0.4.0+: thrown by `bootstrap()` when the user has set
 * `${SERVER_NAME}_DISABLE_FETCHPROXY=1` in the environment.
 * MCPs catch this and fall back to a "fetchproxy is disabled" path
 * (typically: tell the user how to use the env var to re-enable, or
 * use an alternate auth method).
 */
export class BootstrapDisabledError extends Error {
  constructor(public readonly serverName: string, public readonly envVar: string) {
    super(`fetchproxy bootstrap disabled by ${envVar} (serverName: ${serverName})`);
    this.name = 'BootstrapDisabledError';
  }
}
