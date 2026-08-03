/**
 * @fetchproxy/bootstrap — session-capture helper for MCPs that follow
 * Pattern A.
 *
 * Most MCPs authenticate via the user's signed-in browser tab, then operate
 * from Node directly with `fetch()`. They don't need a long-lived browser
 * bridge; they need the cookies, localStorage values, and request-header
 * captures that prove the user is signed in, copied into the MCP process.
 *
 * Both entry points wrap the same lifecycle — spin up a `FetchproxyServer`,
 * declare the scope, read each declared bucket, close — and hand back a
 * `Session`. They differ in what you hold onto:
 *
 *   * {@link createSessionLifter} returns a **repeatable** lift. Prefer it
 *     whenever the captured session can expire: wire it into whatever your
 *     client uses to mint a session and every expiry re-reads the browser.
 *     Capturing a value once instead is the single most common way to build
 *     an MCP that works for one credential lifetime and then dies with no
 *     way back — a browser-backed account has no password to re-login with.
 *
 *   * {@link bootstrap} performs exactly one lift, immediately. Right for
 *     genuinely one-shot callers — typically a user-invoked `capture_session`
 *     tool that persists the token itself.
 *
 * The MCP imports just those and `Session` — it never sees
 * `FetchproxyServer`.
 */
import { FetchproxyServer, type FetchproxyServerOpts } from '@fetchproxy/server';
import type {
  Capability,
  CaptureHeaderDecl,
  IndexedDbScopeDecl,
  StoragePointerDecl,
} from '@fetchproxy/protocol';

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
  /**
   * 0.4.0+: JSON-pointer extractions over localStorage values. Each
   * entry binds `(outputKey → (storageKey, jsonPointer))`. The
   * storageKey must appear in `localStorage`; bootstrap reads it
   * once and applies all pointers against the parsed JSON.
   */
  localStoragePointers?: { outputKey: string; storageKey: string; jsonPointer: string }[];
  /** 0.4.0+: same shape for sessionStorage. */
  sessionStoragePointers?: { outputKey: string; storageKey: string; jsonPointer: string }[];
}

export interface BootstrapOpts {
  serverName: string;
  version: string;
  domains: string[];
  declare: Declarations;
  /**
   * 0.4.1+: which declared domain bootstrap's cookie / localStorage /
   * sessionStorage / indexedDb reads should target. Required when
   * `domains` has more than one entry; otherwise defaults to the only
   * declared domain. `captureHeaders` is unaffected — each entry
   * carries its own `host`.
   *
   * Example (HoneyBook spans `honeybook.com` for the API
   * `hb-api-fingerprint` capture and `hbportal.co` for the vendor
   * portal where `jStorage` lives):
   *
   *   bootstrap({
   *     domains: ['honeybook.com', 'hbportal.co'],
   *     storageDomain: 'hbportal.co', // jStorage reads target the vendor portal tab
   *     declare: { localStoragePointers: [...], captureHeaders: [...] },
   *   });
   */
  storageDomain?: string;
  /**
   * 0.4.1+: optional subdomain selector applied to the resolved
   * storage domain (e.g. `www`, `app`). The extension matches a tab
   * whose host equals `${subdomain}.${storageDomain}`. Most MCPs
   * leave this unset — the apex-domain match is sufficient.
   */
  storageSubdomain?: string;
  /**
   * 1.11.0+: optional path the cookie read should target, e.g. `/campus`.
   *
   * `chrome.cookies.get({ url, name })` matches the cookie's `Path` attribute
   * against the URL's path, so a cookie set with `Path=/campus` is invisible
   * to a read aimed at the origin root. Sites that scope their session cookie
   * to an app context — Tomcat does this by default — were therefore
   * unreadable, and the miss was indistinguishable from "user is signed out".
   *
   * Only affects the cookie read; localStorage / sessionStorage / IndexedDB
   * are origin-scoped and unaffected by path.
   */
  storagePath?: string;
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
   * 0.8.0+: forwarded as-is to `FetchproxyServer`. Unset → server
   * default (30000ms in 0.8.0). Set to 0 to disable. Useful for
   * one-shot consumers that want a shorter ceiling than the default.
   */
  fetchTimeoutMs?: number;
  /**
   * 0.8.0+: forwarded as-is to `FetchproxyServer`. Unset → server
   * default (2000ms in 0.8.0). Set to 0 to disable. Useful when a
   * Pattern-A startup capture should fail fast rather than tolerate
   * SW eviction (e.g. CI smoke tests).
   */
  bridgeReviveDelayMs?: number;
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
  readCookies(opts: {
    keys: string[];
    domain?: string;
    subdomain?: string;
    path?: string;
  }): Promise<string>;
  readLocalStorage(opts: {
    keys: string[];
    domain?: string;
    subdomain?: string;
    pointers?: Record<string, { storageKey: string; jsonPointer: string }>;
  }): Promise<Record<string, string>>;
  readSessionStorage(opts: {
    keys: string[];
    domain?: string;
    subdomain?: string;
    pointers?: Record<string, { storageKey: string; jsonPointer: string }>;
  }): Promise<Record<string, string>>;
  captureRequestHeader(opts: {
    host: string;
    path?: string;
    headerName: string;
  }): Promise<string>;
  readIndexedDb(opts: {
    database: string;
    store: string;
    keys: string[];
    domain?: string;
    subdomain?: string;
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
  /**
   * 1.8.0+: declared keys the browser did NOT return, per bucket.
   *
   * A partial lift is the most dangerous failure this helper can produce: the
   * call succeeds, the maps look populated, and the MCP builds a session that
   * fails much later somewhere unrelated. That is not hypothetical — an MCP
   * declaring `['accessToken','cfid','cftoken']` while reading at an apex host
   * that only carries `accessToken` got a "successful" bootstrap and then a
   * baffling "you are no longer logged in" from a completely different
   * endpoint. Reading the wrong host is easy (`storageSubdomain`), and nothing
   * used to point at it.
   *
   * Empty arrays mean everything declared came back. Callers that need all of
   * their declared keys should check this and fail loudly, naming the misses.
   *
   * Note these are *declared* keys, not pointer output names: localStorage
   * pointers are resolved from the raw storage keys, which are what is
   * reported here.
   */
  missing: {
    cookies: string[];
    localStorage: string[];
    sessionStorage: string[];
  };
}

const defaultFactory: BootstrapServerFactory = (opts) => new FetchproxyServer(opts);


/**
 * A repeatable browser-session lift.
 *
 * Calling it opens the bridge, reads every declared bucket, closes the bridge,
 * and resolves with the captured {@link Session} — the same work `bootstrap()`
 * does, except you hold the *ability* to do it rather than one result of
 * having done it.
 */
export type SessionLifter = () => Promise<Session>;

/**
 * Build a repeatable lift for one MCP's declared scope.
 *
 * Prefer this over {@link bootstrap} whenever the session can expire.
 *
 * ## Why this exists
 *
 * `bootstrap()` returns a *value*, so consumers naturally capture a session
 * once at process start and hand it to their client. That is the API's grain,
 * not a consumer mistake — and it produces a bug that stays invisible until
 * the site's credential lifetime is short enough to notice:
 *
 *   * **The expiry dead end.** A browser-backed account has no password, so
 *     when the captured credential lapses there is nothing to re-login with.
 *     The MCP is unauthenticated for the life of the process even though the
 *     browser still holds a live session the whole time.
 *   * **The sticky startup failure.** A lift that failed at boot (user not
 *     signed in yet) gets cached just as permanently, so signing in afterwards
 *     changes nothing.
 *
 * A fleet audit behind this API found four MCPs carrying the one-shot capture
 * and four that had independently hand-rolled the renewable shape. Making
 * renewable the default is the point.
 *
 * ## Usage
 *
 * Construction touches nothing — no server, no `listen()`, no pair prompt.
 * Wire the lifter into whatever your client uses to mint a session, so expiry
 * re-reads the browser instead of dead-ending:
 *
 * ```ts
 * const lift = createSessionLifter({ serverName, version, domains, declare });
 * const manager = new CookieSessionManager({ login: lift, isExpired });
 * ```
 *
 * ## What it deliberately does NOT do
 *
 * No TTL tracking, no caching of the result. Expiry semantics are
 * app-specific — some sites need the lifted token exchanged before it is
 * usable, others go stale on an idle timer the library cannot see — so the
 * caller's session manager owns *when* to re-lift. The lifter only owns *how*.
 *
 * Post-processing composes in userland rather than needing a hook:
 *
 * ```ts
 * const raw = createSessionLifter(opts);
 * const lift = async () => exchangeIfStale(await raw());
 * ```
 *
 * Concurrent calls are single-flighted: two simultaneous expiries share one
 * bridge round-trip rather than racing two. Once a lift settles the next call
 * starts a fresh one — this is de-duplication, not caching.
 */
export function createSessionLifter(opts: BootstrapOpts): SessionLifter {
  let inFlight: Promise<Session> | null = null;
  return () => {
    if (inFlight) return inFlight;
    const p = runOneLift(opts).finally(() => {
      // Clear before the caller's `.then` runs so a lift started from within
      // a continuation is not deduped against the one that just settled.
      if (inFlight === p) inFlight = null;
    });
    inFlight = p;
    return p;
  };
}

/**
 * Bootstrap one MCP's session blob — a single lift, run immediately.
 *
 * Equivalent to `createSessionLifter(opts)()`. Kept as a first-class export
 * because plenty of callers genuinely only need one read: the tool-invoked
 * capture pattern (a `capture_session` tool the user runs on demand, which
 * then persists the token) is legitimately one-shot.
 *
 * If the session it returns can expire underneath you, reach for
 * {@link createSessionLifter} instead.
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
  return runOneLift(opts);
}

/** Internal: one open→read→close cycle. See `bootstrap` / `createSessionLifter`. */
async function runOneLift(opts: BootstrapOpts): Promise<Session> {
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
  const localStoragePointers = opts.declare.localStoragePointers ?? [];
  const sessionStoragePointers = opts.declare.sessionStoragePointers ?? [];
  const capabilities: Capability[] = ['fetch'];
  // localStorage / sessionStorage capabilities are needed whenever
  // EITHER raw key reads OR pointer extractions are declared (the
  // extension uses the same verb for both).
  if (opts.declare.cookies.length > 0) capabilities.push('read_cookies');
  if (opts.declare.localStorage.length > 0 || localStoragePointers.length > 0) {
    capabilities.push('read_local_storage');
  }
  if (opts.declare.sessionStorage.length > 0 || sessionStoragePointers.length > 0) {
    capabilities.push('read_session_storage');
  }
  if (opts.declare.captureHeaders.length > 0) capabilities.push('capture_request_header');
  if (indexedDb.length > 0) capabilities.push('read_indexed_db');

  // Pointer declarations need their storageKey listed in declared
  // localStorageKeys / sessionStorageKeys too. We auto-add it here
  // so MCP authors don't have to duplicate the key in two places.
  const localStorageKeys = new Set(opts.declare.localStorage);
  for (const p of localStoragePointers) localStorageKeys.add(p.storageKey);
  const sessionStorageKeys = new Set(opts.declare.sessionStorage);
  for (const p of sessionStoragePointers) sessionStorageKeys.add(p.storageKey);

  const server = factory({
    serverName: opts.serverName,
    version: opts.version,
    domains: [...opts.domains],
    capabilities,
    cookieKeys: [...opts.declare.cookies],
    localStorageKeys: [...localStorageKeys],
    sessionStorageKeys: [...sessionStorageKeys],
    captureHeaders: opts.declare.captureHeaders.map((d) => ({ ...d })),
    indexedDbScopes: indexedDb.map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    })),
    localStoragePointers: localStoragePointers.map((p) => ({
      key: p.storageKey,
      jsonPointer: p.jsonPointer,
    })),
    sessionStoragePointers: sessionStoragePointers.map((p) => ({
      key: p.storageKey,
      jsonPointer: p.jsonPointer,
    })),
    onPairCode: opts.onPairCode,
    // 0.8.0+ pass-through. Only forwarded when the caller set them;
    // unset → server defaults apply (30000 / 2000 in 0.8.0).
    ...(opts.fetchTimeoutMs !== undefined
      ? { fetchTimeoutMs: opts.fetchTimeoutMs }
      : {}),
    ...(opts.bridgeReviveDelayMs !== undefined
      ? { bridgeReviveDelayMs: opts.bridgeReviveDelayMs }
      : {}),
  });
  // 0.4.1: pre-build the storage-domain selector once. Used by every
  // per-tab read (cookies / localStorage / sessionStorage / indexedDb).
  // captureRequestHeader is unaffected — each entry carries its own
  // `host`.
  const storageDomainOpts: { domain?: string; subdomain?: string } = {};
  if (opts.storageDomain !== undefined) storageDomainOpts.domain = opts.storageDomain;
  if (opts.storageSubdomain !== undefined) storageDomainOpts.subdomain = opts.storageSubdomain;

  try {
    await server.listen();
    const cookies: Record<string, string> = {};
    if (opts.declare.cookies.length > 0) {
      const joined = await server.readCookies({
        keys: opts.declare.cookies,
        ...storageDomainOpts,
        // Cookie-only: the other buckets are origin-scoped and ignore path.
        ...(opts.storagePath !== undefined ? { path: opts.storagePath } : {}),
      });
      for (const piece of joined.split('; ')) {
        if (!piece) continue;
        const eq = piece.indexOf('=');
        if (eq < 0) continue;
        cookies[piece.slice(0, eq)] = piece.slice(eq + 1);
      }
    }
    // 0.4.0: when pointers are declared, request them in the same
    // call as the raw key reads — the extension reads each storage
    // key once and applies all pointers to it.
    let localStorage: Record<string, string> = {};
    if (opts.declare.localStorage.length > 0 || localStoragePointers.length > 0) {
      const allKeys = [...localStorageKeys];
      const pointers: Record<string, { storageKey: string; jsonPointer: string }> = {};
      for (const p of localStoragePointers) {
        pointers[p.outputKey] = { storageKey: p.storageKey, jsonPointer: p.jsonPointer };
      }
      localStorage = await server.readLocalStorage({
        keys: allKeys,
        ...storageDomainOpts,
        ...(localStoragePointers.length > 0 ? { pointers } : {}),
      });
    }
    let sessionStorage: Record<string, string> = {};
    if (opts.declare.sessionStorage.length > 0 || sessionStoragePointers.length > 0) {
      const allKeys = [...sessionStorageKeys];
      const pointers: Record<string, { storageKey: string; jsonPointer: string }> = {};
      for (const p of sessionStoragePointers) {
        pointers[p.outputKey] = { storageKey: p.storageKey, jsonPointer: p.jsonPointer };
      }
      sessionStorage = await server.readSessionStorage({
        keys: allKeys,
        ...storageDomainOpts,
        ...(sessionStoragePointers.length > 0 ? { pointers } : {}),
      });
    }
    const capturedHeaders: Record<string, string> = {};
    for (const h of opts.declare.captureHeaders) {
      // capture_request_header is the only step that genuinely blocks
      // on user action — fire onWaiting just before we hand it off to
      // the extension so the MCP can surface a hint.
      if (opts.onWaiting) {
        opts.onWaiting(
          `waiting for next request to ${h.host} to capture ${h.headerName} — interact with the page in your browser`,
        );
      }
      capturedHeaders[h.headerName] = await server.captureRequestHeader({
        host: h.host,
        ...(h.path !== undefined ? { path: h.path } : {}),
        headerName: h.headerName,
      });
    }
    const indexedDbBucket: Record<string, Record<string, unknown>> = {};
    for (const d of indexedDb) {
      const values = await server.readIndexedDb({
        database: d.database,
        store: d.store,
        keys: [...d.keys],
        ...storageDomainOpts,
      });
      indexedDbBucket[`${d.database}/${d.store}`] = values;
    }
    // Declared-but-absent keys, computed against what actually came back.
    // See `Session.missing` for why a silent partial lift is worth surfacing.
    const absent = (declared: readonly string[], got: Record<string, unknown>): string[] =>
      declared.filter((k) => !(k in got));

    return {
      cookies,
      localStorage,
      sessionStorage,
      capturedHeaders,
      indexedDb: indexedDbBucket,
      missing: {
        cookies: absent(opts.declare.cookies, cookies),
        localStorage: absent(opts.declare.localStorage, localStorage),
        sessionStorage: absent(opts.declare.sessionStorage, sessionStorage),
      },
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
