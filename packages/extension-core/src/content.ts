import { evalJsonPointer } from '@fetchproxy/protocol';

/**
 * Content script (isolated world). Listens for fetch RPC messages
 * from the background service worker, runs window.fetch in the
 * page context with credentials: 'include', returns the response.
 *
 * The isolated-world fetch inherits cookies + the user's TLS
 * fingerprint — which is exactly what Akamai/Cloudflare want to see.
 *
 * Page-level globals (like window.__CSRF_TOKEN__) are NOT accessible
 * from the isolated world. The companion MAIN-world `capture-logger.ts`
 * script copies them to `document.documentElement.dataset.fetchproxyCsrf`
 * so we can pick them up here and forward as headers.
 */

const MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024; // 1 MB
const MAX_RESPONSE_BODY_BYTES = 5 * 1024 * 1024; // 5 MB
const GRAPHQL_TIMEOUT_MS = 20 * 1000; // 20 s to await the MAIN-world reply

interface FetchInit {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  tabUrl: string;
}

/**
 * `init` the background sends for a `graphql_query` op. The background has
 * already resolved the declared `name` → `operationName`; we just relay the
 * operation + variables to the MAIN-world Apollo bridge and await the reply.
 */
interface GraphqlQueryRelayInit {
  operationName: string;
  variables: Record<string, unknown>;
  tabUrl?: string;
}

interface GraphqlQueryResponse {
  ok: true;
  data: unknown;
}

/**
 * Minimal window surface the GraphQL relay touches. A fake stand-in is used
 * in unit tests so the `postMessage` round-trip is deterministic without
 * relying on jsdom's message-delivery semantics.
 */
interface GraphqlRelayWindow {
  addEventListener: (type: string, fn: (e: MessageEvent) => void) => void;
  removeEventListener: (type: string, fn: (e: MessageEvent) => void) => void;
  postMessage: (message: unknown, targetOrigin?: string) => void;
  location?: { origin?: string };
}

// Monotonic request id (NOT Math.random) so each in-flight graphql relay can
// match its own MAIN-world reply by `reqId`.
let graphqlReqCounter = 0;

interface FetchResponse {
  ok: true;
  status: number;
  url: string;
  body: string;
}

interface FetchError {
  ok: false;
  error: string;
}

chrome.runtime.onMessage.addListener(
  (
    msg: {
      kind?: string;
      init?: FetchInit | GraphqlQueryRelayInit;
      keys?: string[];
      database?: string;
      store?: string;
      pointers?: Record<string, { storageKey: string; jsonPointer: string }>;
      selectors?: { name: string; selector: string; attribute?: string }[];
    },
    _sender,
    sendResponse,
  ) => {
    if (msg.kind === 'fetchproxy-fetch' && msg.init) {
      void runFetch(msg.init as FetchInit)
        .then(sendResponse)
        .catch((e: unknown) =>
          sendResponse({ ok: false, error: (e as Error).message } satisfies FetchError),
        );
      return true; // tells Chrome we'll respond asynchronously
    }
    if (msg.kind === 'fetchproxy-read-cookies') {
      // Synchronous: `document.cookie` is a string getter on a same-origin
      // page. HttpOnly cookies are not visible to page JS — that is the
      // entire security model for this verb.
      try {
        sendResponse({ ok: true, cookies: document.cookie });
      } catch (e) {
        sendResponse({ ok: false, error: `document.cookie threw: ${(e as Error).message}` });
      }
      return false;
    }
    if (msg.kind === 'fetchproxy-read-local-storage' && Array.isArray(msg.keys)) {
      try {
        const values = readStorageWithPointers(window.localStorage, msg.keys, msg.pointers);
        sendResponse({ ok: true, values });
      } catch (e) {
        sendResponse({ ok: false, error: `localStorage read threw: ${(e as Error).message}` });
      }
      return false;
    }
    if (msg.kind === 'fetchproxy-read-session-storage' && Array.isArray(msg.keys)) {
      try {
        const values = readStorageWithPointers(window.sessionStorage, msg.keys, msg.pointers);
        sendResponse({ ok: true, values });
      } catch (e) {
        sendResponse({ ok: false, error: `sessionStorage read threw: ${(e as Error).message}` });
      }
      return false;
    }
    if (msg.kind === 'fetchproxy-read-dom' && Array.isArray(msg.selectors)) {
      // Isolated-world DOM read: this content script already has DOM
      // access, so no MAIN world / chrome.scripting / page-JS execution
      // is needed. Each declared selector is resolved against the live
      // document; missing elements / attributes are omitted (mirrors how
      // read_local_storage omits missing keys).
      try {
        const values = readDomValues(msg.selectors);
        sendResponse({ ok: true, values });
      } catch (e) {
        sendResponse({ ok: false, error: `DOM read threw: ${(e as Error).message}` });
      }
      return false;
    }
    if (
      msg.kind === 'fetchproxy-read-indexed-db' &&
      typeof msg.database === 'string' &&
      typeof msg.store === 'string' &&
      Array.isArray(msg.keys)
    ) {
      void runReadIndexedDb(msg.database, msg.store, msg.keys)
        .then(sendResponse)
        .catch((e: unknown) =>
          sendResponse({ ok: false, error: (e as Error).message }),
        );
      return true; // async
    }
    if (
      msg.kind === 'fetchproxy-graphql-query' &&
      msg.init &&
      typeof (msg.init as GraphqlQueryRelayInit).operationName === 'string'
    ) {
      // Relay to the MAIN-world Apollo bridge (capture-logger.ts) via a
      // window `postMessage` round-trip and await the reply. The MAIN world
      // invokes the page's real `window.__APOLLO_CLIENT__` — the only path
      // that carries OpenTable's Akamai link telemetry.
      void runGraphqlQuery(msg.init as GraphqlQueryRelayInit)
        .then(sendResponse)
        .catch((e: unknown) =>
          sendResponse({ ok: false, error: (e as Error).message } satisfies FetchError),
        );
      return true; // async
    }
    return false;
  },
);

/**
 * Relay a `graphql_query` to the MAIN-world Apollo bridge and await its
 * reply. Posts a `{ __fetchproxy: 'graphql-req', reqId, operationName,
 * variables }` envelope to `win` (the page's shared message bus, which both
 * the isolated and MAIN content-script worlds listen on) and resolves when a
 * matching `graphql-res` for the same `reqId` arrives. The per-request
 * listener is always removed on settle (reply, timeout, or throw).
 *
 * Exported for unit tests; production callers pass the default `window`.
 */
export function runGraphqlQuery(
  init: GraphqlQueryRelayInit,
  win: GraphqlRelayWindow = window as unknown as GraphqlRelayWindow,
  timeoutMs: number = GRAPHQL_TIMEOUT_MS,
): Promise<GraphqlQueryResponse | FetchError> {
  return new Promise<GraphqlQueryResponse | FetchError>((resolve) => {
    const reqId = ++graphqlReqCounter;
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const onMessage = (event: MessageEvent): void => {
      try {
        // Same-window guard: MAIN + isolated worlds share this window's
        // message bus; a cross-origin frame would have a different source.
        if (event.source !== (win as unknown as MessageEventSource)) return;
        const data = event.data as
          | { __fetchproxy?: string; reqId?: number; ok?: boolean; data?: unknown; error?: string }
          | null
          | undefined;
        if (!data || typeof data !== 'object' || data.__fetchproxy !== 'graphql-res') return;
        if (data.reqId !== reqId) return;
        if (data.ok === true) {
          // capture-logger.ts (the honest MAIN-world bridge) never sends
          // ok:true with a `data` that isn't a plain object — but this
          // listener trusts ANY same-window postMessage matching this
          // shape, and MAIN + isolated worlds share one message bus. A
          // page script (same origin, so it already has direct
          // __APOLLO_CLIENT__ access — no privilege gain, but worth not
          // trusting blindly here either) could post a spoofed graphql-res
          // with ok:true and data:null, data:[...], or data:"x". All of
          // those reach the server's assertObject(raw.data), which rejects
          // anything that isn't a plain object (null, arrays, and
          // primitives alike) — and via host.ts's catch-all, that closes
          // the extension WebSocket for every MCP on the concentrator.
          // Mirror assertObject's own object/array/null check here so
          // nothing it would reject gets this far.
          if (
            data.data === null ||
            data.data === undefined ||
            typeof data.data !== 'object' ||
            Array.isArray(data.data)
          ) {
            const kind =
              data.data === null ? 'null' : Array.isArray(data.data) ? 'array' : typeof data.data;
            finish({
              ok: false,
              error: `graphql bridge returned ok:true with a non-object data (${kind})`,
            });
            return;
          }
          // Mirrors runFetch's MAX_RESPONSE_BODY_BYTES guard — an
          // unbounded GraphQL `data` blob would otherwise cross the
          // isolated→background→server boundary with no size check.
          let serialized: string;
          try {
            serialized = JSON.stringify(data.data) ?? '';
          } catch (e) {
            finish({ ok: false, error: `graphql response not serializable: ${(e as Error).message}` });
            return;
          }
          if (serialized.length > MAX_RESPONSE_BODY_BYTES) {
            finish({ ok: false, error: `graphql response too large: ${serialized.length} bytes` });
            return;
          }
          finish({ ok: true, data: data.data });
        } else {
          finish({
            ok: false,
            error: typeof data.error === 'string' ? data.error : 'graphql bridge returned an error',
          });
        }
      } catch {
        // Never throw out of a window 'message' listener.
      }
    };

    const finish = (r: GraphqlQueryResponse | FetchError): void => {
      if (settled) return;
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      win.removeEventListener('message', onMessage);
      resolve(r);
    };

    const variables =
      init.variables && typeof init.variables === 'object' ? init.variables : {};
    // Mirrors runFetch's MAX_REQUEST_BODY_BYTES guard on the request body.
    let serializedVars: string;
    try {
      serializedVars = JSON.stringify(variables) ?? '';
    } catch (e) {
      resolve({ ok: false, error: `graphql variables not serializable: ${(e as Error).message}` });
      return;
    }
    if (serializedVars.length > MAX_REQUEST_BODY_BYTES) {
      resolve({ ok: false, error: `graphql variables too large: ${serializedVars.length} bytes` });
      return;
    }

    win.addEventListener('message', onMessage);
    timer = setTimeout(
      () =>
        finish({
          ok: false,
          error: `graphql bridge timed out after ${timeoutMs}ms waiting for the MAIN-world Apollo client`,
        }),
      timeoutMs,
    );

    try {
      win.postMessage(
        {
          __fetchproxy: 'graphql-req',
          reqId,
          operationName: init.operationName,
          variables,
        },
        win.location?.origin ?? '*',
      );
    } catch (e) {
      finish({ ok: false, error: `postMessage threw: ${(e as Error).message}` });
    }
  });
}

interface IdbResponse {
  ok: true;
  values: Record<string, unknown>;
}

interface IdbError {
  ok: false;
  error: string;
}

/**
 * Read storage keys plus optional JSON-pointer extractions. Returns a
 * flat string-valued map.
 *
 * - `keys`: full values for these keys are included under their own
 *   names. Missing keys are omitted.
 * - `pointers`: for each (outputKey, { storageKey, jsonPointer }),
 *   the storage value at `storageKey` is JSON-parsed, the pointer
 *   evaluated, and the extracted node JSON-stringified into the
 *   result under `outputKey`. Missing storage key, non-JSON value,
 *   or unresolved path → output key is omitted (NOT an error).
 */
function readStorageWithPointers(
  storage: Storage,
  keys: string[],
  pointers: Record<string, { storageKey: string; jsonPointer: string }> | undefined,
): Record<string, string> {
  const values: Record<string, string> = {};
  // Cache parsed JSON per storage key so we don't re-parse for each
  // pointer that references the same blob (HoneyBook's `jStorage`
  // pattern: one 50KB blob, many pointers).
  const parsed = new Map<string, unknown>();
  const tried = new Set<string>(); // keys we've attempted to parse

  function ensureParsed(storageKey: string): unknown {
    if (tried.has(storageKey)) return parsed.get(storageKey);
    tried.add(storageKey);
    const raw = storage.getItem(storageKey);
    if (typeof raw !== 'string') return undefined;
    try {
      const p = JSON.parse(raw);
      parsed.set(storageKey, p);
      return p;
    } catch {
      return undefined;
    }
  }

  for (const k of keys) {
    const v = storage.getItem(k);
    if (typeof v === 'string') values[k] = v;
  }
  if (pointers) {
    for (const [outputKey, { storageKey, jsonPointer }] of Object.entries(pointers)) {
      const root = ensureParsed(storageKey);
      if (root === undefined) continue;
      const node = evalJsonPointer(root, jsonPointer);
      if (node === undefined) continue;
      // Serialize back to a string so the wire stays homogeneous.
      // Primitives serialize cleanly; objects/arrays become JSON text.
      try {
        const text = typeof node === 'string' ? node : JSON.stringify(node);
        if (typeof text === 'string') values[outputKey] = text;
      } catch {
        // Non-serializable (e.g. circular) — skip.
      }
    }
  }
  return values;
}

/**
 * Read declared DOM selectors from the live document (isolated world).
 *
 * For each selector: `document.querySelector(selector)`; then the value is
 * the named attribute (`getAttribute`) when `attribute` is set, otherwise the
 * element's `.value` (form fields) falling back to `.textContent`. The value
 * is coerced to a string. A name is OMITTED from the result when the element
 * is absent, the attribute is absent, or the resolved value is null/undefined
 * — mirroring how `readStorageWithPointers` omits missing keys.
 */
export function readDomValues(
  selectors: { name: string; selector: string; attribute?: string }[],
): Record<string, string> {
  const values: Record<string, string> = {};
  for (const decl of selectors) {
    const el = document.querySelector(decl.selector);
    if (el === null) continue;
    const raw: unknown = decl.attribute
      ? el.getAttribute(decl.attribute)
      : ((el as HTMLInputElement).value ?? el.textContent);
    if (raw === null || raw === undefined) continue;
    values[decl.name] = String(raw);
  }
  return values;
}

async function runReadIndexedDb(
  database: string,
  store: string,
  keys: string[],
): Promise<IdbResponse | IdbError> {
  // Open the IDB via the standard API, run a readonly transaction
  // against `store`, gather values for each key, close the DB, and
  // return. Non-existent keys are omitted from the response. Any IDB
  // error (DB not found, store not found, etc.) surfaces as a single
  // fail rather than a partial result — the MCP expected to read all
  // declared keys, not some.
  return new Promise<IdbResponse | IdbError>((resolve) => {
    let db: IDBDatabase | null = null;
    let resolved = false;
    const finish = (r: IdbResponse | IdbError): void => {
      if (resolved) return;
      resolved = true;
      try {
        db?.close();
      } catch {
        // ignore
      }
      resolve(r);
    };
    let openReq: IDBOpenDBRequest;
    try {
      openReq = window.indexedDB.open(database);
    } catch (e) {
      finish({ ok: false, error: `indexedDB.open threw: ${(e as Error).message}` });
      return;
    }
    openReq.onerror = (): void => {
      finish({
        ok: false,
        error: `indexedDB.open(${database}) failed: ${openReq.error?.message ?? 'unknown'}`,
      });
    };
    openReq.onsuccess = (): void => {
      db = openReq.result;
      let tx: IDBTransaction;
      try {
        if (!db.objectStoreNames.contains(store)) {
          finish({
            ok: false,
            error: `object store "${store}" not present in database "${database}"`,
          });
          return;
        }
        tx = db.transaction(store, 'readonly');
      } catch (e) {
        finish({ ok: false, error: `IDB transaction failed: ${(e as Error).message}` });
        return;
      }
      const objStore = tx.objectStore(store);
      const values: Record<string, unknown> = {};
      let pending = keys.length;
      if (pending === 0) {
        finish({ ok: true, values });
        return;
      }
      for (const key of keys) {
        const req = objStore.get(key);
        req.onsuccess = (): void => {
          if (req.result !== undefined) {
            // Round-trip through JSON.stringify/parse to detect
            // unserializable values (Blob, typed arrays, etc.)
            // before they leave the page context. If the round-trip
            // throws or yields `undefined`, drop the key — the MCP
            // can't represent it on the wire anyway.
            try {
              const json = JSON.stringify(req.result);
              if (typeof json === 'string') {
                values[key] = JSON.parse(json);
              }
            } catch {
              // unserializable — omit
            }
          }
          if (--pending === 0) finish({ ok: true, values });
        };
        req.onerror = (): void => {
          // Per-key error: don't fail the whole read, just skip.
          if (--pending === 0) finish({ ok: true, values });
        };
      }
    };
  });
}

async function runFetch(init: FetchInit): Promise<FetchResponse | FetchError> {
  if (init.body && init.body.length > MAX_REQUEST_BODY_BYTES) {
    return { ok: false, error: `request body too large: ${init.body.length} bytes` };
  }
  // Auto-inject x-csrf-token from the MAIN-world capture-logger's dataset
  // sync. Caller can override by setting `x-csrf-token` in init.headers
  // explicitly. Sites that don't expose a CSRF on window.__CSRF_TOKEN__
  // just won't have anything to forward — dataset is empty, header omitted.
  const csrf = document.documentElement.dataset.fetchproxyCsrf;
  const headers: Record<string, string> = { ...(init.headers ?? {}) };
  if (csrf && !('x-csrf-token' in headers) && !('X-CSRF-Token' in headers)) {
    headers['x-csrf-token'] = csrf;
  }
  let response: Response;
  try {
    response = await window.fetch(init.url, {
      method: init.method,
      headers,
      body: init.body,
      credentials: 'include',
    });
  } catch (e) {
    return { ok: false, error: `fetch threw: ${(e as Error).message}` };
  }
  let body: string;
  try {
    body = await response.text();
  } catch (e) {
    return { ok: false, error: `response.text() threw: ${(e as Error).message}` };
  }
  if (body.length > MAX_RESPONSE_BODY_BYTES) {
    return { ok: false, error: `response body too large: ${body.length} bytes` };
  }
  return {
    ok: true,
    status: response.status,
    url: response.url,
    body,
  };
}
