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

interface FetchInit {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  tabUrl: string;
}

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
      init?: FetchInit;
      keys?: string[];
      database?: string;
      store?: string;
    },
    _sender,
    sendResponse,
  ) => {
    if (msg.kind === 'fetchproxy-fetch' && msg.init) {
      void runFetch(msg.init)
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
        const values: Record<string, string> = {};
        for (const k of msg.keys) {
          const v = window.localStorage.getItem(k);
          if (typeof v === 'string') values[k] = v;
        }
        sendResponse({ ok: true, values });
      } catch (e) {
        sendResponse({ ok: false, error: `localStorage read threw: ${(e as Error).message}` });
      }
      return false;
    }
    if (msg.kind === 'fetchproxy-read-session-storage' && Array.isArray(msg.keys)) {
      try {
        const values: Record<string, string> = {};
        for (const k of msg.keys) {
          const v = window.sessionStorage.getItem(k);
          if (typeof v === 'string') values[k] = v;
        }
        sendResponse({ ok: true, values });
      } catch (e) {
        sendResponse({ ok: false, error: `sessionStorage read threw: ${(e as Error).message}` });
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
    return false;
  },
);

interface IdbResponse {
  ok: true;
  values: Record<string, unknown>;
}

interface IdbError {
  ok: false;
  error: string;
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
