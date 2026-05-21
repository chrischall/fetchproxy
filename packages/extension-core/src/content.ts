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
    msg: { kind?: string; init?: FetchInit; keys?: string[] },
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
    return false;
  },
);

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
