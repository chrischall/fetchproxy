/**
 * Content script (isolated world). Listens for fetch RPC messages
 * from the background service worker, runs window.fetch in the
 * page context with credentials: 'include', returns the response.
 *
 * The isolated-world fetch inherits cookies + the user's TLS
 * fingerprint — which is exactly what Akamai/Cloudflare want to see.
 * The page's own auth state (CSRF tokens that live on window.*) is
 * NOT directly accessible; for the v1 booking flow we don't need
 * them in this codebase — the MCP server can include them via
 * init.headers if needed.
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

chrome.runtime.onMessage.addListener((msg: { kind?: string; init?: FetchInit }, _sender, sendResponse) => {
  if (msg.kind !== 'fetchproxy-fetch' || !msg.init) return false;

  void runFetch(msg.init)
    .then(sendResponse)
    .catch((e: unknown) => sendResponse({ ok: false, error: (e as Error).message } satisfies FetchError));
  return true; // tells Chrome we'll respond asynchronously
});

async function runFetch(init: FetchInit): Promise<FetchResponse | FetchError> {
  if (init.body && init.body.length > MAX_REQUEST_BODY_BYTES) {
    return { ok: false, error: `request body too large: ${init.body.length} bytes` };
  }
  let response: Response;
  try {
    response = await window.fetch(init.url, {
      method: init.method,
      headers: init.headers,
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
