/**
 * MAIN-world bridge script. The isolated-world content script can read
 * cookies + run `window.fetch` with `credentials: 'include'`, but it
 * CAN'T see page-level globals like `window.__CSRF_TOKEN__` (those live
 * in the page MAIN world, isolated from the extension's content scripts).
 *
 * This script runs in MAIN world and copies a small set of well-known
 * page globals onto `document.documentElement.dataset` so the isolated-
 * world content script can pick them up and forward them as headers on
 * the fetch.
 *
 * v1 hardcodes one mapping: `window.__CSRF_TOKEN__` → `data-fetchproxy-csrf`,
 * which `content.ts` reads + sets as `x-csrf-token` on every fetch. This
 * is what OpenTable + similar Akamai-fronted sites need to clear their
 * bot check. A follow-up spec will make this configurable per-MCP via
 * a `csrf_capture` field in the server's hello frame.
 *
 * Security: dataset attributes are readable by any same-origin script.
 * The page's own scripts already have window.__CSRF_TOKEN__, so this
 * doesn't expand the same-origin attack surface. Cross-origin code
 * cannot read another origin's DOM datasets.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

declare global {
  interface Window {
    __CSRF_TOKEN__?: string;
  }
}

const SYNC_INTERVAL_MS = 2000;
const DATASET_KEY = 'fetchproxyCsrf';

function syncCsrf(): void {
  const token = window.__CSRF_TOKEN__;
  if (typeof token === 'string' && token.length > 0) {
    document.documentElement.dataset[DATASET_KEY] = token;
  } else {
    delete document.documentElement.dataset[DATASET_KEY];
  }
}

// First sync immediately so a fetch issued right after extension load
// has the token; then refresh every 2s in case the page rotates it.
syncCsrf();
setInterval(syncCsrf, SYNC_INTERVAL_MS);

export {};
