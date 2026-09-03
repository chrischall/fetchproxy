/**
 * The "this tab can't inject a CSRF token" soft miss, shared by the
 * background's fetch handler and the content script.
 *
 * Why it exists (#286): sites like OpenTable refuse every write without
 * `x-csrf-token`. The content script injects that header from the tab's
 * `data-fetchproxy-csrf`, which the MAIN-world capture-logger copies from
 * `window.__CSRF_TOKEN__` — and only the site's *app* pages define that
 * global; a homepage or search tab doesn't. The fetch handler relays through
 * the first matching tab in `chrome.tabs.query` order, so a user whose oldest
 * tab on the site was the homepage got every write 403'd while a tab that
 * could serve it sat open two tabs over.
 *
 * The fix mirrors `graphql_query`'s per-tab walk: for a write, the background
 * first asks matching tabs with `requireCsrf` set; a tab with no token replies
 * with this soft miss instead of issuing the request, and the walk moves on.
 * If every tab misses (a site that never exposes `__CSRF_TOKEN__`), the
 * background re-sends without the marker and the first responsive tab serves
 * it exactly as before. No wire-protocol change; GETs are untouched.
 *
 * A leaf under `src/lib/`: no imports, no state, importable from both worlds.
 */

export const CSRF_SOFT_MISS = 'no-csrf' as const;

export interface CsrfSoftMiss {
  ok: false;
  error: string;
  softMiss: typeof CSRF_SOFT_MISS;
}

export function csrfSoftMiss(tabUrl: string): CsrfSoftMiss {
  return {
    ok: false,
    error: `tab ${tabUrl} exposes no CSRF token (window.__CSRF_TOKEN__ undefined) — trying another tab`,
    softMiss: CSRF_SOFT_MISS,
  };
}

export function isCsrfSoftMiss(response: unknown): boolean {
  if (!response || typeof response !== 'object') return false;
  const r = response as { ok?: unknown; softMiss?: unknown };
  return r.ok === false && r.softMiss === CSRF_SOFT_MISS;
}

/**
 * Whether a request should prefer a CSRF-bearing relay tab. Writes only:
 * reads never need the header, and walking them past csrf-less tabs would
 * cost every site without a `__CSRF_TOKEN__` global a second pass per GET.
 */
export function prefersCsrfTab(method: string): boolean {
  const m = method.toUpperCase();
  return m !== 'GET' && m !== 'HEAD';
}
