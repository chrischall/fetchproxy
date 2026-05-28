/**
 * Classifies the raw `error` string the extension puts on the wire
 * into a small discriminated set. Downstream MCPs (compass-mcp,
 * honeybook-mcp, …) can branch on `kind` instead of pattern-matching
 * strings — every change to extension-emitted error templates needs
 * to be reflected here in one place.
 *
 * The kinds correspond 1:1 with concrete error templates in
 * `extension-core/src/background.ts` and
 * `extension-core/src/content.ts`. Adding a new kind is additive: old
 * downstream code that only inspects `error` keeps working; code that
 * switch()es on `kind` gets a new case to handle.
 *
 * `'other'` is the explicit forward-compat escape — if an extension
 * version emits a string this classifier doesn't recognise yet, the
 * server still surfaces the raw `error`, just with `kind: 'other'`.
 */
export type FetchErrorKind =
  /** chrome.tabs.sendMessage failed: the matched tab has no content-
   * script listener (content script never injected, was unloaded,
   * background service worker died — see also MV3 keepalive). The
   * fix is on the extension side; downstream MCPs should hint the
   * user to reload the extension or open a fresh tab. */
  | 'content_script_unreachable'
  /** No browser tab is currently open on a URL that matches the
   * `tabUrl` prefix the MCP asked for. User needs to open the site. */
  | 'no_tab'
  /** A matching tab exists and the content script responded, but the
   * page-side `window.fetch` itself failed (CORS, DNS, network error,
   * abort). Genuine upstream / network problem, not a bridge issue. */
  | 'tab_fetch_failed'
  /** The requested URL was outside the MCP's declared `domains` list.
   * Programmer error — the MCP code is asking for a domain it didn't
   * declare at construction time. */
  | 'domain_denied'
  /** The op requested a capability the MCP didn't declare (e.g.
   * `read_cookies` without listing it in `capabilities`). Programmer
   * error in the MCP code. */
  | 'capability_denied'
  /** Request or response body exceeded the bridge's size cap. The MCP
   * is moving too much data through the per-request frame; consider
   * a different endpoint or paginating. */
  | 'body_too_large'
  /** 0.8.0+: server-side `fetchTimeoutMs` fired before the bridge
   * responded. Not produced by `classifyFetchError` — emitted directly
   * by `FetchproxyServer.fetch()` when its own timer wins the race. */
  | 'timeout'
  /** 0.11.x+ (#86): the upstream site served a bot-wall / CAPTCHA
   * interstitial (PerimeterX, AWS WAF, Cloudflare, DataDome) instead of
   * real content. Detected by `classifyBotWall` on the response
   * body/status — NOT by this string classifier (a bot-wall is content,
   * not an extension error string). Distinct from `no_tab` / not-found
   * and from `tab_fetch_failed`: a bot-wall is transient and retryable
   * (back off via `backoffDelayMs`, ideally with a smaller batch) and
   * must never be mistaken for "not found" — that's the silent-data-
   * corruption failure class the cohort guards against. */
  | 'bot_challenge'
  /** Catch-all for strings this classifier doesn't recognise yet.
   * Forward-compat: a future extension version emitting a new error
   * template lands here until the classifier is updated. */
  | 'other';

/**
 * Map a raw extension error string to a `FetchErrorKind`. Pure;
 * matches against substrings (the extension wraps its inner errors,
 * so we can't anchor on prefixes alone).
 */
export function classifyFetchError(error: string): FetchErrorKind {
  // Order matters: content_script_unreachable and tab_fetch_failed
  // BOTH show up under the `tab fetch failed:` wrapper, so the
  // more-specific Chrome runtime strings have to be checked first.
  // (A real-world example: "tab fetch failed: Error: Could not
  // establish connection. Receiving end does not exist." — without
  // checking the inner phrasing first, this would mis-classify as
  // `tab_fetch_failed`.)
  if (
    /Could not establish connection/i.test(error) ||
    /Receiving end does not exist/i.test(error)
  ) {
    return 'content_script_unreachable';
  }
  if (/^tab fetch failed:/.test(error)) {
    return 'tab_fetch_failed';
  }
  if (/^fetch threw:/.test(error)) {
    return 'tab_fetch_failed';
  }
  if (/^no tab matching /.test(error)) {
    return 'no_tab';
  }
  if (/not in domains \[/.test(error)) {
    return 'domain_denied';
  }
  if (/^capability .+ not granted/.test(error)) {
    return 'capability_denied';
  }
  if (/^(request|response) body too large:/.test(error)) {
    return 'body_too_large';
  }
  return 'other';
}
