/**
 * `sendToFirstResponsiveTab` — the multi-tab content-script fan-out,
 * moved verbatim out of `background.ts`.
 *
 * It lives under `src/lib/` rather than beside any one handler because it
 * has six callers spread across every tab-driven verb (fetch, legacy
 * read_cookies, read_storage, read_indexed_db, read_dom, graphql_query).
 * It holds no module state and reaches nothing but `chrome.tabs`, so it is
 * a leaf: importable from any handler without creating an edge between them.
 */

import type { ChromeApi } from '../chrome-api.js';

declare const chrome: ChromeApi;

/**
 * 0.5.2+: walk every tab whose URL passes `matcher`, send the built
 * message via `chrome.tabs.sendMessage`, and return the first response.
 *
 * Three terminal states:
 *
 *   - `{ kind: 'response', response, tabUrl }` — a tab's content script
 *     replied (the body is the content script's typed payload, opaque
 *     to this helper; caller knows the shape).
 *   - `{ kind: 'no-tab', error }` — either no tab matched, or every
 *     matched tab threw "Receiving end does not exist" (i.e., none of
 *     them have a loaded content script — the caller's `tabUrl` is
 *     surfaced in the error so the user knows which page to refresh).
 *   - `{ kind: 'throw', error }` — one of the matched tabs threw a
 *     non-receiving-end error. Surfaced verbatim so the caller can
 *     wrap it in a verb-specific error message; iteration stops at the
 *     first such throw since it likely indicates a real fault rather
 *     than a missing content script.
 *
 * `isSoftMiss` (optional) widens the fan-out: when it returns true for a
 * tab's response, that tab is treated like one without a content script —
 * iteration continues to the next match instead of stopping. If every
 * matching tab soft-misses, the FIRST miss is returned as the response, so
 * its actionable hint survives. Only `graphql_query` passes one; every
 * other verb keeps the first-answer-wins behaviour unchanged, because for
 * them an `ok:false` is a real answer (an HTTP error, a denied read) that
 * must not be retried against every other tab on the origin.
 *
 * `buildMessage` is called per-tab so the message can carry the matched
 * tab's resolved URL (useful for verbs that need to canonicalise their
 * tabUrl against the actual tab). The caller controls the matcher so
 * each verb can choose between strict-prefix (`isTabUrlMatch`) and
 * host-or-subdomain (`isTabUrlOnOrigin`) semantics.
 */
export type SendToFirstResponsiveTabResult =
  | { kind: 'response'; response: unknown; tabUrl: string }
  | { kind: 'no-tab'; error: string }
  | { kind: 'throw'; error: string };

// Exported for unit testing; not surfaced from `./index.ts` because
// production callers (extension-chrome, extension-safari) have no
// reason to invoke it directly — the handlers in this file are the
// only callsites.
export async function sendToFirstResponsiveTab(
  matcher: (tabUrl: string) => boolean,
  buildMessage: (matchedTabUrl: string) => unknown,
  tabUrlForError: string,
  isSoftMiss?: (response: unknown) => boolean,
): Promise<SendToFirstResponsiveTabResult> {
  const tabs = await chrome.tabs.query({});
  // Fold the ID check into the filter so `matches.length` accurately
  // reflects the count of tabs we'll actually try — without this, a tab
  // with `undefined` id would inflate the count and the error message
  // would claim "N URL matches, none responded" when one of those N
  // was never even attempted.
  const matches = tabs.filter(
    (t) => typeof t.id === 'number' && t.url && matcher(t.url),
  );
  if (matches.length === 0) {
    return { kind: 'no-tab', error: `no tab matching ${tabUrlForError}` };
  }
  // "Receiving end does not exist" surfaces when a tab matches the URL
  // but has no content script (typically post-reload pages that pre-date
  // the current extension install). Skip those and try the next match —
  // self-heals the common "extension reloaded, old tabs still open" case
  // without the user having to refresh every pre-reload tab.
  let lastNoListener: string | null = null;
  // First soft miss, kept so it can be returned verbatim if EVERY matching
  // tab misses — the miss carries the actionable "open a page that triggers
  // this operation" hint, which is still the right remedy in that case.
  let firstSoftMiss: { response: unknown; tabUrl: string } | null = null;
  for (const match of matches) {
    // `match.id` is guaranteed `number` by the filter above, but the
    // chrome typings still type it as `number | undefined` so we use a
    // non-null narrowing here. The filter is the authority.
    const id = match.id as number;
    const tabUrl = match.url ?? tabUrlForError;
    try {
      const response = await chrome.tabs.sendMessage(id, buildMessage(tabUrl));
      // A soft miss means "this tab can't serve the request, but another
      // matching tab might" — the graphql bridge's per-tab DocumentNode
      // cache is the only such case today. Keep walking rather than let one
      // stale tab shadow the tab that actually has what was asked for.
      if (isSoftMiss?.(response)) {
        if (firstSoftMiss === null) firstSoftMiss = { response, tabUrl };
        continue;
      }
      return { kind: 'response', response, tabUrl };
    } catch (e) {
      const msg = String(e);
      if (msg.includes('Receiving end does not exist')) {
        lastNoListener = msg;
        continue;
      }
      return { kind: 'throw', error: msg };
    }
  }
  if (firstSoftMiss !== null) {
    return {
      kind: 'response',
      response: firstSoftMiss.response,
      tabUrl: firstSoftMiss.tabUrl,
    };
  }
  return {
    kind: 'no-tab',
    error:
      `no tab matching ${tabUrlForError} has the fetchproxy content script loaded ` +
      `(${matches.length} URL match${matches.length === 1 ? '' : 'es'}, none responded). ` +
      `Reload that tab in your browser to inject the content script, then retry. ` +
      `This is the expected state right after the extension updates: Chrome removes the ` +
      `content script from tabs that were already open and does not replace it.` +
      (lastNoListener ? ` Last error: ${lastNoListener}` : ''),
  };
}
