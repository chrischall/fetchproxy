/**
 * `sendToFirstResponsiveTab` — the multi-tab content-script fan-out,
 * moved verbatim out of `background.ts`.
 *
 * It lives under `src/lib/` rather than beside any one handler because it
 * has six callers spread across every tab-driven verb (fetch, legacy
 * read_cookies, read_storage, read_indexed_db, read_dom, graphql_query).
 * It holds no module state of its own and reaches nothing but `chrome.tabs`
 * and the cold-open registry, so it stays a leaf: importable from any handler
 * without creating an edge between them, and — this is the reason the registry
 * is its own module rather than a function on `ensure-domain-tab.ts` — without
 * an edge to the code that opens tabs either.
 */

import type { ChromeApi } from '../chrome-api.js';
import { coldOpenInFlight, coldOpenTiming } from './cold-open.js';

declare const chrome: ChromeApi;

/** Wait, in a form that does not need `chrome.alarms` or a timer permission. */
function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * The one wording that says a tab for this host is arriving.
 *
 * It keeps the `no tab matching ` prefix on purpose. `@fetchproxy/server`
 * routes extension rejections to a typed error by matching that prefix, and an
 * older server than the extension is the normal state of a browser add-on the
 * person updates on their own schedule — so a message that dropped the prefix
 * would be classified `protocol` and answered with "extension/server version
 * mismatch, update both", which is #204's failure exactly. Current servers tell
 * this apart by the `one is still opening` marker, the same way they tell the
 * unreachable-content-script variant apart by its own.
 */
/**
 * One pass's outcome plus how many tabs matched by URL.
 *
 * The count is what makes the cold-open substitution safe (#293). A miss with
 * matches is the "a tab is there and its content script never answered"
 * state — fixed by RELOADING the page, and routed by `@fetchproxy/server` to
 * `content_script_unreachable`, which is what arms its lazy-revive retry.
 * Overwriting that with the cold-open wording drops the remedy and takes the
 * request off that path, so only a miss with ZERO matches may be reworded.
 */
interface Attempt {
  result: SendToFirstResponsiveTabResult;
  urlMatches: number;
}

function stillOpeningError(tabUrlForError: string): string {
  return (
    `no tab matching ${tabUrlForError} answered yet — one is still opening. ` +
    `The extension opened it moments ago and it has not finished loading; ` +
    `retry in a few seconds rather than opening one yourself.`
  );
}

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
  let last = await attemptSend(matcher, buildMessage, tabUrlForError, isSoftMiss);
  // Only a miss is worth a second look, and only while a tab that could serve
  // THIS host is still loading. Both guards matter: without the first, every
  // answered request pays a registry check it cannot benefit from; without the
  // second, a request for a host nobody is opening waits out the whole budget
  // to reach the same answer it already had.
  if (last.result.kind !== 'no-tab') return last.result;
  if (!(await coldOpenInFlight(tabUrlForError))) return last.result;

  const { budgetMs, pollMs } = coldOpenTiming();
  const deadline = Date.now() + budgetMs;
  for (;;) {
    if (Date.now() >= deadline) {
      // Reworded only where nothing matched by URL. With matches, the miss is
      // the unreachable-content-script one, which carries its own remedy and
      // its own server-side handling.
      return last.urlMatches === 0
        ? { kind: 'no-tab', error: stillOpeningError(tabUrlForError) }
        : last.result;
    }
    await delay(pollMs);
    last = await attemptSend(matcher, buildMessage, tabUrlForError, isSoftMiss);
    if (last.result.kind !== 'no-tab') return last.result;
    // The open settled and this host still has nothing: "open a tab on that
    // host" is once again the true remedy, so hand back the ordinary wording
    // rather than blaming a load that has finished.
    if (!(await coldOpenInFlight(tabUrlForError))) return last.result;
  }
}

/** One pass over the currently open tabs. The retry above calls it repeatedly. */
async function attemptSend(
  matcher: (tabUrl: string) => boolean,
  buildMessage: (matchedTabUrl: string) => unknown,
  tabUrlForError: string,
  isSoftMiss?: (response: unknown) => boolean,
): Promise<Attempt> {
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
    return { result: { kind: 'no-tab', error: `no tab matching ${tabUrlForError}` }, urlMatches: 0 };
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
      return { result: { kind: 'response', response, tabUrl }, urlMatches: matches.length };
    } catch (e) {
      const msg = String(e);
      if (msg.includes('Receiving end does not exist')) {
        lastNoListener = msg;
        continue;
      }
      return { result: { kind: 'throw', error: msg }, urlMatches: matches.length };
    }
  }
  if (firstSoftMiss !== null) {
    return {
      result: {
        kind: 'response',
        response: firstSoftMiss.response,
        tabUrl: firstSoftMiss.tabUrl,
      },
      urlMatches: matches.length,
    };
  }
  return {
    result: {
      kind: 'no-tab',
      error:
        `no tab matching ${tabUrlForError} has the fetchproxy content script loaded ` +
        `(${matches.length} URL match${matches.length === 1 ? '' : 'es'}, none responded). ` +
        `Reload that tab in your browser to inject the content script, then retry. ` +
        `This is the expected state right after the extension updates: Chrome removes the ` +
        `content script from tabs that were already open and does not replace it.` +
        (lastNoListener ? ` Last error: ${lastNoListener}` : ''),
    },
    urlMatches: matches.length,
  };
}
