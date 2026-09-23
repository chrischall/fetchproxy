/**
 * `fetch` verb handler, moved verbatim out of `background.ts`.
 *
 * Long the simplest handler: `domains` arrives as a parameter and it makes
 * no direct `chrome.*` call. It now reads ONE scope Map — `mcpCapabilities`,
 * to gate `init.inPage` — because that flag is a privilege decision and the
 * only authority on which MCP holds it is the approved capability set. Its
 * dependencies still point strictly downward: `sendInner` (L2), the scope
 * tables, and two leaf helpers under `src/lib/`.
 */

import type { InnerRequestFetch } from '@fetchproxy/protocol';

import { isUrlAllowedForAnyDomain, isTabUrlMatch } from '../../lib/url-match.js';
import { isCsrfSoftMiss, prefersCsrfTab } from '../../lib/csrf-soft-miss.js';
import { sendToFirstResponsiveTab } from '../../lib/send-to-responsive-tab.js';
import { sendInner } from '../send-inner.js';
import { mcpCapabilities } from '../session-scope.js';

export async function handleFetchRequest(
  mcpId: string,
  req: InnerRequestFetch,
  domains: string[],
): Promise<void> {
  // `inPage` runs the request in the page's MAIN world, where page script can
  // observe and patch `window.fetch`. Refuse it here — before the request
  // reaches a tab — for any MCP that didn't declare `fetch_in_page` and have
  // it approved at pair time. `inPage: false` is just an ordinary fetch and
  // needs nothing.
  if (req.init.inPage === true) {
    const capabilities = mcpCapabilities.get(mcpId) ?? ['fetch'];
    if (!capabilities.includes('fetch_in_page')) {
      await sendInner(mcpId, {
        type: 'response',
        id: req.id,
        ok: false,
        op: 'fetch',
        error:
          'init.inPage requires the "fetch_in_page" capability ' +
          `(declared: [${capabilities.join(', ')}])`,
      });
      return;
    }
  }
  if (!isUrlAllowedForAnyDomain(req.init.url, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      error: `url ${req.init.url} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  // The relay tab is scoped exactly like the request URL (and like
  // graphql_query's / legacy read_cookies' tabUrl). Without this, a paired
  // MCP could name ANY open tab — the user's bank — to perform its request,
  // and that tab's content script would attach the page's CSRF token. The
  // `viaTab` guard in @fetchproxy/server runs in the MCP's own process, so
  // it cannot be the enforcement point. Checking the tab against the
  // declared domains also keeps CSRF injection declared-domain scoped while
  // leaving the api.example.com-through-www.example.com pattern intact.
  if (!isUrlAllowedForAnyDomain(req.init.tabUrl, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      error: `tabUrl ${req.init.tabUrl} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  // 0.5.2+: iterate ALL matching tabs instead of `.find()`-ing the first
  // one. Chrome doesn't retroactively inject content scripts into pages
  // that were already loaded when the extension was (re)installed —
  // those tabs match the URL but `sendMessage` to them throws "Receiving
  // end does not exist". Before this loop, the first such pre-reload tab
  // returned by `chrome.tabs.query` would shadow any subsequent
  // freshly-loaded tab that DOES have the content script, and every
  // fetch failed even though a working tab existed.
  //
  // #286: a write additionally prefers a tab that can inject `x-csrf-token`.
  // First pass asks every matching tab with `requireCsrf`; a tab with no
  // token soft-misses and the walk continues. Only if EVERY tab misses (the
  // site exposes no `__CSRF_TOKEN__` at all) does the second pass re-send
  // without the marker, so the first responsive tab serves it as before.
  // GETs skip both — they never need the header.
  //
  // The marker is the background's decision alone. `validateInnerRequest`'s
  // fetch branch doesn't reject unknown `init` keys, so a hand-crafted wire
  // frame could carry its own `requireCsrf`; strip it here so neither a GET
  // nor the no-marker fallback pass can inherit it.
  const { requireCsrf: _inbound, ...init } = req.init as typeof req.init & {
    requireCsrf?: unknown;
  };
  void _inbound;
  const matcher = (tabUrl: string): boolean => isTabUrlMatch(tabUrl, init.tabUrl);
  const build =
    (requireCsrf: boolean) =>
    (tabUrl: string): unknown => ({
      kind: 'fetchproxy-fetch',
      init: { ...init, tabUrl, ...(requireCsrf ? { requireCsrf: true } : {}) },
    });
  const preferCsrf = prefersCsrfTab(init.method);
  let result = await sendToFirstResponsiveTab(
    matcher,
    build(preferCsrf),
    init.tabUrl,
    preferCsrf ? isCsrfSoftMiss : undefined,
  );
  if (preferCsrf && result.kind === 'response' && isCsrfSoftMiss(result.response)) {
    result = await sendToFirstResponsiveTab(matcher, build(false), init.tabUrl);
  }
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      error: `tab fetch failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as
    | { ok: true; status: number; url: string; body: string }
    | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'fetch',
      status: resp.status,
      url: resp.url,
      body: resp.body,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      error: resp.error,
    });
  }
}
