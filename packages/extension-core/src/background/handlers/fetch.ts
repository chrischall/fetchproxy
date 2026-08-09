/**
 * `fetch` verb handler, moved verbatim out of `background.ts`.
 *
 * The first handler to be split out, and deliberately the simplest one:
 * it reads no per-session scope Map (`domains` arrives as a parameter) and
 * makes no direct `chrome.*` call, so it needs neither `session-scope.ts`
 * nor a chrome declaration. Its only dependencies point strictly downward —
 * `sendInner` (L2) and two leaf helpers under `src/lib/` — which is the
 * shape every subsequent handler module follows.
 */

import type { InnerRequestFetch } from '@fetchproxy/protocol';

import { isUrlAllowedForAnyDomain, isTabUrlMatch } from '../../lib/url-match.js';
import { sendToFirstResponsiveTab } from '../../lib/send-to-responsive-tab.js';
import { sendInner } from '../send-inner.js';

export async function handleFetchRequest(
  mcpId: string,
  req: InnerRequestFetch,
  domains: string[],
): Promise<void> {
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
  // 0.5.2+: iterate ALL matching tabs instead of `.find()`-ing the first
  // one. Chrome doesn't retroactively inject content scripts into pages
  // that were already loaded when the extension was (re)installed —
  // those tabs match the URL but `sendMessage` to them throws "Receiving
  // end does not exist". Before this loop, the first such pre-reload tab
  // returned by `chrome.tabs.query` would shadow any subsequent
  // freshly-loaded tab that DOES have the content script, and every
  // fetch failed even though a working tab existed.
  const result = await sendToFirstResponsiveTab(
    (tabUrl) => isTabUrlMatch(tabUrl, req.init.tabUrl),
    (tabUrl) => ({
      kind: 'fetchproxy-fetch',
      init: { ...req.init, tabUrl },
    }),
    req.init.tabUrl,
  );
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
