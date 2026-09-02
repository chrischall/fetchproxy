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
