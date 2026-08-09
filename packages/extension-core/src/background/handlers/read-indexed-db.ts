/**
 * `read_indexed_db` verb handler, moved verbatim out of `background.ts`.
 *
 * Unlike `read_dom` and `graphql_query`, this verb's gate is still INLINED in
 * the handler rather than factored into a pure `resolve*` helper. That stays
 * as-is here: extracting one would be a behaviour-risking change, not a move.
 *
 * It is also the only tab-relay verb that matches its target tab with
 * strict-prefix `isTabUrlMatch` rather than origin-level `isTabUrlOnOrigin`.
 */

import type { InnerRequestReadIndexedDb } from '@fetchproxy/protocol';

import { isUrlAllowedForAnyDomain, isTabUrlMatch } from '../../lib/url-match.js';
import { sendToFirstResponsiveTab } from '../../lib/send-to-responsive-tab.js';
import { sendInner } from '../send-inner.js';
import { mcpIndexedDbScopes } from '../session-scope.js';

export async function handleReadIndexedDbRequest(
  mcpId: string,
  req: InnerRequestReadIndexedDb,
  domains: string[],
): Promise<void> {
  const declared = mcpIndexedDbScopes.get(mcpId) ?? [];
  if (!isUrlAllowedForAnyDomain(req.init.origin, domains)) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: `origin ${req.init.origin} not in domains [${domains.join(', ')}]`,
    });
    return;
  }
  // Find a matching scope: same origin, database, store. Then check
  // requested keys ⊆ declared keys.
  const scope = declared.find(
    (d) =>
      d.origin === req.init.origin &&
      d.database === req.init.database &&
      d.store === req.init.store,
  );
  if (!scope) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: `(origin, database, store) not in declared indexedDbScopes`,
    });
    return;
  }
  const declaredSet = new Set(scope.keys);
  const undeclared = req.init.keys.filter((k) => !declaredSet.has(k));
  if (undeclared.length > 0) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: `IndexedDB keys not in declared set: ${undeclared.join(', ')}`,
    });
    return;
  }
  const tabUrl = `${req.init.origin}/`;
  // 0.5.2+: multi-tab fallback via `sendToFirstResponsiveTab` — see the
  // helper's doc. Same rationale as the fetch path: a pre-reload tab
  // (no content script) can shadow a fresh one, and the user shouldn't
  // have to refresh every page after every extension update.
  const result = await sendToFirstResponsiveTab(
    (t) => isTabUrlMatch(t, tabUrl),
    () => ({
      kind: 'fetchproxy-read-indexed-db',
      database: req.init.database,
      store: req.init.store,
      keys: [...req.init.keys],
    }),
    tabUrl,
  );
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: `tab read_indexed_db failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as
    | { ok: true; values: Record<string, unknown> }
    | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'read_indexed_db',
      values: resp.values,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_indexed_db',
      error: resp.error,
    });
  }
}
