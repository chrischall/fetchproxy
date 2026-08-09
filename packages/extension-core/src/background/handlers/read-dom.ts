/**
 * `read_dom` verb handler plus its two pure gate helpers, moved verbatim out
 * of `background.ts`.
 *
 * `resolveReadDomRequest` and `readDomTabMatcher` are exported (and
 * re-exported from `background.ts`) because `tests/background.test.ts` pins
 * them directly — the gating logic is unit-testable without the module's live
 * WS/session state, which is the whole reason they were factored out.
 */

import type {
  DomSelectorDecl,
  InnerRequestReadDom,
} from '@fetchproxy/protocol';

import { isUrlAllowedForAnyDomain, isTabUrlOnOrigin } from '../../lib/url-match.js';
import { sendToFirstResponsiveTab } from '../../lib/send-to-responsive-tab.js';
import { sendInner } from '../send-inner.js';
import { mcpDomSelectors } from '../session-scope.js';

/**
 * Pure gate for a `read_dom` request. Mirrors the origin + declared-set
 * checks inlined in `handleReadIndexedDbRequest`, but factored out so the
 * gating logic is unit-testable without the module's live WS/session state.
 *
 * Returns the resolved DomSelectorDecls (in the request's `names` order) to
 * forward to the tab, or an `error` string (origin not allowed, or names not
 * in the declared set) to echo back to the MCP.
 */
export function resolveReadDomRequest(
  req: InnerRequestReadDom,
  declared: DomSelectorDecl[],
  domains: string[],
): { ok: true; selectors: DomSelectorDecl[] } | { ok: false; error: string } {
  if (!isUrlAllowedForAnyDomain(req.init.origin, domains)) {
    return {
      ok: false,
      error: `origin ${req.init.origin} not in domains [${domains.join(', ')}]`,
    };
  }
  const byName = new Map(declared.map((d) => [d.name, d]));
  const undeclared = req.init.names.filter((n) => !byName.has(n));
  if (undeclared.length > 0) {
    return {
      ok: false,
      error: `read_dom names not in declared set: ${undeclared.join(', ')}`,
    };
  }
  const selectors = req.init.names.map((n) => ({ ...byName.get(n)! }));
  return { ok: true, selectors };
}

/**
 * Tab-match predicate for a `read_dom` request. Host-or-subdomain
 * (`isTabUrlOnOrigin`), not strict-prefix (`isTabUrlMatch`) — a declared
 * apex origin (e.g. `https://example.com`) must still match a vendor
 * subdomain tab (e.g. `https://app.example.com/...`), the same rationale
 * that landed `isTabUrlOnOrigin` for the read_local_storage /
 * read_session_storage handlers. Factored out (mirrors
 * `resolveReadDomRequest`) so the choice of matcher is unit-testable
 * without the module's live WS/session state.
 */
export function readDomTabMatcher(origin: string): (tabUrl: string) => boolean {
  return (tabUrl: string) => isTabUrlOnOrigin(tabUrl, origin);
}

export async function handleReadDomRequest(
  mcpId: string,
  req: InnerRequestReadDom,
  domains: string[],
): Promise<void> {
  const declared = mcpDomSelectors.get(mcpId) ?? [];
  const gate = resolveReadDomRequest(req, declared, domains);
  if (!gate.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_dom',
      error: gate.error,
    });
    return;
  }
  const tabUrl = `${req.init.origin}/`;
  // 0.5.2+: multi-tab fallback via `sendToFirstResponsiveTab` — see the
  // helper's doc. Same rationale as the read_indexed_db path: a pre-reload
  // tab (no content script) can shadow a fresh one, and the user shouldn't
  // have to refresh every page after every extension update.
  //
  // Host-or-subdomain match (`readDomTabMatcher`/`isTabUrlOnOrigin`), not
  // strict-prefix (`isTabUrlMatch`) — see that helper's doc. A declared
  // apex origin routinely has its real tab on a vendor subdomain.
  const result = await sendToFirstResponsiveTab(
    readDomTabMatcher(req.init.origin),
    () => ({
      kind: 'fetchproxy-read-dom',
      selectors: gate.selectors.map((d) => ({ ...d })),
    }),
    tabUrl,
  );
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_dom',
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_dom',
      error: `tab read_dom failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as
    | { ok: true; values: Record<string, string> }
    | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'read_dom',
      values: resp.values,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_dom',
      error: resp.error,
    });
  }
}
