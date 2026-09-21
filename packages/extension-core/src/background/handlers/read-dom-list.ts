/**
 * `read_dom_list` verb handler plus its two pure gate helpers. Mirrors
 * `read-dom.ts`'s shape exactly — same gating structure, same tab-matcher —
 * widened from a single named `querySelector` to a named
 * `querySelectorAll(itemSelector)` + per-item field map.
 *
 * `resolveReadDomListRequest` and `readDomListTabMatcher` are exported (and
 * would be re-exported from `background.ts` the same way `read-dom.ts`'s are)
 * because the gating logic is unit-testable without the module's live
 * WS/session state, which is the whole reason they are factored out.
 */

import type {
  DomListSelectorDecl,
  InnerRequestReadDomList,
} from '@fetchproxy/protocol';

import { isUrlAllowedForAnyDomain, isTabUrlOnOrigin } from '../../lib/url-match.js';
import { sendToFirstResponsiveTab } from '../../lib/send-to-responsive-tab.js';
import { sendInner } from '../send-inner.js';
import { mcpDomListSelectors } from '../session-scope.js';

/**
 * Pure gate for a `read_dom_list` request. Mirrors `resolveReadDomRequest`:
 * the origin + declared-set checks, factored out so the gating logic is
 * unit-testable without the module's live WS/session state.
 *
 * Returns the resolved `DomListSelectorDecl` to forward to the tab, or an
 * `error` string (origin not allowed, or name not in the declared set) to
 * echo back to the MCP.
 */
export function resolveReadDomListRequest(
  req: InnerRequestReadDomList,
  declared: DomListSelectorDecl[],
  domains: string[],
): { ok: true; selector: DomListSelectorDecl } | { ok: false; error: string } {
  if (!isUrlAllowedForAnyDomain(req.init.origin, domains)) {
    return {
      ok: false,
      error: `origin ${req.init.origin} not in domains [${domains.join(', ')}]`,
    };
  }
  const found = declared.find((d) => d.name === req.init.name);
  if (!found) {
    return {
      ok: false,
      error: `read_dom_list name not in declared set: ${req.init.name}`,
    };
  }
  return { ok: true, selector: { ...found, fields: found.fields.map((f) => ({ ...f })) } };
}

/**
 * Tab-match predicate for a `read_dom_list` request. Host-or-subdomain
 * (`isTabUrlOnOrigin`), same rationale as `readDomTabMatcher`.
 */
export function readDomListTabMatcher(origin: string): (tabUrl: string) => boolean {
  return (tabUrl: string) => isTabUrlOnOrigin(tabUrl, origin);
}

export async function handleReadDomListRequest(
  mcpId: string,
  req: InnerRequestReadDomList,
  domains: string[],
): Promise<void> {
  const declared = mcpDomListSelectors.get(mcpId) ?? [];
  const gate = resolveReadDomListRequest(req, declared, domains);
  if (!gate.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_dom_list',
      error: gate.error,
    });
    return;
  }
  const tabUrl = `${req.init.origin}/`;
  // Same multi-tab fallback + host-or-subdomain match rationale as
  // `handleReadDomRequest` — see that function's doc.
  const result = await sendToFirstResponsiveTab(
    readDomListTabMatcher(req.init.origin),
    () => ({
      kind: 'fetchproxy-read-dom-list',
      selector: { ...gate.selector, fields: gate.selector.fields.map((f) => ({ ...f })) },
    }),
    tabUrl,
  );
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_dom_list',
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_dom_list',
      error: `tab read_dom_list failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as
    | { ok: true; rows: Record<string, string>[] }
    | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'read_dom_list',
      rows: resp.rows,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'read_dom_list',
      error: resp.error,
    });
  }
}
