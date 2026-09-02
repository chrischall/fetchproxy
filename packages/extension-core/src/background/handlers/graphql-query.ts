/**
 * `graphql_query` verb handler plus its two pure gate helpers, moved verbatim
 * out of `background.ts`.
 *
 * The only handler that reads TWO scope Maps (`mcpGraphqlOps` and
 * `mcpCapabilities`). Its `'graphql'` capability re-check duplicates the gate
 * `handleRequest` already applied — dead-but-defensive, and kept as-is: it is
 * the second half of the one verb whose wire name (`graphql_query`) differs
 * from its capability name (`graphql`).
 */

import type {
  GraphqlOpDeclaration,
  InnerRequestGraphqlQuery,
} from '@fetchproxy/protocol';

import { isUrlAllowedForAnyDomain, isTabUrlOnOrigin } from '../../lib/url-match.js';
import { sendToFirstResponsiveTab } from '../../lib/send-to-responsive-tab.js';
import { isNotYetObservedError } from '../../lib/graphql-observed.js';
import { sendInner } from '../send-inner.js';
import { mcpCapabilities, mcpGraphqlOps } from '../session-scope.js';

/**
 * Pure gate for a `graphql_query` request. Mirrors `resolveReadDomRequest`,
 * but factored out so the gating logic is unit-testable without the module's
 * live WS/session state.
 *
 * Three checks, in order:
 *   1. the `'graphql'` capability is present for this mcpId,
 *   2. `req.init.name` resolves to a declared `graphqlOps[]` entry, and
 *   3. when a coarse `tabUrl` hint is supplied, it is on a declared domain
 *      (host-or-subdomain). When omitted, the extension picks a tab on ANY
 *      declared domain, so the domain restriction is enforced by the tab
 *      matcher (`graphqlTabMatcher`) instead.
 *
 * Returns the resolved `operationName` (the DocumentNode handle the page
 * owns) to forward to the tab, or an `error` string to echo back to the MCP.
 */
export function resolveGraphqlQueryRequest(
  req: InnerRequestGraphqlQuery,
  capabilities: string[],
  declared: GraphqlOpDeclaration[],
  domains: string[],
): { ok: true; operationName: string } | { ok: false; error: string } {
  if (!capabilities.includes('graphql')) {
    return {
      ok: false,
      error: `capability "graphql" not granted (declared: [${capabilities.join(', ')}])`,
    };
  }
  const byName = new Map(declared.map((d) => [d.name, d]));
  const match = byName.get(req.init.name);
  if (!match) {
    return {
      ok: false,
      error: `graphql_query name not in declared graphqlOps: ${req.init.name}`,
    };
  }
  if (req.init.tabUrl !== undefined && !isUrlAllowedForAnyDomain(req.init.tabUrl, domains)) {
    return {
      ok: false,
      error: `tabUrl ${req.init.tabUrl} not in domains [${domains.join(', ')}]`,
    };
  }
  return { ok: true, operationName: match.operationName };
}

/**
 * Tab-match predicate for a `graphql_query` request. Host-or-subdomain
 * (`isTabUrlOnOrigin`), mirroring `readDomTabMatcher`. When the MCP supplied a
 * coarse `tabUrl` hint, match tabs on that host (or a subdomain of it). When it
 * didn't, match any tab on a declared domain — the query runs through whatever
 * tab's Apollo client already owns the operation. Factored out so the choice of
 * matcher is unit-testable without the module's live WS/session state.
 */
export function graphqlTabMatcher(
  tabUrl: string | undefined,
  domains: string[],
): (candidateTabUrl: string) => boolean {
  if (tabUrl !== undefined) {
    return (candidateTabUrl: string) => isTabUrlOnOrigin(candidateTabUrl, tabUrl);
  }
  return (candidateTabUrl: string) => isUrlAllowedForAnyDomain(candidateTabUrl, domains);
}

/**
 * A tab's response that means "not this tab — try another", as opposed to a
 * real answer. The Apollo DocumentNode cache is per-tab, so a tab that never
 * fired the operation misses while a sibling tab on the same origin has it.
 *
 * Without this, the first matching tab in `chrome.tabs.query` order decides
 * the outcome for every call: a dashboard or confirmation tab left open ahead
 * of the restaurant tab shadows it permanently, and no amount of reloading the
 * *right* page helps, because that page is never asked.
 */
function isGraphqlSoftMiss(response: unknown): boolean {
  if (!response || typeof response !== 'object') return false;
  const r = response as { ok?: unknown; error?: unknown };
  return r.ok === false && isNotYetObservedError(r.error);
}

export async function handleGraphqlQueryRequest(
  mcpId: string,
  req: InnerRequestGraphqlQuery,
  domains: string[],
): Promise<void> {
  const declared = mcpGraphqlOps.get(mcpId) ?? [];
  const capabilities = mcpCapabilities.get(mcpId) ?? ['fetch'];
  const gate = resolveGraphqlQueryRequest(req, capabilities, declared, domains);
  if (!gate.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'graphql_query',
      error: gate.error,
    });
    return;
  }
  const tabUrlForError = req.init.tabUrl ?? `domains [${domains.join(', ')}]`;
  // 0.5.2+: multi-tab fallback via `sendToFirstResponsiveTab` — see the
  // helper's doc. Host-or-subdomain match (`graphqlTabMatcher`), not strict
  // prefix, for the same reason the read_dom path uses it. The relay carries
  // the extension-resolved `operationName` (never the raw declared `name`);
  // the MAIN-world Apollo bridge reuses the page's cached DocumentNode for it.
  const result = await sendToFirstResponsiveTab(
    graphqlTabMatcher(req.init.tabUrl, domains),
    (matchedTabUrl) => ({
      kind: 'fetchproxy-graphql-query',
      init: {
        operationName: gate.operationName,
        variables: req.init.variables,
        tabUrl: matchedTabUrl,
      },
    }),
    tabUrlForError,
    isGraphqlSoftMiss,
  );
  if (result.kind === 'no-tab') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'graphql_query',
      error: result.error,
    });
    return;
  }
  if (result.kind === 'throw') {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'graphql_query',
      error: `tab graphql_query failed: ${result.error}`,
    });
    return;
  }
  const resp = result.response as
    | { ok: true; data: unknown }
    | { ok: false; error: string };
  if (resp.ok) {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'graphql_query',
      data: resp.data,
    });
  } else {
    await sendInner(mcpId, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'graphql_query',
      error: resp.error,
    });
  }
}
