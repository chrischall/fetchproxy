/**
 * Per-mcpId session scope tables — the twelve `mcp*` maps the request
 * handler consults to gate every inbound verb, plus the functions that
 * marshal them. Moved verbatim out of `background.ts`.
 *
 * The maps were file-local `const`s; they are exported here (still the same
 * objects, mutated in place) so the socket, approval and handler modules all
 * read and write ONE set of tables. Never re-declare them elsewhere — a second
 * copy would silently split writer from reader and fail every gated verb.
 *
 * `clearAllSessionScopes` is the one piece of new code in this move: it
 * collects the twelve `.clear()` calls that were inlined in the WS `close`
 * handler, in the same order, so teardown cannot drift out of sync with a
 * future thirteenth map.
 */

import type {
  GraphqlOpDeclaration,
  IndexedDbScopeDecl,
  DomSelectorDecl,
  StoragePointerDecl,
} from '@fetchproxy/protocol';
import type { AnyPendingRecord } from './pending-records.js';

// Track each mcpId's declared domain set so the request handler can enforce
// the allowlist. 0.2.0+: this is a Map<mcpId, string[]> rather than the
// 0.1.x Map<mcpId, string> — every URL must match SOME entry to be allowed.
export const mcpDomains = new Map<string, string[]>();
// Track each mcpId's declared capability set so the request handler can
// reject verbs the MCP didn't ask for at pair time. 0.2.0+: defaults to
// ['fetch'] when the hello omits the field.
export const mcpCapabilities = new Map<string, string[]>();
// 0.3.0+: per-mcpId declared scope tables. Each verb checks its inbound
// request against the matching table, so a misdeclared MCP can't escalate
// to keys / headers it didn't ask for at pair time.
export const mcpCookieKeys = new Map<string, string[]>();
export const mcpLocalStorageKeys = new Map<string, string[]>();
export const mcpSessionStorageKeys = new Map<string, string[]>();
export const mcpCaptureHeaders = new Map<string, { host: string; path?: string; headerName: string }[]>();
// 0.4.0+: per-mcpId declared IndexedDB scopes. The request handler
// gates `read_indexed_db` on subset-match against this table.
export const mcpIndexedDbScopes = new Map<string, IndexedDbScopeDecl[]>();
// 1.4.0+: per-mcpId declared DOM selectors. The request handler gates
// `read_dom` on the declared name set against this table.
export const mcpDomSelectors = new Map<string, DomSelectorDecl[]>();
// 1.x+: per-mcpId declared GraphQL operations. The request handler gates
// `graphql_query` on the declared name set (name -> operationName) against
// this table.
export const mcpGraphqlOps = new Map<string, GraphqlOpDeclaration[]>();
// 0.4.0+: per-mcpId declared storage pointer decls. Storage-read
// handlers gate per-request pointer fields on these.
export const mcpLocalStoragePointers = new Map<string, { key: string; jsonPointer: string }[]>();
export const mcpSessionStoragePointers = new Map<string, { key: string; jsonPointer: string }[]>();
// Part 3: per-mcpId identity hash — set when a session is established
// (auto-trust or post-approval), cleared on session teardown. Used to
// expose the set of currently-connected identity hashes to the popup.
export const mcpIdentityHash = new Map<string, string>();

export function connectedIdentityHashes(): Set<string> {
  return new Set(
    [...mcpIdentityHash.values()].filter((h): h is string => !!h),
  );
}

/**
 * The per-mcpId scope tables that gate inbound request verbs — a snapshot of
 * the `mcp*` maps the request handler consults. Computed from an approved
 * record and applied to a LIVE session so a granted scope-update takes effect
 * immediately, with no reconnect.
 */
export interface GrantedSessionScope {
  capabilities: string[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: { host: string; path?: string; headerName: string }[];
  indexedDbScopes: IndexedDbScopeDecl[];
  domSelectors: DomSelectorDecl[];
  graphqlOps: GraphqlOpDeclaration[];
  localStoragePointers: StoragePointerDecl[];
  sessionStoragePointers: StoragePointerDecl[];
}

/**
 * Build the granted scope tables from an approved record. Capabilities default
 * to `['fetch']` (defensive — older popup state could omit them). Deep-copies
 * arrays so later mutation of the record can't alias the live maps.
 */
export function grantedScopeFromApproval(
  approved: AnyPendingRecord,
): GrantedSessionScope {
  return {
    capabilities:
      approved.capabilities && approved.capabilities.length > 0
        ? [...approved.capabilities]
        : ['fetch'],
    cookieKeys: [...(approved.cookieKeys ?? [])],
    localStorageKeys: [...(approved.localStorageKeys ?? [])],
    sessionStorageKeys: [...(approved.sessionStorageKeys ?? [])],
    captureHeaders: (approved.captureHeaders ?? []).map((d) => ({ ...d })),
    indexedDbScopes: (approved.indexedDbScopes ?? []).map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    })),
    domSelectors: (approved.domSelectors ?? []).map((d) => ({ ...d })),
    graphqlOps: (approved.graphqlOps ?? []).map((d) => ({ ...d })),
    localStoragePointers: (approved.localStoragePointers ?? []).map((d) => ({ ...d })),
    sessionStoragePointers: (approved.sessionStoragePointers ?? []).map((d) => ({ ...d })),
  };
}

/**
 * Write a granted scope onto the live per-mcpId maps the request handler reads.
 * Idempotent; overwrites any prior scope for `mcpId`. Used both at
 * session establishment (post-pair) and when a scope-update is granted on an
 * already-connected session — the latter is what makes a widened grant take
 * effect without a reconnect.
 */
export function applyGrantedScopeToSession(
  mcpId: string,
  scope: GrantedSessionScope,
): void {
  mcpCapabilities.set(mcpId, [...scope.capabilities]);
  mcpCookieKeys.set(mcpId, [...scope.cookieKeys]);
  mcpLocalStorageKeys.set(mcpId, [...scope.localStorageKeys]);
  mcpSessionStorageKeys.set(mcpId, [...scope.sessionStorageKeys]);
  mcpCaptureHeaders.set(mcpId, scope.captureHeaders.map((d) => ({ ...d })));
  mcpIndexedDbScopes.set(
    mcpId,
    scope.indexedDbScopes.map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    })),
  );
  mcpDomSelectors.set(mcpId, scope.domSelectors.map((d) => ({ ...d })));
  mcpGraphqlOps.set(mcpId, scope.graphqlOps.map((d) => ({ ...d })));
  mcpLocalStoragePointers.set(mcpId, scope.localStoragePointers.map((d) => ({ ...d })));
  mcpSessionStoragePointers.set(mcpId, scope.sessionStoragePointers.map((d) => ({ ...d })));
}

/**
 * Read back the live granted scope for `mcpId`, or `undefined` if no session
 * scope is recorded. Exported for tests + diagnostics.
 */
export function sessionScopeSnapshot(mcpId: string): GrantedSessionScope | undefined {
  const capabilities = mcpCapabilities.get(mcpId);
  if (!capabilities) return undefined;
  return {
    capabilities: [...capabilities],
    cookieKeys: [...(mcpCookieKeys.get(mcpId) ?? [])],
    localStorageKeys: [...(mcpLocalStorageKeys.get(mcpId) ?? [])],
    sessionStorageKeys: [...(mcpSessionStorageKeys.get(mcpId) ?? [])],
    captureHeaders: (mcpCaptureHeaders.get(mcpId) ?? []).map((d) => ({ ...d })),
    indexedDbScopes: (mcpIndexedDbScopes.get(mcpId) ?? []).map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    })),
    domSelectors: (mcpDomSelectors.get(mcpId) ?? []).map((d) => ({ ...d })),
    graphqlOps: (mcpGraphqlOps.get(mcpId) ?? []).map((d) => ({ ...d })),
    localStoragePointers: (mcpLocalStoragePointers.get(mcpId) ?? []).map((d) => ({ ...d })),
    sessionStoragePointers: (mcpSessionStoragePointers.get(mcpId) ?? []).map((d) => ({ ...d })),
  };
}

/**
 * Compute the live-scope applications for a granted approval. Only
 * `scope-update` records target already-connected sessions (a `pair` approval
 * establishes its sessions separately, with rekey + ReadyFrame). Filters to the
 * subset of the record's mcpIds that are currently live, so a session that
 * disconnected between the offer and the grant is skipped.
 */
export function liveScopeApplications(
  approved: AnyPendingRecord,
  isLive: (mcpId: string) => boolean,
): { mcpId: string; scope: GrantedSessionScope }[] {
  if (approved.kind !== 'scope-update') return [];
  const scope = grantedScopeFromApproval(approved);
  return (approved.mcpIds ?? [])
    .filter((mcpId) => isLive(mcpId))
    .map((mcpId) => ({ mcpId, scope }));
}

/** Part 3: notify any open popup that the connected-session set changed. */
export function broadcastConnectionsChanged(): void {
  const c = (globalThis as { chrome?: { runtime?: { sendMessage?: (m: unknown) => void } } }).chrome;
  try {
    c?.runtime?.sendMessage?.({ type: 'connections-changed' });
  } catch {
    // No listeners (popup closed) — ignore the error Chrome throws.
  }
}

/**
 * Clear every per-mcpId scope table. Called on WS teardown so a reconnect
 * cannot inherit a previous connection's granted scope.
 */
export function clearAllSessionScopes(): void {
  mcpDomains.clear();
  mcpCapabilities.clear();
  mcpCookieKeys.clear();
  mcpLocalStorageKeys.clear();
  mcpSessionStorageKeys.clear();
  mcpCaptureHeaders.clear();
  mcpIndexedDbScopes.clear();
  mcpDomSelectors.clear();
  mcpGraphqlOps.clear();
  mcpLocalStoragePointers.clear();
  mcpSessionStoragePointers.clear();
  // Part 3: clear identity hash map on teardown.
  mcpIdentityHash.clear();
}
