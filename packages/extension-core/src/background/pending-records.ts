/**
 * Shapes of the records queued in `chrome.storage.local` for the popup,
 * plus `applyNeedsPairRecord`, moved verbatim out of `background.ts`.
 *
 * `PendingRecordBase`, `PendingPairRecord` and `PendingScopeUpdateRecord`
 * were file-local; they are exported here because `background.ts` still
 * constructs both record kinds.
 */

import type {
  GraphqlOpDeclaration,
  IndexedDbScopeDecl,
  DomSelectorDecl,
  StoragePointerDecl,
} from '@fetchproxy/protocol';

/**
 * Shared fields for all pending record kinds.
 * keyed by `${identityHash}:${scopeHash}` in `chrome.storage.local`.
 */
export interface PendingRecordBase {
  /** `${identityHash}:${scopeHash}` — dict key. */
  key: string;
  identityHash: string;
  serverName: string;
  version: string;
  /** All MCP process IDs associated with this entry. */
  mcpIds: string[];
  domains: string[];
  identityX25519Pub: string;
  identityEd25519Pub: string;
}

/**
 * 0.6.0+: pending PAIR record. The MCP is not yet connected — the user
 * must approve before any session is established.
 *
 * Replacing the old `mcpId`-keyed shape so that concurrent processes sharing
 * the same identity + scope collapse into a single user-visible approval prompt.
 * The `mcpIds` array tracks every process waiting on this entry; `sessionNonces`
 * maps each process's nonce so the approval handler can drive per-process ECDH.
 */
export interface PendingPairRecord extends PendingRecordBase {
  kind: 'pair';
  /**
   * Per-process hello nonce (b64). Used in session-key derivation after
   * approval. Each process sends its own hello with its own nonce.
   */
  sessionNonces: Record<string, string>;
  capabilities: string[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: { host: string; path?: string; headerName: string }[];
  /** 0.4.0+: declared IndexedDB scopes the user is being asked to approve. */
  indexedDbScopes: IndexedDbScopeDecl[];
  /** 1.4.0+: declared DOM selectors the user is being asked to approve. */
  domSelectors: DomSelectorDecl[];
  /** 1.x+: declared GraphQL operations the user is being asked to approve. */
  graphqlOps: GraphqlOpDeclaration[];
  /** 0.4.0+: declared storage-pointer extractions. */
  localStoragePointers: StoragePointerDecl[];
  sessionStoragePointers: StoragePointerDecl[];
  /**
   * 0.4.0+: previously approved scope (only present on re-pair).
   * Popup renders the diff vs the new scope.
   */
  previousScope?: {
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
  };
  pairCode: string;
}

/**
 * Part 2: non-blocking scope-update record. The MCP is already connected
 * (session live, granted = approved ∩ declared). This offers the user a
 * chance to widen the approved scope to cover the new declaration.
 *
 * [Grant] → trust.put with declared scope; no session restart needed.
 * [Keep as is] → dismiss: remove this entry, record the dismissed scopeHash
 *   so the same declared scope does not re-queue until it changes again.
 */
export interface PendingScopeUpdateRecord extends PendingRecordBase {
  kind: 'scope-update';
  /** The FULL declared scope (what the MCP now wants). */
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
  /** The previously approved scope shown as the diff baseline. */
  previousScope: {
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
  };
}

export type AnyPendingRecord = PendingPairRecord | PendingScopeUpdateRecord;

/**
 * Apply a needs-pair record to a pending dict.
 *
 * Three cases:
 *  1. Key is occupied by another `pair` entry → collapse (dedup mcpId).
 *  2. Key is unoccupied → create a new `pair` entry.
 *  3. Key is occupied by a `scope-update` entry → the needs-pair supersedes it:
 *     trust is gone, so the scope-update offer is moot. Replace with a `pair`
 *     entry, unioning the mcpIds so every waiting process gets unblocked.
 *
 * Exported for unit testing; production callers use `onServerHello`.
 *
 * @internal
 */
export function applyNeedsPairRecord(
  existing: Record<string, AnyPendingRecord>,
  pendingKey: string,
  newRecord: PendingPairRecord,
): void {
  const currentEntry = existing[pendingKey];
  if (currentEntry && currentEntry.kind === 'pair') {
    // Case 1: Collapse — add this mcpId to the waiting set (dedup).
    const mcpId = newRecord.mcpIds[0]!;
    const nonce = newRecord.sessionNonces[mcpId]!;
    if (!currentEntry.mcpIds.includes(mcpId)) {
      currentEntry.mcpIds.push(mcpId);
    }
    currentEntry.sessionNonces[mcpId] = nonce;
  } else if (!currentEntry) {
    // Case 2: New entry.
    existing[pendingKey] = newRecord;
  } else {
    // Case 3: A scope-update sits at this key. The needs-pair supersedes it —
    // trust has been revoked, so the non-blocking scope-update offer is moot.
    // Replace with the pair record, unioning the mcpIds so every process
    // waiting on this identity (including those that drove the scope-update)
    // gets a prompt on the next approval.
    const inherited = currentEntry.mcpIds.filter((id) => !newRecord.mcpIds.includes(id));
    const mergedRecord: PendingPairRecord = {
      ...newRecord,
      mcpIds: [...inherited, ...newRecord.mcpIds],
    };
    // Carry over any session nonces already recorded for the inherited mcpIds.
    // (scope-update records don't have sessionNonces, so nothing to copy —
    // the inherited mcpIds will just be missing nonces, which is safe: the
    // approval handler skips mcpIds with missing nonces gracefully.)
    existing[pendingKey] = mergedRecord;
  }
}
