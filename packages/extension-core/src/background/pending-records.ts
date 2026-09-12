/**
 * Shapes of the records queued in `chrome.storage.local` for the popup,
 * plus `applyNeedsPairRecord`, moved verbatim out of `background.ts`.
 *
 * `PendingPairRecord` and `PendingScopeUpdateRecord` are exported because
 * `server-hello.ts` constructs both record kinds. `PendingRecordBase` is only
 * the `extends` base of those two, so it stays file-local as it was before
 * the split — a type does not need `export` to be reachable through the
 * exported interfaces that extend it.
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
interface PendingRecordBase {
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
  /**
   * 3.0.0+ (protocol 4): per-process MCP session EPHEMERAL pub (b64), beside
   * the nonce and refreshed with it.
   *
   * The approval path answers a hello it read back out of storage, minutes
   * after it arrived. Under v3 a stored record sufficed because the MCP's half
   * of the ECDH was its long-term `identityX25519Pub`; under v4 it is this
   * per-session value, so it has to be stored or the approval has nothing to
   * derive against. Refreshing it on every hello is what keeps a record from
   * naming a superseded ephemeral after a reconnect — and an entry with no
   * value here is SKIPPED rather than falling back to the identity key, which
   * would be the v3 derivation reinstated under a v4 signature.
   */
  sessionPubs: Record<string, string>;
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
  /**
   * The code the user compares against the MCP's own.
   *
   * 3.0.0 (protocol 4): per HELLO, not per identity — it commits to both hello
   * nonces and the MCP's session ephemeral ({@link pairTranscript}) — so it is
   * refreshed on every collapse, and a record covering several mcpIds holds
   * the most recent hello's number rather than one they all share.
   */
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
    // 3.0.0: the ephemeral moves with the nonce. A record that kept the FIRST
    // hello's pub and the SECOND hello's nonce would derive a key nothing
    // holds, which is the same failure as not storing it at all.
    const sessionPub = newRecord.sessionPubs[mcpId];
    if (sessionPub !== undefined) {
      currentEntry.sessionPubs = { ...(currentEntry.sessionPubs ?? {}), [mcpId]: sessionPub };
    }
    // 3.0.0 (protocol 4): so does the pair code. It commits to the two hello
    // nonces and the MCP's ephemeral, so it CHANGES on every re-hello where
    // v3's — over two long-term identity pubs — changed never, and the frame
    // this collapse answers carries the FRESH number to the MCP. A record
    // keeping the first hello's code would put a stale number on the screen
    // the user is asked to compare against the MCP's, and the one thing a SAS
    // must never manufacture is a false mismatch. This is scalar where the
    // two above are keyed by mcpId, so what it holds is the most recent
    // hello's code: several PROCESSES sharing one identity and scope collapse
    // into this one record and no longer share one number, which is inherent
    // to a per-session code and is why the popup shows the latest.
    currentEntry.pairCode = newRecord.pairCode;
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
