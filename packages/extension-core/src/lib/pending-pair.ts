/**
 * Shared normalisation for the `pendingPair` value stored in
 * `chrome.storage.local`. The shape evolved across versions:
 *
 *   - 0.5.1 and earlier wrote a single `PendingPairRecord` (object with
 *     a top-level `mcpId` field).
 *   - 0.5.2+ writes a `Record<mcpId, PendingPairRecord>` dict so multiple
 *     simultaneous unpaired MCPs can queue without overwriting each other.
 *   - 0.6.0+ (multi-instance pairing) keys the dict by
 *     `${identityHash}:${scopeHash}` (the `key` field) and carries an
 *     `mcpIds: string[]` array instead of a singular `mcpId`. Each entry
 *     represents all concurrent processes sharing the same identity and
 *     scope — the user approves once and all waiting processes are unblocked.
 *
 * Both the service-worker (background.ts) and the popup (popup.ts) read
 * this value and need to handle the same input set identically — if the
 * two contexts disagreed on what counts as a malformed record, one could
 * silently render an entry the other refuses to act on. This helper is
 * the single source of truth; callers in either context must use it.
 *
 * Returns an empty dict for any unrecognised input (null, undefined,
 * non-object, or an object whose entries can't be normalised). The dict
 * is keyed by the `key` field of each new-shape record. Legacy entries
 * (with `mcpId` but no `key`) are migrated on a best-effort basis: if a
 * `identityHash` field is present the key is synthesised as
 * `${identityHash}:legacy`; if not, the entry is dropped silently
 * (a dropped stale pending is non-destructive — the next MCP reconnect
 * triggers a fresh pair flow).
 *
 * Generic over the record type so this file has no dependency on the
 * specific `PendingPairRecord` shape each caller defines — the only
 * invariants we enforce are:
 *   - New-shape:    entry has `key: string` and `mcpIds: string[]`
 *   - Legacy-shape: entry has `mcpId: string` (no `key`)
 */
export function normalisePendingPair<T extends { key: string; mcpIds: string[] }>(
  stored: unknown,
): Record<string, T> {
  if (!stored || typeof stored !== 'object') return {};
  const obj = stored as Record<string, unknown>;

  // ---------------------------------------------------------------------------
  // Legacy single-record shape (pre-0.5.2): a flat object with its own `mcpId`
  // and no `key` field.  Migrate it to a best-effort new-shape entry so the
  // popup / background can handle it uniformly.
  // ---------------------------------------------------------------------------
  if (typeof (obj as { mcpId?: unknown }).mcpId === 'string' &&
      typeof (obj as { key?: unknown }).key !== 'string') {
    return migrateFromLegacySingle(obj) as Record<string, T>;
  }

  // ---------------------------------------------------------------------------
  // Dict shape: walk entries, keep ones that look like valid records, migrate
  // legacy 0.5.2 (mcpId-keyed, no `key`) entries inline.
  // ---------------------------------------------------------------------------
  const out: Record<string, T> = {};
  for (const [, v] of Object.entries(obj)) {
    if (!v || typeof v !== 'object') continue;
    const rec = v as Record<string, unknown>;

    if (typeof rec.key === 'string' && Array.isArray(rec.mcpIds)) {
      // New-shape (0.6.0+) — key is the authoritative dict key.
      out[rec.key] = v as T;
    } else if (typeof rec.mcpId === 'string' && typeof rec.key !== 'string') {
      // Legacy 0.5.2 shape — mcpId-keyed dict entry. Migrate.
      const migrated = migrateFromLegacySingle(rec);
      for (const [k, r] of Object.entries(migrated)) {
        out[k] = r as T;
      }
    }
    // Anything else: drop silently.
  }
  return out;
}

/**
 * Migrate a legacy single-record object (has `mcpId: string`, no `key`) to
 * a new-shape entry. Returns a one-entry dict keyed by the derived key, or
 * an empty dict if the entry is too corrupt to migrate safely.
 *
 * The derived key is:
 *   - `${identityHash}:legacy` if `identityHash` is present (best-effort)
 *   - dropped otherwise
 *
 * We carry `mcpIds: [mcpId]` and `sessionNonces: { [mcpId]: sessionNonceB64 }`
 * forward so the approval path can still drive session setup. All other fields
 * are forwarded as-is.
 */
function migrateFromLegacySingle(
  rec: Record<string, unknown>,
): Record<string, unknown> {
  const mcpId = rec.mcpId as string;
  const identityHash = typeof rec.identityHash === 'string' ? rec.identityHash : null;
  if (!identityHash) return {};

  const key = `${identityHash}:legacy`;
  const sessionNonceB64 = typeof rec.sessionNonceB64 === 'string' ? rec.sessionNonceB64 : '';
  const migrated: Record<string, unknown> = {
    ...rec,
    key,
    kind: 'pair',
    mcpIds: [mcpId],
    sessionNonces: { [mcpId]: sessionNonceB64 },
    // Remove the old singular fields that are now superseded.
    mcpId: undefined,
    sessionNonceB64: undefined,
  };
  // Clean up undefined values (keep the spread clean).
  delete migrated.mcpId;
  delete migrated.sessionNonceB64;
  return { [key]: migrated };
}
