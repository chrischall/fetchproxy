/**
 * Shared normalisation for the `pendingPair` value stored in
 * `chrome.storage.local`. The shape evolved across versions:
 *
 *   - 0.5.1 and earlier wrote a single `PendingPairRecord` (object with
 *     a top-level `mcpId` field).
 *   - 0.5.2+ writes a `Record<mcpId, PendingPairRecord>` dict so multiple
 *     simultaneous unpaired MCPs can queue without overwriting each other.
 *
 * Both the service-worker (background.ts) and the popup (popup.ts) read
 * this value and need to handle the same input set identically — if the
 * two contexts disagreed on what counts as a malformed record, one could
 * silently render an entry the other refuses to act on. This helper is
 * the single source of truth; callers in either context must use it.
 *
 * Returns an empty dict for any unrecognised input (null, undefined,
 * non-object, or an object that's neither a single record nor a
 * mcpId-keyed dict of records). The dict is keyed by mcpId; values are
 * the caller's record type unchanged.
 *
 * Generic over the record type so this file has no dependency on the
 * specific `PendingPairRecord` shape each caller defines — the only
 * invariant we enforce is that each entry has a string `mcpId` field.
 */
export function normalisePendingPair<T extends { mcpId: string }>(
  stored: unknown,
): Record<string, T> {
  if (!stored || typeof stored !== 'object') return {};
  const obj = stored as Record<string, unknown>;
  // Legacy single-record shape: a flat object with its own `mcpId`. Wrap
  // it into a one-entry dict so callers can treat the result uniformly.
  if (typeof obj.mcpId === 'string') {
    return { [obj.mcpId]: obj as unknown as T };
  }
  // Dict shape: keep entries whose value has a string `mcpId`. Anything
  // else is dropped silently so a partial / corrupt write can't poison
  // the structure on read.
  const out: Record<string, T> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v && typeof v === 'object' && typeof (v as { mcpId?: unknown }).mcpId === 'string') {
      out[k] = v as T;
    }
  }
  return out;
}
