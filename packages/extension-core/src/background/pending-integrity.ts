/**
 * The background's own copy of every pending pair / scope-update record, in
 * `chrome.storage.session`.
 *
 * Why (S-SEC-3): the popup ⇄ background hand-off runs through
 * `chrome.storage.local` (`pendingPair` → `approvedPair`), and `storage.local`
 * is readable AND writable from content scripts — which this extension
 * injects into every site. Trusting whatever lands in `approvedPair` meant a
 * renderer compromise on any site (or a future bug that lets page input reach
 * `chrome.storage` in the isolated world) could approve an identity of its
 * choosing, with any domains and capabilities, with no popup interaction.
 * `storage.session` is restricted to trusted contexts (extension pages and
 * the service worker) by default, so a record written there can only have
 * come from this code.
 *
 * Every background write to `pendingPair` applies the SAME mutation to this
 * mirror (never a copy of the `storage.local` dict, which may be tampered).
 * `onApproval` then honours an approval only if the mirror holds a record
 * under the same key that is identical in everything the user was shown and
 * approved; the live per-process fields (`mcpIds`, `sessionNonces`,
 * `sessionPubs`, `pairCode`) are taken from the mirror, since more processes may have
 * joined the entry after the popup rendered it.
 *
 * `storage.session` survives service-worker eviction but not a browser or
 * extension restart; a pending record left over from before one has no
 * mirror entry, is refused, and the MCP's next hello queues it again.
 */

import type { ChromeApi } from '../chrome-api.js';

declare const chrome: ChromeApi;

import type { AnyPendingRecord } from './pending-records.js';
import { mergePending } from './pending-pair-store.js';

export const AUTHORITATIVE_PENDING_KEY = 'pendingPairAuthoritative';

/**
 * Fields that change as processes join an entry, not by user decision:
 * another process of the same identity and scope collapsing into the record
 * after the popup rendered it adds to these and refreshes `pairCode` (a
 * per-hello SAS — see `applyNeedsPairRecord`). Comparing them would refuse a
 * genuine approval for a race the user cannot see.
 */
const LIVE_FIELDS = new Set(['mcpIds', 'sessionNonces', 'sessionPubs', 'pairCode']);

function sessionArea(): ChromeApi['storage']['session'] {
  return (globalThis as { chrome?: ChromeApi }).chrome?.storage?.session;
}

/**
 * Apply `mutate` to the authoritative mirror. Callers run it inside
 * `withPendingPairLock`, beside the matching `storage.local` write. A no-op
 * where `storage.session` does not exist (Chrome < 102, unit-test fakes).
 */
export async function recordPendingAuthoritative(
  mutate: (dict: Record<string, AnyPendingRecord>) => void,
): Promise<void> {
  const s = sessionArea();
  if (!s) return;
  const got = await s.get(AUTHORITATIVE_PENDING_KEY);
  const dict = mergePending(got[AUTHORITATIVE_PENDING_KEY]);
  mutate(dict);
  if (Object.keys(dict).length === 0) await s.remove(AUTHORITATIVE_PENDING_KEY);
  else await s.set({ [AUTHORITATIVE_PENDING_KEY]: dict });
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function approvedFields(r: AnyPendingRecord): string {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(r)) if (!LIVE_FIELDS.has(k)) out[k] = v;
  return canonical(out);
}

export type ApprovalCheck = { ok: true; record: AnyPendingRecord } | { ok: false; reason: string };

/**
 * Resolve an `approvedPair` record against the mirror. Returns the MIRROR's
 * record — the one to act on — or why the approval is refused. Where
 * `storage.session` is unavailable the approval is passed through unchecked
 * (there is no trusted-only store to check it against).
 */
export async function authoritativeApproval(approved: AnyPendingRecord): Promise<ApprovalCheck> {
  const s = sessionArea();
  if (!s) return { ok: true, record: approved };
  const got = await s.get(AUTHORITATIVE_PENDING_KEY);
  const dict = mergePending(got[AUTHORITATIVE_PENDING_KEY]);
  const mine = typeof approved?.key === 'string' ? dict[approved.key] : undefined;
  if (!mine)
    return { ok: false, reason: 'no pending request with that key was queued by the extension' };
  if (approvedFields(mine) !== approvedFields(approved)) {
    return {
      ok: false,
      reason: 'approved record differs from the pending request the extension queued',
    };
  }
  return { ok: true, record: mine };
}
