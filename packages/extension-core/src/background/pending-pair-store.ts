/**
 * The `chrome.storage.local` keys used for the pairing / scope-approval
 * queue, plus the read-modify-write lock that serialises access to them.
 * Moved verbatim out of `background.ts`.
 *
 * These things share a module because they are the one place two
 * otherwise-separate regions of the service worker meet: the socket region
 * (`onServerHello` queues a pending record) and the approval region
 * (`onApproval` / `onScopeUpdateDismiss` drain it). Hoisting them into a
 * shared leaf module turns what was a backwards reference into a normal
 * downward import and lets both regions be split apart without a cycle.
 * (The dismissed-scope-hash set that used to be named here moved into the
 * vault — `vault-records.ts` — because a content script could write it in
 * `storage.local`; fleet-audit #252.)
 *
 * `pendingPairLock` in particular MUST have exactly one declaration in the
 * program: two copies would be two independent promise chains, which is
 * exactly the get/set race the comment below describes — silently, and with
 * no test that would catch it.
 */

import { normalisePendingPair } from '../lib/pending-pair.js';

import type { AnyPendingRecord } from './pending-records.js';

export const PENDING_PAIR_KEY = 'pendingPair';
export const APPROVED_PAIR_KEY = 'approvedPair';
/** The popup's "keep as is" decision on a scope update. */
export const DISMISS_SCOPE_UPDATE_KEY = 'dismissedScopeUpdate';

/**
 * Where the pairing queue and the popup's decisions live:
 * `chrome.storage.session`, NEVER `chrome.storage.local` (S-SEC-3).
 *
 * `storage.local` is readable and writable by content scripts, which this
 * extension injects into every site, so an approval read from it could have
 * been written by a compromised renderer on any site — minting trust for an
 * identity of its choosing, with any domains and capabilities, with no popup
 * interaction. `storage.session` is restricted to trusted contexts (extension
 * pages and the service worker) by default, so everything on this channel
 * was written by this extension's own code.
 *
 * `undefined` where the area does not exist (Chrome < 102, which the
 * manifest's `minimum_chrome_version` excludes). Callers FAIL CLOSED on it:
 * nothing is queued and nothing is approved.
 *
 * The queue does not survive a browser restart, which is intended: the MCP
 * that asked will hello again, and a request from before the restart could
 * not have been answered anyway (its link is gone).
 */
export type PendingArea = {
  get: (k: string | string[]) => Promise<Record<string, unknown>>;
  set: (kv: Record<string, unknown>) => Promise<void>;
  remove: (k: string) => Promise<void>;
};

export function pendingArea(): PendingArea | undefined {
  return (globalThis as { chrome?: { storage?: { session?: PendingArea } } }).chrome?.storage
    ?.session;
}

/**
 * Local alias bound to this file's `AnyPendingRecord`. The shared
 * helper in `../lib/pending-pair.ts` is generic so the popup can use it
 * against its own structurally-compatible interface without a circular
 * dependency on this file's exact type.
 */
export function mergePending(stored: unknown): Record<string, AnyPendingRecord> {
  return normalisePendingPair<AnyPendingRecord>(stored);
}

/**
 * 0.5.2+: serialise reads-then-writes of the pendingPair storage key.
 *
 * Two `onServerHello` invocations from concurrent peer hellos (or an
 * `onApproval` interleaving with an `onServerHello`) would otherwise race
 * the `get → set` pair and one of the entries would silently disappear:
 * both reads see the same starting state, both writes resolve to that
 * state plus their own entry, and whichever set lands second wins. The
 * window is narrow on a real SW (event-loop microtasks), but `await`
 * boundaries are exactly where Chrome can interleave other callbacks.
 *
 * `pendingPairLock` is a tail-promise chain: every mutation appends a
 * function that runs after the previous one resolves, so the read and
 * the write for a single logical update happen back-to-back without any
 * other mutation slipping between. Errors are swallowed on the chain
 * itself (logged at the call site) so one failure can't permanently
 * jam the queue.
 */
let pendingPairLock: Promise<unknown> = Promise.resolve();

export function withPendingPairLock<T>(fn: () => Promise<T>): Promise<T> {
  const next = pendingPairLock.then(fn, fn);
  pendingPairLock = next.catch(() => undefined);
  return next;
}
