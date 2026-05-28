/**
 * Bulk-fan-out helpers for MCPs that issue many parallel fetchproxy
 * requests (the realty MCP cohort: zillow, redfin, compass,
 * homes_com, onehome — anything with a `*_bulk_get` tool).
 *
 * Hoisted from the cohort's per-MCP duplicates after the round-3 #78
 * zillow-vs-redfin comparison pinned a stable contract: bounded
 * concurrency at 6, per-row one-shot timeout retry, and a per-row
 * error wrapper string that the cohort's "20-of-20 with X timeouts"
 * reporting depends on.
 *
 * Pure helpers — no state, no I/O, no logging. Caller wires them into
 * its own tool handler and decides how to render the per-row outcome.
 */

import {
  FetchproxyTimeoutError,
  FetchproxyBridgeDownError,
} from './ws-server.js';
import { classifyBridgeError } from './classify-bridge-error.js';

/**
 * Default cohort fan-out concurrency. Pinned to **6** by the round-3
 * #78 zillow-vs-redfin comparison: at 6 in flight Redfin's bulk did
 * 20/20 cleanly; at unlimited concurrency Zillow timed out 7-of-20.
 *
 * Export so the cohort converges on one number instead of every MCP
 * hard-coding its own. Bump only after a fresh cross-MCP comparison.
 */
export const BRIDGE_CONCURRENCY = 6;

/**
 * Bounded-concurrency fan-out. **Input-order preserving** — results
 * are returned in the same order as `items`, regardless of which item
 * finished first. Cursor-based worker pool: at most `limit` calls to
 * `fn` are in flight at any time.
 *
 * On rejection: propagates immediately (Promise.all-style — the first
 * rejection wins). Per-row error capture is the caller's job; wrap
 * the body of `fn` in try/catch and return a result envelope if
 * per-row outcomes matter. Don't bake row-error handling into a
 * generic utility.
 *
 * @param items   Inputs to map over.
 * @param limit   Max concurrent invocations of `fn`. Use
 *                {@link BRIDGE_CONCURRENCY} for fetchproxy bulk fan-out.
 * @param fn      Per-item async worker. Receives the item and its
 *                input index.
 * @returns       Results in the same order as `items`.
 */
export async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  if (items.length === 0) return results;
  const effectiveLimit = Math.max(1, Math.min(limit, items.length));
  let cursor = 0;

  const worker = async (): Promise<void> => {
    while (true) {
      const i = cursor++;
      if (i >= items.length) return;
      results[i] = await fn(items[i]!, i);
    }
  };

  const workers: Promise<void>[] = [];
  for (let w = 0; w < effectiveLimit; w++) {
    workers.push(worker());
  }
  await Promise.all(workers);
  return results;
}

/**
 * Run `fn`; if it throws {@link FetchproxyTimeoutError}, retry once.
 * Any other error propagates immediately without retry. A second
 * `FetchproxyTimeoutError` on the retry also propagates.
 *
 * Matches the rotating-tab tax observed in the bridge — the second
 * attempt almost always succeeds even when the first hit a stale tab
 * that the extension hadn't fully wired up yet. Empirically the right
 * trade-off for bulk fan-out: one retry buys back most of the timeout
 * rate without doubling wall-clock on a real failure.
 *
 * Pure helper, no state.
 */
export async function retryOnceOnTimeout<T>(
  fn: () => Promise<T>,
): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof FetchproxyTimeoutError) {
      return await fn();
    }
    throw err;
  }
}

/**
 * Per-row error classification for bulk-get tools. Returns both the
 * kind (so callers can branch on it for counters / hints) and the
 * user-facing message string the round-3 cohort standardized on:
 *
 *   * `'timeout'`     → `'bridge timeout after retry: <inner>'`
 *                       (critical that this stays distinguishable from
 *                       "no listing found" in the cohort's summary
 *                       reports — round-3 #78).
 *   * `'bridge_down'` → `'bridge unreachable: <inner>'`
 *   * `'protocol'`    → bare `FetchproxyProtocolError.message`
 *   * `'other'`       → `Error.message` or `String(err)` for non-Errors
 *
 * Higher-level than {@link classifyBridgeError}, which only returns
 * the kind. Built on top of it so the discrimination stays consistent.
 *
 * The `'http'` bucket in `classifyBridgeError` is intentionally folded
 * into `'other'` here — `*_bulk_get` tools work below the convenience
 * layer that throws `FetchproxyHttpError`, so an HTTP-shaped error at
 * this layer is a programmer error, not a per-row outcome.
 */
export function classifyRowError(err: unknown): {
  kind: 'timeout' | 'bridge_down' | 'protocol' | 'other';
  message: string;
} {
  const kind = classifyBridgeError(err);
  if (kind === 'timeout') {
    return {
      kind: 'timeout',
      message: `bridge timeout after retry: ${(err as FetchproxyTimeoutError).message}`,
    };
  }
  if (kind === 'bridge_down') {
    return {
      kind: 'bridge_down',
      message: `bridge unreachable: ${(err as FetchproxyBridgeDownError).message}`,
    };
  }
  if (kind === 'protocol') {
    return {
      kind: 'protocol',
      message: (err as Error).message,
    };
  }
  // 'http' folds into 'other' here (see jsdoc above), as do raw Errors
  // and non-Error inputs.
  if (err instanceof Error) {
    return { kind: 'other', message: err.message };
  }
  return { kind: 'other', message: String(err) };
}
