/**
 * `withDeadline` — race a promise against a timer, returning a
 * `{ timedOut }` envelope (#86).
 *
 * Promoted from homes-mcp's `src/tools/deadline.ts` (#54/#56). The MCP
 * SDK gives each tool call a finite request deadline (60s default); a
 * fetch with no shorter effective deadline can wedge the connection
 * into a `-32001 Request timed out`. Wrapping the inner work in a
 * deadline comfortably below the MCP timeout turns "hang until the
 * client kills the connection" into "return partial results with
 * per-row markers".
 *
 * Pure: no I/O, no logging. The timer is always cleared (and unref'd)
 * so a fast inner promise never keeps the process alive for the full
 * deadline, and inner rejections propagate rather than being folded
 * into a timeout.
 */

/** Discriminated outcome of a deadline race. */
export type DeadlineOutcome<T> =
  | { timedOut: false; value: T }
  | { timedOut: true };

/**
 * Race `inner` against a `ms` timer.
 *
 *   * Inner resolves first → `{ timedOut: false, value }`.
 *   * Timer fires first     → `{ timedOut: true }` (the inner promise is
 *                             left to settle in the background; its
 *                             eventual result/rejection is ignored).
 *   * Inner rejects first   → the rejection propagates (NOT folded into
 *                             a timeout) so per-row try/catch still sees
 *                             the real error.
 *
 * The timer is cleared as soon as either side wins, and `unref`'d so it
 * can't hold the event loop open on its own.
 *
 * @param inner  The promise to race.
 * @param ms     Deadline in milliseconds.
 */
export function withDeadline<T>(
  inner: Promise<T>,
  ms: number,
): Promise<DeadlineOutcome<T>> {
  return new Promise<DeadlineOutcome<T>>((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve({ timedOut: true });
    }, ms);
    // Don't let the deadline timer hold the event loop open on its own.
    if (typeof timer === 'object' && typeof timer.unref === 'function') {
      timer.unref();
    }
    inner.then(
      (value) => {
        clearTimeout(timer);
        if (settled) return;
        settled = true;
        resolve({ timedOut: false, value });
      },
      (err) => {
        clearTimeout(timer);
        if (settled) return;
        settled = true;
        reject(err);
      },
    );
  });
}
