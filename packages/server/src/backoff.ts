/**
 * `backoffDelayMs` — exponential backoff with full jitter and a
 * retry-after floor (#86).
 *
 * Promoted from zillow-mcp's `src/backoff.ts` (#90/#91). On a bot-wall
 * outcome (see {@link classifyBotWall}) a bulk fan-out backs off and
 * retries the blocked sub-requests rather than failing them. The
 * schedule is full jitter (AWS-style): a uniform random pick in
 * `[0, exponential-window]`, which decorrelates concurrent retriers so
 * they don't re-stampede the wall in lockstep.
 *
 * Pure: the random source is injected so the schedule is deterministic
 * under test.
 */

export interface BackoffOptions {
  /**
   * Base delay (ms) for attempt 0. The exponential window is
   * `baseMs * 2^attempt`.
   */
  baseMs: number;
  /** Hard ceiling (ms) on the exponential window before jitter. */
  capMs: number;
  /** Random source in [0,1). Defaults to `Math.random`. */
  rng?: () => number;
  /**
   * Lower bound (ms) on the returned delay — used to honour a server /
   * bot-wall `retry-after` hint so jitter can't undershoot it.
   */
  retryAfterMs?: number;
}

/**
 * Delay (ms) before the given retry `attempt` (0-based). Full-jitter:
 * `rng() * min(capMs, baseMs * 2^attempt)`, then floored at
 * `retryAfterMs`.
 *
 * @param attempt  0-based retry number; grows the exponential window.
 * @param opts     {@link BackoffOptions}.
 */
export function backoffDelayMs(attempt: number, opts: BackoffOptions): number {
  const rng = opts.rng ?? Math.random;
  const window = Math.min(opts.capMs, opts.baseMs * 2 ** attempt);
  const jittered = rng() * window;
  const floor = opts.retryAfterMs ?? 0;
  return Math.max(floor, Math.round(jittered));
}
