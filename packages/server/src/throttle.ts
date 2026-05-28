/**
 * `TokenBucket` — per-host requests-per-minute governor (#86).
 *
 * Promoted from zillow-mcp's `src/throttle.ts` (#90/#91). The
 * concurrency cap ({@link BRIDGE_CONCURRENCY}) governs *parallelism*,
 * but a bot-wall counts *total request volume in a short window*. Bulk
 * fan-out therefore needs a second governor on top of the concurrency
 * pool: a per-host RPM token bucket. One bucket per host, shared across
 * the whole fan-out, keeps total volume under the wall's threshold.
 *
 * Pure-ish: the bucket owns one number (available tokens) plus a clock
 * reference. No I/O, no logging. The clock is injectable so the bucket
 * is deterministic under fake timers or an explicit test clock.
 */

export interface TokenBucketOptions {
  /**
   * Sustained request rate, in requests per minute. The bucket refills
   * continuously at `ratePerMinute / 60_000` tokens per millisecond.
   */
  ratePerMinute: number;
  /**
   * Maximum tokens that can accumulate — the largest instantaneous
   * burst allowed before the rate limit bites. Defaults to
   * `ratePerMinute` (one minute's worth).
   */
  burst?: number;
  /**
   * Clock source returning the current time in milliseconds. Injectable
   * for deterministic tests; defaults to `Date.now`. (Under vitest fake
   * timers `Date.now` is itself mocked, so the default works there too.)
   */
  now?: () => number;
}

/**
 * A continuously-refilling token bucket. `acquire()` resolves
 * immediately when a token is available, otherwise waits exactly long
 * enough for the next token to refill. Callers are served as their
 * waits elapse.
 *
 * This is the per-host RPM governor for bulk fan-out (#90). Construct
 * one per host and share it across the fan-out so *total* request
 * volume — not just concurrency — stays under the bot-wall threshold.
 */
export class TokenBucket {
  private readonly ratePerMs: number;
  private readonly capacity: number;
  private readonly now: () => number;
  private tokens: number;
  private last: number;

  constructor(opts: TokenBucketOptions) {
    const rate = Math.max(1, opts.ratePerMinute);
    this.ratePerMs = rate / 60_000;
    this.capacity = Math.max(1, opts.burst ?? rate);
    this.now = opts.now ?? Date.now;
    this.tokens = this.capacity;
    this.last = this.now();
  }

  /** Refill tokens based on elapsed time, capped at capacity. */
  private refill(): void {
    const now = this.now();
    const elapsed = now - this.last;
    if (elapsed > 0) {
      this.tokens = Math.min(
        this.capacity,
        this.tokens + elapsed * this.ratePerMs,
      );
      this.last = now;
    }
  }

  /**
   * Acquire one token, waiting if the bucket is empty. Resolves as soon
   * as a token is available.
   */
  async acquire(): Promise<void> {
    // Loop rather than single-shot: setTimeout granularity means a
    // wakeup can fire a hair early, leaving us still <1 token; re-check
    // and wait the remainder rather than over-spending.
    for (;;) {
      this.refill();
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return;
      }
      const deficit = 1 - this.tokens;
      const waitMs = Math.ceil(deficit / this.ratePerMs);
      await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
    }
  }
}
