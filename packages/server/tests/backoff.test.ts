// Tests for `backoffDelayMs` — exponential backoff with full jitter
// and a retry-after floor (#86).
//
// Promoted from zillow-mcp's `src/backoff.ts` (#90/#91). On a bot-wall
// outcome bulk-get backs off and retries the blocked sub-requests. The
// schedule is full jitter (AWS-style): a uniform pick in [0, window],
// which decorrelates concurrent retriers so they don't re-stampede the
// wall in lockstep. Pure: the random source is injected so the schedule
// is deterministic under test.
import { describe, it, expect } from 'vitest';
import { backoffDelayMs } from '../src/index.js';

describe('backoffDelayMs', () => {
  it('grows the exponential window as base*2^attempt', () => {
    // rng pinned to 1 (its supremum) surfaces the full window per attempt.
    const opts = { baseMs: 100, capMs: 100_000, rng: () => 0.999999 };
    // window = 100 * 2^attempt → ~100, ~200, ~400, ~800
    expect(backoffDelayMs(0, opts)).toBe(Math.round(100 * 0.999999));
    expect(backoffDelayMs(1, opts)).toBe(Math.round(200 * 0.999999));
    expect(backoffDelayMs(2, opts)).toBe(Math.round(400 * 0.999999));
    expect(backoffDelayMs(3, opts)).toBe(Math.round(800 * 0.999999));
  });

  it('applies full jitter: rng() scales the window linearly', () => {
    const opts = { baseMs: 1000, capMs: 100_000, rng: () => 0.5 };
    // attempt 2 → window 4000, jittered at 0.5 → 2000.
    expect(backoffDelayMs(2, opts)).toBe(2000);
  });

  it('returns 0 when rng() is 0 (full-jitter lower edge)', () => {
    expect(backoffDelayMs(3, { baseMs: 100, capMs: 100_000, rng: () => 0 })).toBe(0);
  });

  it('caps the exponential window at capMs before jitter', () => {
    // attempt 10 → uncapped window would be 100*1024; cap pins it to 5000.
    const opts = { baseMs: 100, capMs: 5000, rng: () => 1 };
    expect(backoffDelayMs(10, opts)).toBe(5000);
  });

  it('honors the retry-after floor when jitter would undershoot it', () => {
    // rng 0 would give 0ms, but the server said wait at least 3000ms.
    const opts = { baseMs: 100, capMs: 100_000, rng: () => 0, retryAfterMs: 3000 };
    expect(backoffDelayMs(0, opts)).toBe(3000);
  });

  it('lets jitter exceed the floor when the window is larger', () => {
    // window for attempt 5 = 100*32 = 3200; rng 1 → 3200 > floor 1000.
    const opts = { baseMs: 100, capMs: 100_000, rng: () => 1, retryAfterMs: 1000 };
    expect(backoffDelayMs(5, opts)).toBe(3200);
  });

  it('defaults rng to Math.random and stays within [floor, window]', () => {
    // No injected rng → real Math.random; assert bounds across samples.
    for (let i = 0; i < 50; i++) {
      const d = backoffDelayMs(3, { baseMs: 100, capMs: 100_000 });
      expect(d).toBeGreaterThanOrEqual(0);
      expect(d).toBeLessThanOrEqual(800); // window = 100*2^3
    }
  });
});
