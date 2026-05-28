// Tests for the `TokenBucket` per-host RPM governor (#86).
//
// Promoted from zillow-mcp's `src/throttle.ts` (#90/#91): the
// concurrency cap governs *parallelism*, but a bot-wall counts *total
// request volume in a short window*, so bulk fan-out needs a second
// governor — a per-host requests-per-minute token bucket on top of the
// pool. Pure: the clock is injected so tests are deterministic under
// fake timers.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { TokenBucket } from '../src/index.js';

describe('TokenBucket', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('serves the initial burst immediately without waiting', async () => {
    const bucket = new TokenBucket({ ratePerMinute: 60, burst: 3 });
    // Three tokens available at construction → three immediate acquires.
    await bucket.acquire();
    await bucket.acquire();
    await bucket.acquire();
    // If any of those had blocked, this test would hang past its
    // timeout — reaching here proves they resolved without timer advance.
    expect(true).toBe(true);
  });

  it('defaults burst to one minute worth of tokens', async () => {
    const bucket = new TokenBucket({ ratePerMinute: 5 });
    // No burst → capacity == ratePerMinute == 5 immediate tokens.
    for (let i = 0; i < 5; i++) await bucket.acquire();
    expect(true).toBe(true);
  });

  it('blocks the 4th acquire until a token refills', async () => {
    // 60 rpm == 1 token/sec. burst 3 → first 3 immediate, 4th waits ~1s.
    const bucket = new TokenBucket({ ratePerMinute: 60, burst: 3 });
    await bucket.acquire();
    await bucket.acquire();
    await bucket.acquire();

    let resolved = false;
    const fourth = bucket.acquire().then(() => {
      resolved = true;
    });

    // Not yet — bucket is empty.
    await vi.advanceTimersByTimeAsync(500);
    expect(resolved).toBe(false);

    // A full second after the burst drained, one token has refilled.
    await vi.advanceTimersByTimeAsync(600);
    await fourth;
    expect(resolved).toBe(true);
  });

  it('paces a steady stream at the configured rate', async () => {
    // 120 rpm == 1 token / 500ms. burst 1 → strictly serialized at 500ms.
    const bucket = new TokenBucket({ ratePerMinute: 120, burst: 1 });
    const order: number[] = [];
    await bucket.acquire(); // consumes the single initial token

    const p1 = bucket.acquire().then(() => order.push(1));
    const p2 = bucket.acquire().then(() => order.push(2));

    await vi.advanceTimersByTimeAsync(500);
    await p1;
    expect(order).toEqual([1]);

    await vi.advanceTimersByTimeAsync(500);
    await p2;
    expect(order).toEqual([1, 2]);
  });

  it('caps accumulated tokens at the burst ceiling', async () => {
    // After a long idle, tokens must not exceed `burst` — otherwise a
    // long pause would let a huge instantaneous burst through the wall.
    const bucket = new TokenBucket({ ratePerMinute: 60, burst: 2 });
    // Idle 10 minutes' worth of refill.
    await vi.advanceTimersByTimeAsync(600_000);
    // Only `burst` (2) immediate acquires should be available.
    await bucket.acquire();
    await bucket.acquire();

    let third = false;
    const p = bucket.acquire().then(() => {
      third = true;
    });
    await vi.advanceTimersByTimeAsync(0);
    expect(third).toBe(false); // capped — the 3rd must wait for a real refill

    await vi.advanceTimersByTimeAsync(1000);
    await p;
    expect(third).toBe(true);
  });

  it('accepts an injected clock for deterministic testing without fake timers', async () => {
    // The bucket reads time via an injected `now` so callers (and tests
    // that prefer explicit clocks) don't depend on Date.now.
    let clock = 0;
    const bucket = new TokenBucket({ ratePerMinute: 60, burst: 1, now: () => clock });
    await bucket.acquire(); // initial token

    let resolved = false;
    const p = bucket.acquire().then(() => {
      resolved = true;
    });
    // Advance the injected clock AND the timers together (the wait still
    // uses setTimeout, but the refill math reads the injected clock).
    clock = 1000;
    await vi.advanceTimersByTimeAsync(1000);
    await p;
    expect(resolved).toBe(true);
  });
});
