// Tests for the batch-paging primitives in `@fetchproxy/server`.
//
// `chunk` and `sleep` pair with the existing fan-out kit
// (`mapWithConcurrency` / `TokenBucket` / `backoffDelayMs`): a big id
// list gets split into safe-sized pages with `chunk`, dispatched one
// page at a time, with `sleep` spacing the pages. Hoisted from
// zillow-mcp's bulk-get (`src/throttle.ts` / `src/backoff.ts`).
//
// Both are pure (no shared state), so the tests are direct.
import { describe, it, expect, vi } from 'vitest';
import { chunk, sleep } from '../src/index.js';

describe('chunk', () => {
  it('splits an array into pages of at most `size`', () => {
    expect(chunk([1, 2, 3, 4, 5], 2)).toEqual([[1, 2], [3, 4], [5]]);
  });

  it('returns a single full page when size >= length', () => {
    expect(chunk([1, 2, 3], 10)).toEqual([[1, 2, 3]]);
  });

  it('returns one page per element when size is 1', () => {
    expect(chunk([1, 2, 3], 1)).toEqual([[1], [2], [3]]);
  });

  it('produces an exact division with no trailing short page', () => {
    expect(chunk([1, 2, 3, 4], 2)).toEqual([
      [1, 2],
      [3, 4],
    ]);
  });

  it('returns an empty array for an empty input', () => {
    expect(chunk([], 3)).toEqual([]);
  });

  it('collapses to a single page when size <= 0 (no infinite loop)', () => {
    // Defensive: a non-positive size must not loop forever.
    expect(chunk([1, 2, 3], 0)).toEqual([[1, 2, 3]]);
    expect(chunk([1, 2, 3], -5)).toEqual([[1, 2, 3]]);
  });

  it('returns a fresh outer array and does not mutate the input', () => {
    const input = [1, 2, 3];
    const pages = chunk(input, 2);
    pages[0]!.push(99);
    expect(input).toEqual([1, 2, 3]);
  });

  it('preserves element types/order for objects', () => {
    const a = { id: 'a' };
    const b = { id: 'b' };
    const c = { id: 'c' };
    expect(chunk([a, b, c], 2)).toEqual([[a, b], [c]]);
  });
});

describe('sleep', () => {
  it('resolves after the given delay (fake timers)', async () => {
    vi.useFakeTimers();
    try {
      let resolved = false;
      const p = sleep(1000).then(() => {
        resolved = true;
      });
      expect(resolved).toBe(false);
      await vi.advanceTimersByTimeAsync(999);
      expect(resolved).toBe(false);
      await vi.advanceTimersByTimeAsync(1);
      await p;
      expect(resolved).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it('returns a promise that resolves to undefined', async () => {
    await expect(sleep(0)).resolves.toBeUndefined();
  });
});
