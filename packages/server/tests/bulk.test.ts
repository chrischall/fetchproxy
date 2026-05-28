// Tests for the bulk-fan-out helpers in `@fetchproxy/server`.
//
// These helpers were promoted from the realty MCP cohort (zillow,
// redfin, compass, homes_com, onehome) where every bulk-get tool
// rebuilt the same primitives. The round-3 #78 zillow-vs-redfin
// comparison pinned the contract:
//
//   * Bounded fan-out at 6 in flight (the cohort sweet spot — at 20
//     unlimited Zillow timed out 7/20; Redfin's bulk hit 20/20 cleanly
//     at 6).
//   * Per-row one-shot timeout retry (matches the rotating-tab tax
//     observed in the bridge — the second attempt almost always works
//     even though the first hit a stale tab).
//   * Per-row error classification with a stable wrapper string so the
//     cohort's "20-of-20 with X timeouts" reporting works.
//
// All four helpers are pure (no state, no side effects, no logging),
// so the tests are direct.
import { describe, it, expect } from 'vitest';
import {
  mapWithConcurrency,
  retryOnceOnTimeout,
  BRIDGE_CONCURRENCY,
  classifyRowError,
  FetchproxyTimeoutError,
  FetchproxyBridgeDownError,
  FetchproxyProtocolError,
} from '../src/index.js';

describe('mapWithConcurrency', () => {
  it('preserves input order across uneven completion times', async () => {
    // Items finish in reverse order of submission; the result array
    // still has to be in input order, not completion order.
    const items = [0, 1, 2, 3, 4];
    const result = await mapWithConcurrency(items, 3, async (i) => {
      // Earlier indexes wait longer — completion order is reversed.
      await new Promise((r) => setTimeout(r, (items.length - i) * 5));
      return `v${i}`;
    });
    expect(result).toEqual(['v0', 'v1', 'v2', 'v3', 'v4']);
  });

  it('respects the concurrency cap', async () => {
    // Instrument by tracking peak in-flight count.
    let inFlight = 0;
    let peak = 0;
    const items = Array.from({ length: 20 }, (_, i) => i);
    const limit = 4;
    await mapWithConcurrency(items, limit, async (i) => {
      inFlight++;
      if (inFlight > peak) peak = inFlight;
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return i;
    });
    expect(peak).toBeLessThanOrEqual(limit);
    // Sanity: cap was actually exercised (we had enough work to saturate it).
    expect(peak).toBe(limit);
  });

  it('propagates a rejection in one item', async () => {
    const items = [0, 1, 2, 3];
    await expect(
      mapWithConcurrency(items, 2, async (i) => {
        if (i === 2) throw new Error('boom');
        return i;
      }),
    ).rejects.toThrow('boom');
  });

  it('returns [] for empty input', async () => {
    const calls: number[] = [];
    const result = await mapWithConcurrency<number, number>(
      [],
      4,
      async (i) => {
        calls.push(i);
        return i;
      },
    );
    expect(result).toEqual([]);
    expect(calls).toEqual([]);
  });

  it('passes the input index to the worker fn', async () => {
    const items = ['a', 'b', 'c'];
    const result = await mapWithConcurrency(items, 2, async (item, index) => {
      return `${index}:${item}`;
    });
    expect(result).toEqual(['0:a', '1:b', '2:c']);
  });

  it('handles items.length < limit (no over-spawn)', async () => {
    const items = [0, 1];
    let inFlight = 0;
    let peak = 0;
    const result = await mapWithConcurrency(items, 8, async (i) => {
      inFlight++;
      if (inFlight > peak) peak = inFlight;
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return i;
    });
    expect(result).toEqual([0, 1]);
    expect(peak).toBeLessThanOrEqual(2);
  });
});

describe('retryOnceOnTimeout', () => {
  it('returns the value if the first attempt succeeds', async () => {
    let attempts = 0;
    const result = await retryOnceOnTimeout(async () => {
      attempts++;
      return 'ok';
    });
    expect(result).toBe('ok');
    expect(attempts).toBe(1);
  });

  it('retries once on FetchproxyTimeoutError and returns the second result', async () => {
    let attempts = 0;
    const result = await retryOnceOnTimeout(async () => {
      attempts++;
      if (attempts === 1) {
        throw new FetchproxyTimeoutError({
          url: 'https://example.com/x',
          timeoutMs: 30000,
        });
      }
      return 'ok-on-retry';
    });
    expect(result).toBe('ok-on-retry');
    expect(attempts).toBe(2);
  });

  it('propagates a second FetchproxyTimeoutError', async () => {
    let attempts = 0;
    await expect(
      retryOnceOnTimeout(async () => {
        attempts++;
        throw new FetchproxyTimeoutError({
          url: 'https://example.com/x',
          timeoutMs: 30000,
        });
      }),
    ).rejects.toBeInstanceOf(FetchproxyTimeoutError);
    expect(attempts).toBe(2);
  });

  it('does not retry on a non-timeout error', async () => {
    let attempts = 0;
    await expect(
      retryOnceOnTimeout(async () => {
        attempts++;
        throw new FetchproxyProtocolError('no_tab');
      }),
    ).rejects.toThrow('no_tab');
    expect(attempts).toBe(1);
  });

  it('does not retry on a generic Error', async () => {
    let attempts = 0;
    await expect(
      retryOnceOnTimeout(async () => {
        attempts++;
        throw new Error('whatever');
      }),
    ).rejects.toThrow('whatever');
    expect(attempts).toBe(1);
  });
});

describe('BRIDGE_CONCURRENCY', () => {
  // Pinned to 6 by the round-3 #78 evidence. Don't change without a
  // new cross-MCP comparison run — the cohort defaults to this number
  // and bumping it risks a regression in Zillow / Compass.
  it('is 6', () => {
    expect(BRIDGE_CONCURRENCY).toBe(6);
  });
});

describe('classifyRowError', () => {
  it('wraps FetchproxyTimeoutError with the round-3 wording', () => {
    const err = new FetchproxyTimeoutError({
      url: 'https://example.com/listing/123',
      timeoutMs: 30000,
    });
    const out = classifyRowError(err);
    expect(out.kind).toBe('timeout');
    expect(out.message).toBe(`bridge timeout after retry: ${err.message}`);
  });

  it('wraps FetchproxyBridgeDownError as bridge_down', () => {
    const err = new FetchproxyBridgeDownError({
      originalError: 'ws closed',
    });
    const out = classifyRowError(err);
    expect(out.kind).toBe('bridge_down');
    expect(out.message).toBe(`bridge unreachable: ${err.message}`);
  });

  it('surfaces FetchproxyProtocolError message bare', () => {
    const err = new FetchproxyProtocolError('no tab matching https://x.com/');
    const out = classifyRowError(err);
    expect(out.kind).toBe('protocol');
    expect(out.message).toBe('no tab matching https://x.com/');
  });

  it('surfaces a generic Error message bare as other', () => {
    const err = new Error('whatever');
    const out = classifyRowError(err);
    expect(out.kind).toBe('other');
    expect(out.message).toBe('whatever');
  });

  it('handles non-Error inputs via String()', () => {
    const out = classifyRowError('plain string');
    expect(out.kind).toBe('other');
    expect(out.message).toBe('plain string');
  });

  it('handles undefined as other', () => {
    const out = classifyRowError(undefined);
    expect(out.kind).toBe('other');
    expect(out.message).toBe('undefined');
  });
});
