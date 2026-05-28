// Tests for `withDeadline` — races a promise against a timer and
// returns a `{ timedOut }` envelope (#86).
//
// Promoted from homes-mcp's `src/tools/deadline.ts` (#54/#56). Turns
// "hang until the MCP client kills the connection" into "return partial
// results with per-row markers". The timer is always cleared (and
// unref'd) so a fast inner promise never keeps the process alive for
// the full deadline, and inner rejections propagate rather than being
// folded into a timeout.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { withDeadline } from '../src/index.js';

describe('withDeadline', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('resolves with the value when the inner promise wins', async () => {
    const inner = Promise.resolve('ok');
    const out = await withDeadline(inner, 1000);
    expect(out).toEqual({ timedOut: false, value: 'ok' });
  });

  it('returns timedOut:true when the timer wins', async () => {
    // Inner never settles within the deadline.
    const inner = new Promise<string>((resolve) => setTimeout(() => resolve('late'), 5000));
    const p = withDeadline(inner, 1000);
    await vi.advanceTimersByTimeAsync(1000);
    expect(await p).toEqual({ timedOut: true });
  });

  it('propagates an inner rejection instead of folding it into a timeout', async () => {
    const inner = Promise.reject(new Error('boom'));
    await expect(withDeadline(inner, 1000)).rejects.toThrow('boom');
  });

  it('clears the timer when the inner promise resolves first', async () => {
    const clearSpy = vi.spyOn(globalThis, 'clearTimeout');
    await withDeadline(Promise.resolve(42), 10_000);
    expect(clearSpy).toHaveBeenCalled();
    clearSpy.mockRestore();
  });

  it('unrefs the deadline timer so it cannot hold the event loop open', async () => {
    // Capture the timer object returned by setTimeout and assert unref
    // was invoked on it (Node-only API; jsdom timers may not expose it,
    // so guard accordingly).
    const unref = vi.fn();
    const realSetTimeout = globalThis.setTimeout;
    const spy = vi
      .spyOn(globalThis, 'setTimeout')
      .mockImplementation(((fn: TimerHandler, ms?: number, ...rest: unknown[]) => {
        const handle = (realSetTimeout as typeof setTimeout)(fn, ms, ...(rest as []));
        // Attach a spy unref so withDeadline's `timer.unref?.()` hits it.
        (handle as unknown as { unref: () => void }).unref = unref;
        return handle;
      }) as typeof setTimeout);

    const out = await withDeadline(Promise.resolve('x'), 1000);
    expect(out).toEqual({ timedOut: false, value: 'x' });
    expect(unref).toHaveBeenCalled();
    spy.mockRestore();
  });

  it('ignores a late inner settle after the timeout already won', async () => {
    let resolveInner: (v: string) => void = () => {};
    const inner = new Promise<string>((r) => {
      resolveInner = r;
    });
    const p = withDeadline(inner, 1000);
    await vi.advanceTimersByTimeAsync(1000);
    expect(await p).toEqual({ timedOut: true });
    // Settling the inner promise late must not throw or change the result.
    resolveInner('too-late');
    await vi.advanceTimersByTimeAsync(0);
  });
});
