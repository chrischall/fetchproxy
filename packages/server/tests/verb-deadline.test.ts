import { describe, it, expect } from 'vitest';
import { FetchproxyServer, FetchproxyTimeoutError } from '../src/index.js';
// Imported from the PACKAGE ENTRY POINT, not from ws-server.js: `#372` found
// both missing from it, and a constant a JSDoc tells consumers to import is
// only importable if the entry point says so. This import is the assertion.
import { VERB_DEADLINE_GRACE_MS, verbDeadlineMs } from '../src/index.js';
import { installFakeHost } from './helpers/fake-host.js';

/**
 * A waiting verb's own `timeoutMs` GOVERNS its own deadline (#237).
 *
 * This file was `capture-timeout-cap.test.ts` and it pinned the opposite: a
 * per-call `timeoutMs` could not exceed the transport's `fetchTimeoutMs`, and
 * the error said so (#277, extended to all three waiting verbs in #279). That
 * cap is reversed here rather than the test deleted, because what #277 and
 * #279 were really defending is still true and still worth pinning — an error
 * must name the number that actually bound it, and it must name the same one
 * on every verb that takes a per-call timeout. Only the number changed.
 *
 * Why the cap had to go: `fetchTimeoutMs` bounds EVERY verb, so the remedy it
 * prescribed — raise the transport bound — also lengthened the deadline on
 * ordinary fetches and storage reads. A consumer that exposes its request
 * timeout as an operator setting could not pay that, which made the documented
 * workaround unusable for exactly the callers who needed it.
 */
/**
 * A tiny reply grace so these run in milliseconds. The DEFAULT is 15s, which
 * would make every end-to-end case here a 15-second wait — the option exists
 * for a hosted bridge's longer round trip, and the tests are its second user.
 * `verbDeadlineMs`'s own cases below cover the default explicitly.
 */
const GRACE = 20;

const baseOpts = {
  verbDeadlineGraceMs: GRACE,
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
  capabilities: [
    'fetch' as const,
    'capture_request_header' as const,
    'capture_redirect' as const,
    'download' as const,
  ],
  captureHeaders: [{ host: 'example.com', path: '/x*', headerName: 'Authorization' }],
};

/**
 * EVERY verb that takes a per-call `timeoutMs` is governed by it.
 *
 * The first pass at the old cap threaded two of them and said "both verbs" —
 * counted off the call sites in view rather than off the type, which is the
 * shape of mistake that leaves one behind (#279). There are three, and the
 * loop is here so a fourth cannot be added without answering for it.
 */
async function errorFor(
  verb: 'capture' | 'redirect' | 'download',
  fetchTimeoutMs: number,
  timeoutMs?: number,
): Promise<Error> {
  const s = new FetchproxyServer({ ...baseOpts, fetchTimeoutMs });
  installFakeHost(s);
  try {
    if (verb === 'capture') {
      await s.captureRequestHeader({
        host: 'example.com',
        path: '/x*',
        headerName: 'Authorization',
        ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      });
    } else if (verb === 'redirect') {
      await s.captureRedirect({
        host: 'example.com',
        path: '/x*',
        ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      });
    } else {
      await s.download({
        url: 'https://example.com/x',
        ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      });
    }
    throw new Error('expected a timeout');
  } catch (e) {
    return e as Error;
  }
}

describe('verbDeadlineMs', () => {
  it('gives a call its own window plus the reply grace', () => {
    // The onehome case: asked 120s, silently got 30s under the cap.
    expect(verbDeadlineMs(30_000, 120_000)).toBe(120_000 + VERB_DEADLINE_GRACE_MS);
  });

  it('takes a caller-supplied grace, for a bridge with a longer round trip', () => {
    expect(verbDeadlineMs(30_000, 120_000, 45_000)).toBe(165_000);
  });

  it('breaks the tie a window equal to the transport bound used to lose', () => {
    // The alltrails case: a 30s window on a 30s transport. Both timers fired at
    // once and the race decided whether the caller saw the extension's reason
    // or a transport timeout. The server now outlasts the extension by the
    // grace, so the extension's answer is the one that arrives.
    expect(verbDeadlineMs(30_000, 30_000)).toBeGreaterThan(30_000);
  });

  it('binds a window NEAR the transport bound, not only one above it', () => {
    // The band `transport - grace < requested < transport`, which the floor
    // does NOT keep at the transport bound: 20s asked for on a 30s transport
    // is 35s, because 20s plus the grace exceeds 30s. This is the near-tie the
    // grace exists for — the extension answers at 20s and the server has to
    // still be listening — and it is the case a doc claiming "asking for less
    // keeps the transport bound" reads as an exception when it is the rule.
    expect(verbDeadlineMs(30_000, 20_000)).toBe(20_000 + VERB_DEADLINE_GRACE_MS);
  });

  it('never shortens below the transport bound', () => {
    // A call asking for LESS keeps the transport's deadline. The extension's
    // own timer fires first either way, and tightening the server's wait to
    // match would start cutting off replies that arrive in time today.
    expect(verbDeadlineMs(60_000, 1_000)).toBe(60_000);
  });

  it('leaves a call that asked for nothing exactly where it was', () => {
    expect(verbDeadlineMs(30_000, undefined)).toBe(30_000);
  });
});

describe('a per-call timeout governs its own verb (#237)', () => {
  for (const verb of ['capture', 'redirect', 'download'] as const) {
    it(`${verb} waits past fetchTimeoutMs when the call asked for more`, async () => {
      // fetchTimeoutMs is 5ms and the call asks for 40ms. Under the cap this
      // rejected at 5ms; now the call's own window governs, so the deadline is
      // 40ms + the grace and the 5ms transport bound does not bind.
      const e = await errorFor(verb, 5, 40);
      expect(e, verb).toBeInstanceOf(FetchproxyTimeoutError);
      expect((e as FetchproxyTimeoutError).timeoutMs, verb).toBe(40 + GRACE);
    });

    it(`${verb} says whose number the deadline was`, async () => {
      const e = await errorFor(verb, 5, 40);
      // The value the caller passed, and where the rest of the deadline came
      // from — never the old advice to raise fetchTimeoutMs, which would now
      // lengthen every other verb for nothing.
      expect(e.message, verb).toMatch(/40ms this call asked for/);
      expect(e.message, verb).not.toMatch(/raise fetchTimeoutMs/);
    });
  }
});

describe('what the old cap test defended, still defended', () => {
  it('says nothing extra when the caller set no window', async () => {
    const e = await errorFor('capture', 5);
    expect((e as FetchproxyTimeoutError).timeoutMs).toBe(5);
    expect(e.message).not.toMatch(/this call asked for/);
  });

  it('does not describe the transport deadline as the caller’s number', async () => {
    // The floor case. The deadline is the transport's 60ms, not 1 + grace, so
    // the message must not present it as the caller's window plus the grace —
    // that would name a total the deadline is not, which is the same class of
    // defect the old message had in the other direction.
    const e = await errorFor('capture', 60, 1);
    expect((e as FetchproxyTimeoutError).timeoutMs).toBe(60);
    expect(e.message).not.toMatch(/this call asked for/);
  });
});
