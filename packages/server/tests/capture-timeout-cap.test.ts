import { describe, it, expect } from 'vitest';
import { FetchproxyServer, FetchproxyTimeoutError } from '../src/index.js';
import { installFakeHost } from './helpers/fake-host.js';

/**
 * A per-call `timeoutMs` cannot exceed the transport's `fetchTimeoutMs`, and
 * the error has to say so (#277).
 *
 * `captureRequestHeader` forwards `timeoutMs` to the extension, but the
 * SERVER-side deadline still fires at `fetchTimeoutMs` and the thrown
 * `FetchproxyTimeoutError` was built with the deadline's own number. A caller
 * asking for 150s was told "did not respond within 30000ms" — a value they
 * never supplied, from an option the message never mentioned.
 *
 * The failure disguises itself, which is why it is worth a message rather than
 * a doc line: it reads as an unresponsive bridge, so the obvious next move is
 * to raise `timeoutMs` further, which changes nothing and confirms the wrong
 * theory. It took three diagnoses to notice the number was not the one passed.
 *
 * Capture is also the verb where a long wait is NORMAL — waiting for the page
 * to act is the whole point of it — so the collision is routine here in a way
 * it is not for `fetch()`.
 */
const baseOpts = {
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

async function captureError(fetchTimeoutMs: number, timeoutMs?: number): Promise<Error> {
  const s = new FetchproxyServer({ ...baseOpts, fetchTimeoutMs });
  installFakeHost(s);
  try {
    await s.captureRequestHeader({
      host: 'example.com',
      path: '/x*',
      headerName: 'Authorization',
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    });
    throw new Error('expected a timeout');
  } catch (e) {
    return e as Error;
  }
}

/**
 * EVERY verb that takes a per-call `timeoutMs` hits the same cap.
 *
 * The first pass threaded two of them and the PR said "both verbs that take a
 * per-call timeout" — counted off the two call sites in view rather than off
 * the type, which is exactly the shape of mistake that leaves one behind
 * (#279). There are three: capture_request_header, capture_redirect, download.
 */
async function errorFor(
  verb: 'capture' | 'redirect' | 'download',
  fetchTimeoutMs: number,
  timeoutMs: number,
): Promise<Error> {
  const s = new FetchproxyServer({ ...baseOpts, fetchTimeoutMs });
  installFakeHost(s);
  try {
    if (verb === 'capture') {
      await s.captureRequestHeader({ host: 'example.com', path: '/x*', headerName: 'Authorization', timeoutMs });
    } else if (verb === 'redirect') {
      await s.captureRedirect({ host: 'example.com', path: '/x*', timeoutMs });
    } else {
      await s.download({ url: 'https://example.com/x', timeoutMs });
    }
    throw new Error('expected a timeout');
  } catch (e) {
    return e as Error;
  }
}

describe('every per-call timeout verb explains the cap (#279)', () => {
  for (const verb of ['capture', 'redirect', 'download'] as const) {
    it(`${verb} names fetchTimeoutMs when the call asked for more`, async () => {
      const e = await errorFor(verb, 5, 150_000);
      expect(e.message, verb).toMatch(/fetchTimeoutMs/);
      expect(e.message, verb).toMatch(/150000/);
    });
  }
});

describe('captureRequestHeader timeout vs fetchTimeoutMs (#277)', () => {
  it('names fetchTimeoutMs as the binding constraint when the call asked for more', async () => {
    const e = await captureError(5, 150_000);
    expect(e).toBeInstanceOf(FetchproxyTimeoutError);
    // The deadline that actually fired…
    expect(e.message).toMatch(/5ms/);
    // …and WHY, naming both the option and the value the caller asked for, so
    // the reader is pointed at the knob that governs it.
    expect(e.message).toMatch(/fetchTimeoutMs/);
    expect(e.message).toMatch(/150000/);
  });

  it('says nothing extra when the call asked for less than the deadline', async () => {
    const e = await captureError(5, 1);
    // 1ms is under the deadline, so the deadline is not what capped it and
    // mentioning it would be noise.
    expect(e.message).not.toMatch(/fetchTimeoutMs/);
  });

  it('says nothing extra when no per-call timeout was given', async () => {
    const e = await captureError(5);
    expect(e.message).not.toMatch(/fetchTimeoutMs/);
  });
});
