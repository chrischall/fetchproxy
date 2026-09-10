import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, vi } from 'vitest';
import { FetchproxyServer } from '../src/index.js';

/**
 * A rejection that lands before the caller is listening must not kill the
 * process (#329).
 *
 * Every verb registers its resolver, then AWAITS `sendInnerFrame` before a
 * handler is attached. That send seals a frame and writes a socket, so it
 * yields. Anything draining the pending maps inside that window — a refused
 * pairing, an extension disconnect, `close()` — rejects a promise nothing is
 * listening to, and Node's default `--unhandled-rejections=throw` turns that
 * into process death.
 *
 * The symptom was not a stack trace anyone could act on: a hosted `resy-mcp`
 * child asked the extension to pair, was told "pairing required, code
 * NNN-NN", and died instead of reporting it. Each respawn minted a fresh
 * code, so there was never a stable one to approve.
 */

/** Collect `unhandledRejection` events raised while `fn` runs. */
async function unhandledDuring(fn: () => Promise<void>): Promise<unknown[]> {
  const seen: unknown[] = [];
  const onUnhandled = (reason: unknown) => void seen.push(reason);
  process.on('unhandledRejection', onUnhandled);
  try {
    await fn();
  } finally {
    // The check runs on a later turn than the rejection; give it several.
    for (let i = 0; i < 3; i++) await new Promise((r) => setTimeout(r, 0));
    process.off('unhandledRejection', onUnhandled);
  }
  return seen;
}

const server = () =>
  new FetchproxyServer({
    serverName: 'test',
    version: '0.0.0',
    domains: ['example.com'],
    // 0 is the supported opt-out: no timer is armed, so nothing else can
    // quietly attach a handler and mask the hole under test.
    fetchTimeoutMs: 0,
  });

describe('an early rejection is handled, not fatal', () => {
  it('a pairing refusal mid-send rejects the caller and raises nothing', async () => {
    const s = server();
    // Hold the send open so the refusal lands in the window the bug lived in.
    let release!: () => void;
    const inFlight = new Promise<void>((r) => {
      release = r;
    });
    vi.spyOn(s as never, 'hostHandle', 'get').mockReturnValue({
      sendOwnInner: () => inFlight,
    } as never);

    let outcome = 'never settled';
    const seen = await unhandledDuring(async () => {
      const call = (
        s as unknown as {
          _captureRequestHeaderOnce: (o: {
            host: string;
            headerName: string;
          }) => Promise<string>;
        }
      )._captureRequestHeaderOnce({ host: 'example.com', headerName: 'x-token' });
      // The caller IS listening; the promise under test is the one still
      // sitting in `pendingCapture` with nothing attached to it.
      const caught = call.then(
        () => 'resolved',
        (e: Error) => e.message,
      );

      (
        s as unknown as { rejectAllPending: (reason: string) => void }
      ).rejectAllPending('pairing required for test. The pair code is: 123-45');

      // Let Node run its unhandled-rejection check BEFORE the send completes
      // and the real handler goes on. Without this the two can land in one
      // microtask drain and the hole hides.
      await new Promise((r) => setTimeout(r, 0));
      release();
      outcome = await caught;
    });

    expect(outcome).toContain('pairing required');
    expect(seen, 'an early rejection must never be unhandled').toEqual([]);
  });
});

/**
 * The behavioural test above proves ONE verb. This proves the other nine
 * cannot drift, and that a verb added tomorrow is covered the day it is
 * written — the discovery idiom `pending-maps-drained.test.ts` already uses
 * for the draining half of the same invariant.
 */
describe('every pending registration is guarded', () => {
  const source = readFileSync(
    fileURLToPath(new URL('../src/ws-server.ts', import.meta.url)),
    'utf8',
  );
  const lines = source.split('\n');

  it('finds every registration site, so the check cannot pass vacuously', () => {
    const sites = lines.filter((l) => /this\.pending\w*\.set\(/.test(l));
    expect(sites.length).toBeGreaterThanOrEqual(10);
  });

  it('wraps each one in guardPending', () => {
    const unguarded: string[] = [];
    lines.forEach((line, i) => {
      if (!/this\.pending\w*\.set\(/.test(line)) return;
      const inExecutor = (lines[i - 1] ?? '').includes('new Promise<');
      const guarded = (lines[i - 2] ?? '').includes('guardPending(');
      if (!inExecutor || !guarded) unguarded.push(`line ${i + 1}: ${line.trim()}`);
    });
    expect(unguarded, 'these would reject with nobody listening').toEqual([]);
  });
});
