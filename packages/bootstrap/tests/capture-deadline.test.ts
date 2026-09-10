import { describe, it, expect, vi } from 'vitest';
import { bootstrap, CAPTURE_BOOTSTRAP_DEADLINE_MS, type BootstrapServer } from '../src/index.js';
import type { FetchproxyServerOpts } from '@fetchproxy/server';

/**
 * `bootstrap` asks for no per-call `timeoutMs`, so a declared capture runs for
 * the EXTENSION's 30 s default — against a transport deadline that was also
 * 30 s. Two timers armed for the same instant, and the transport's starts
 * first, because its frame has yet to travel.
 *
 * The timing was never wrong. The MESSAGE was: winning that race replaces the
 * extension's rejection — which explains that a capture resolves on the next
 * request the PAGE makes, so an idle tab times out — with a bare "did not
 * respond within 30000ms", a number the caller never chose about a mechanism it
 * never mentions.
 *
 * Twelve MCPs in the fleet reach captures only through here, so every one of
 * them inherited it and none could have fixed it locally.
 */
function makeStubServer(): BootstrapServer {
  return {
    listen: async () => {},
    close: async () => {},
    readCookies: async () => '',
    readLocalStorage: async () => ({}),
    readSessionStorage: async () => ({}),
    captureRequestHeader: async () => 'VALUE',
    readIndexedDb: async () => ({}),
  };
}

const CAPTURES = [{ host: 'api.example.com', path: '/*', headerName: 'authorization' }];

async function deadlineFor(
  captureHeaders: typeof CAPTURES,
  extra: Record<string, unknown> = {},
): Promise<number | undefined> {
  const factory = vi.fn((_o: FetchproxyServerOpts) => makeStubServer());
  await bootstrap({
    serverName: 'test',
    version: '0.0.0',
    domains: ['example.com'],
    declare: { cookies: [], localStorage: [], sessionStorage: [], captureHeaders },
    _serverFactory: factory,
    ...extra,
  } as never);
  return factory.mock.calls[0]![0].fetchTimeoutMs;
}

describe('bootstrap clears the capture window it relies on', () => {
  it('leaves the extension’s timer first when captures are declared', async () => {
    expect(await deadlineFor(CAPTURES)).toBe(CAPTURE_BOOTSTRAP_DEADLINE_MS);
    // The margin is the property, not the number: equal would still be a race
    // this side wins, and winning is what costs the useful message.
    expect(CAPTURE_BOOTSTRAP_DEADLINE_MS).toBeGreaterThan(30_000);
  });

  // A tie-break and nothing more. A bootstrap with nothing to capture has no
  // race to win, so its deadline must not move for a verb it never calls.
  it('changes nothing when no capture is declared', async () => {
    expect(await deadlineFor([])).toBeUndefined();
  });

  /**
   * An explicit deadline is a deliberate bound and stays exactly as given, even
   * though it re-loses the race. Bounding is the caller's decision; this fills
   * a default, and overriding an explicit value would turn "fix the default"
   * into "ignore the caller".
   */
  it('never overrides a deadline the caller set', async () => {
    expect(await deadlineFor(CAPTURES, { fetchTimeoutMs: 5_000 })).toBe(5_000);
    expect(await deadlineFor(CAPTURES, { fetchTimeoutMs: 300_000 })).toBe(300_000);
  });
});
