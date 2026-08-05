import { describe, it, expect, vi } from 'vitest';
import { FetchproxyServer } from '../src/index.js';

/**
 * Every awaiter map must be drained when the bridge goes away.
 *
 * `write_cookies` shipped its map without registering it in `rejectAllPending`
 * or `sendInnerFrame`'s catch. The consequence is not cosmetic: on extension
 * disconnect, re-pair, or `close()`, an in-flight call waits out
 * `fetchTimeoutMs` and reports a timeout instead of "extension disconnected" —
 * and with the supported `fetchTimeoutMs: 0` opt-out no timer is armed at all,
 * so the promise **never settles**.
 *
 * The per-verb tests could not catch that, because each one exercises its own
 * map. So this test asserts the invariant across *all* of them by discovery:
 * it finds every `pending*` Map on the instance rather than naming them, which
 * means the next verb to add a map is covered the moment it exists — no new
 * test required, and no way to forget.
 */
function pendingMaps(s: FetchproxyServer): [string, Map<number, unknown>][] {
  const out: [string, Map<number, unknown>][] = [];
  const self = s as unknown as Record<string, unknown>;
  for (const key of Object.keys(self)) {
    if (!key.startsWith('pending')) continue;
    const v = self[key];
    if (v instanceof Map) out.push([key, v as Map<number, unknown>]);
  }
  return out;
}

/** Populate a map with a resolver of whichever shape it holds. */
function seed(map: Map<number, unknown>, id: number, onSettle: () => void) {
  // Two shapes in use: a bare callback (fetch, read_cookies) and a
  // {resolve, reject} pair (everything else). Seed both so discovery doesn't
  // need to know which map is which.
  map.set(id, Object.assign(() => onSettle(), {
    resolve: () => onSettle(),
    reject: () => onSettle(),
  }));
}

const server = () =>
  new FetchproxyServer({ serverName: 'test', version: '0.0.0', domains: ['example.com'] });

describe('pending awaiter maps', () => {
  it('discovers every map, so a new verb is covered without a new test', () => {
    // Guards the guard: if this ever finds nothing, the discovery broke and
    // the assertions below would pass vacuously.
    const found = pendingMaps(server()).map(([k]) => k);
    expect(found.length).toBeGreaterThanOrEqual(9);
    expect(found).toContain('pendingWriteCookies');
  });

  it('rejectAllPending drains all of them', () => {
    const s = server();
    const maps = pendingMaps(s);
    let settled = 0;
    maps.forEach(([, m], i) => seed(m, i + 1, () => settled++));

    (s as unknown as { rejectAllPending: (e: Error) => void }).rejectAllPending(
      new Error('extension disconnected'),
    );

    for (const [name, m] of maps) {
      expect(m.size, `${name} was not cleared by rejectAllPending`).toBe(0);
    }
    // Cleared is not enough — an awaiter dropped without settling hangs its
    // caller just as badly as one left in the map.
    expect(settled, 'every awaiter must be settled, not just discarded').toBe(maps.length);
  });

  it("sendInnerFrame's catch drops the id from all of them", async () => {
    const s = server();
    const maps = pendingMaps(s);
    const ID = 4242;
    for (const [, m] of maps) seed(m, ID, () => {});

    // Force the send to throw — the frame never reached the bridge, so no
    // reply will ever arrive and the resolver would leak until close().
    vi.spyOn(s as never, 'hostHandle', 'get').mockReturnValue({
      sendOwnInner: async () => {
        throw new Error('session never confirmed');
      },
    } as never);

    await expect(
      (s as unknown as { sendInnerFrame: (f: unknown) => Promise<void> }).sendInnerFrame({
        type: 'request',
        id: ID,
        op: 'fetch',
        init: { url: 'https://example.com/', method: 'GET', tabUrl: 'https://example.com/' },
      }),
    ).rejects.toThrow(/session never confirmed/);

    for (const [name, m] of maps) {
      expect(m.has(ID), `${name} still holds the id after a failed send`).toBe(false);
    }
  });
});
