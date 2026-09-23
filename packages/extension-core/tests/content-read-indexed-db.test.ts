// @vitest-environment jsdom
import { describe, it, expect, beforeAll } from 'vitest';

/**
 * B-BUG-3 — reading an IndexedDB database that does not exist yet must not
 * CREATE it. `indexedDB.open(name)` with no version creates the database at
 * v1 with no stores; the site's own later `open(name, 1)` then sees no
 * upgrade and runs against a store-less database until site data is
 * cleared. The read has to abort the versionchange transaction (which, for a
 * brand-new database, discards it) and report "not present".
 */

type RunReadIndexedDb = (
  database: string,
  store: string,
  keys: string[],
  idb?: IDBFactory,
) => Promise<{ ok: boolean; error?: string; values?: Record<string, unknown> }>;

let runReadIndexedDb: RunReadIndexedDb;

beforeAll(async () => {
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: { onMessage: { addListener: () => {} } },
  };
  ({ runReadIndexedDb } = (await import('../src/content.js')) as unknown as {
    runReadIndexedDb: RunReadIndexedDb;
  });
});

/** A fake IDBFactory whose database does not exist: open() fires upgradeneeded. */
function missingDbFactory(): { factory: IDBFactory; aborted: () => boolean } {
  let aborted = false;
  const factory = {
    open: () => {
      const req: Record<string, unknown> = {};
      req.transaction = {
        abort: () => {
          aborted = true;
          // Per spec, aborting the upgrade surfaces as an AbortError on the open request.
          queueMicrotask(() => {
            req.error = new DOMException('Version change transaction was aborted', 'AbortError');
            (req.onerror as (() => void) | undefined)?.();
          });
        },
      };
      queueMicrotask(() => {
        req.result = {
          objectStoreNames: { contains: () => false },
          close: () => {},
        };
        (req.onupgradeneeded as (() => void) | undefined)?.();
        // A real browser would fire onsuccess next unless the upgrade was aborted.
        if (!aborted) (req.onsuccess as (() => void) | undefined)?.();
      });
      return req;
    },
  } as unknown as IDBFactory;
  return { factory, aborted: () => aborted };
}

describe('runReadIndexedDb: a missing database is not created (B-BUG-3)', () => {
  it('aborts the upgrade and reports the database as not present', async () => {
    const { factory, aborted } = missingDbFactory();
    const r = await runReadIndexedDb('app-cache', 'kv', ['token'], factory);
    expect(aborted()).toBe(true);
    expect(r.ok).toBe(false);
    expect(r.error).toBe('database "app-cache" not present');
  });
});
