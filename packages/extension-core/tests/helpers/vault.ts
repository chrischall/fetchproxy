/**
 * Test helpers for the extension's IndexedDB vault (`src/vault.ts`).
 *
 * The vault is the extension-origin IndexedDB, which content scripts cannot
 * open. Under vitest there is no IndexedDB, so each test installs a FRESH
 * in-memory one from `fake-indexeddb` — a brand-new factory is a brand-new
 * profile, which is what the old per-test `chrome.storage.local` mocks gave.
 *
 * `mockLocalArea()` is the other half of the threat model these tests encode:
 * it is `chrome.storage.local`, the area a compromised renderer's content
 * script CAN read and write. Tests hand its `data` object to the "attacker"
 * and assert what that does and does not buy.
 */
import { IDBFactory } from 'fake-indexeddb';

export function freshVault(): IDBFactory {
  const f = new IDBFactory();
  (globalThis as { indexedDB?: IDBFactory }).indexedDB = f;
  return f;
}

export interface LocalArea {
  data: Record<string, unknown>;
  get: (k: string | string[]) => Promise<Record<string, unknown>>;
  set: (kv: Record<string, unknown>) => Promise<void>;
  remove: (k: string | string[]) => Promise<void>;
}

export function mockLocalArea(data: Record<string, unknown> = {}): LocalArea {
  return {
    data,
    get: async (k) => {
      const ks = Array.isArray(k) ? k : [k];
      const out: Record<string, unknown> = {};
      for (const x of ks) if (x in data) out[x] = data[x];
      return out;
    },
    set: async (kv) => {
      Object.assign(data, kv);
    },
    remove: async (k) => {
      for (const x of Array.isArray(k) ? k : [k]) delete data[x];
    },
  };
}

/**
 * Install `chrome.storage.local` as the given area, plus a fresh
 * `chrome.storage.session` (trusted contexts only in a real browser — the
 * area the upgrade authorisation lives in; see `chromeSession()`).
 */
export function installChromeLocal(area: LocalArea = mockLocalArea()): LocalArea {
  (globalThis as { chrome?: unknown }).chrome = {
    storage: { local: area, session: mockLocalArea() },
  };
  return area;
}

/** The `chrome.storage.session` mock `installChromeLocal` installed. */
export function chromeSession(): LocalArea {
  return (globalThis as unknown as { chrome: { storage: { session: LocalArea } } }).chrome.storage
    .session;
}
