/**
 * The extension's vault: a small key/value store in the EXTENSION ORIGIN's
 * IndexedDB, for everything a content script must not be able to read or
 * write.
 *
 * Why not `chrome.storage.local`: the extension injects content scripts into
 * every site, and content scripts can read AND write `storage.local`. A
 * renderer compromise on any site therefore reaches everything stored there.
 * IndexedDB is origin-scoped, and a content script runs in the PAGE's origin —
 * its `indexedDB` is the site's, never `chrome-extension://<id>`'s — so the
 * vault is reachable only from the service worker and extension pages (the
 * popup). No manifest permission is involved: IndexedDB is a web platform API.
 *
 * What lives here (keys of the single `kv` object store):
 * - `identity`             — the extension's long-term keypairs, private halves
 *                            as NON-EXTRACTABLE `CryptoKey`s
 *                            (`identity-keys.ts`, fleet-audit #253);
 * - `trustedMcps`          — the MCP trust records (`trust-store.ts`);
 * - `remoteBridges`        — configured remote bridge targets;
 * - `dismissedScopeHashes` — scope-update offers the user said "keep as is" to
 *                            (`vault-records.ts`; these three are fleet-audit
 *                            #252 — a content script could forge or revoke
 *                            them while they lived in `storage.local`);
 * - `legacyStoresMigrated` — marker: the one-time import of those three out of
 *                            `storage.local` has happened (`vault-migration.ts`).
 *
 * Every value is stored by structured clone, which is what lets a
 * non-extractable `CryptoKey` persist without its bytes ever being exposed.
 *
 * The factory is read from `globalThis.indexedDB` at call time, not captured
 * at import, so tests can hand each case a fresh in-memory profile.
 */

const DB_NAME = 'fetchproxy-vault';
const DB_VERSION = 1;
const STORE = 'kv';

export type VaultKey =
  'identity' | 'trustedMcps' | 'remoteBridges' | 'dismissedScopeHashes' | 'legacyStoresMigrated';

function factory(): IDBFactory {
  const f = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
  if (!f) throw new Error('IndexedDB is unavailable in this context');
  return f;
}

const dbs = new WeakMap<IDBFactory, Promise<IDBDatabase>>();

function openDb(f: IDBFactory): Promise<IDBDatabase> {
  let p = dbs.get(f);
  if (!p) {
    p = new Promise<IDBDatabase>((resolve, reject) => {
      const req = f.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
      };
      req.onsuccess = () => {
        const db = req.result;
        // Another context upgrading the schema must not be blocked by us.
        db.onversionchange = () => {
          db.close();
          dbs.delete(f);
        };
        resolve(db);
      };
      req.onerror = () => reject(req.error ?? new Error('indexedDB.open failed'));
      req.onblocked = () => reject(new Error('indexedDB.open blocked'));
    });
    dbs.set(f, p);
    p.catch(() => dbs.delete(f));
  }
  return p;
}

/**
 * The factory the vault is currently bound to. Exposed so per-profile caches
 * (the migration memo in `vault-migration.ts`) can key on it.
 */
export function vaultFactory(): IDBFactory {
  return factory();
}

/**
 * Run `body` in ONE IndexedDB transaction and resolve with whatever it hands
 * to `done` once the transaction has COMMITTED. `body` and every request
 * callback it chains must be synchronous: an `await` inside would let the
 * transaction auto-commit underneath it.
 */
async function transact<T>(
  mode: IDBTransactionMode,
  body: (store: IDBObjectStore, done: (v: T) => void) => void,
): Promise<T> {
  const db = await openDb(factory());
  return new Promise<T>((resolve, reject) => {
    const tx = db.transaction(STORE, mode);
    let result: T | undefined;
    let set = false;
    tx.oncomplete = () => {
      if (set) resolve(result as T);
      else reject(new Error('vault transaction completed without a result'));
    };
    tx.onerror = () => reject(tx.error ?? new Error('vault transaction failed'));
    tx.onabort = () => reject(tx.error ?? new Error('vault transaction aborted'));
    body(tx.objectStore(STORE), (v) => {
      result = v;
      set = true;
    });
  });
}

/** Read one value (undefined when absent). */
export function vaultGet(key: VaultKey): Promise<unknown> {
  return transact<unknown>('readonly', (store, done) => {
    const req = store.get(key);
    req.onsuccess = () => done(req.result);
  });
}

/**
 * Atomic read-modify-write of one value. `fn` gets the current value and
 * returns the next one; returning `undefined` deletes the key. Because the
 * read and the write share a transaction, two writers (the service worker
 * and the popup) cannot lose each other's update.
 */
export function vaultUpdate<T>(
  key: VaultKey,
  fn: (current: unknown) => T | undefined,
): Promise<T | undefined> {
  return transact<T | undefined>('readwrite', (store, done) => {
    const req = store.get(key);
    req.onsuccess = () => {
      const next = fn(req.result);
      if (next === undefined) store.delete(key);
      else store.put(next, key);
      done(next);
    };
  });
}

/**
 * Write every entry in ONE transaction, but only if `sentinel` is still
 * absent (per `isPresent`) when the transaction reads it. Resolves `true` if the entries were
 * written, `false` if another context got there first (in which case nothing
 * was written at all). This is what makes first-run initialisation and the
 * one-time migration safe to race between the popup and the service worker.
 */
export function vaultInitIfAbsent(
  sentinel: VaultKey,
  entries: Partial<Record<VaultKey, unknown>>,
  isPresent: (current: unknown) => boolean = (current) => current !== undefined,
): Promise<boolean> {
  return transact<boolean>('readwrite', (store, done) => {
    const req = store.get(sentinel);
    req.onsuccess = () => {
      if (isPresent(req.result)) {
        done(false);
        return;
      }
      for (const [k, v] of Object.entries(entries)) {
        if (v !== undefined) store.put(v, k);
      }
      done(true);
    };
  });
}
