/**
 * First-run initialisation of the vault (`vault.ts`), including the ONE-TIME
 * migration out of `chrome.storage.local` for installs from before the vault.
 *
 * Before the vault the extension kept its identity keys (fleet-audit #253) and its
 * trust records, remote bridge targets and dismissed scope-update hashes
 * (#252) in `storage.local`, which every site's content script can read and
 * write. They now live in the vault; this module moves them there once.
 *
 * The rules that make this safe:
 *
 * - **storage.local is read only on an UNFORGEABLE upgrade signal.** An empty
 *   vault is not one: quota eviction, corruption or a wipe of the extension's
 *   IndexedDB empties it too, and if emptiness alone authorised the import, a
 *   renderer that had planted an identity (whose private key it knows) and
 *   trust records pinned to it would have both installed the next time the
 *   vault was lost. The signal is `chrome.runtime.onInstalled` with reason
 *   `update` arriving while the vault is still empty — Chrome fires it,
 *   nothing a page does can. It is deliberately NOT tied to a version number:
 *   whichever release first ships the vault, the one before it kept state in
 *   storage.local, and a hardcoded "last legacy version" would silently strand
 *   every user of a storage.local release cut after it was written (3.2.1 was
 *   one). What this admits beyond a genuine upgrade is a vault lost at the
 *   moment of an update — not something an attacker can schedule. An update
 *   onto a vault that already has an identity authorises nothing, so no
 *   authorisation lingers for a vault lost later. `noteInstalled` records it in
 *   `chrome.storage.session` (trusted contexts only), so a service worker
 *   killed mid-import retries from there, and the import CONSUMES it. With an
 *   empty vault and no signal, a fresh identity is minted and whatever sits
 *   under the legacy keys is deleted unread.
 * - **the service worker waits for the signal.** On an upgrade Chrome starts
 *   the new worker and only then dispatches onInstalled, so boot's first
 *   vault access can come first. Boot arms `armInstallSignal`; an empty vault
 *   waits (bounded) for onInstalled to say what happened before it decides.
 *   A normal wake never gets here — the vault already has an identity — so
 *   the wait costs only a worker that woke up to a lost vault.
 * - **the identity and everything imported with it land in ONE transaction**
 *   that first checks the identity is still absent (`vaultInitIfAbsent`),
 *   so the popup and the service worker cannot both initialise.
 * - **the stores are imported only alongside a legacy identity.** A trust
 *   record is meaningless without the identity it was pinned to.
 * - **everything imported is validated the way the live stores validate it**
 *   — malformed rows are dropped, never repaired into something trusted.
 *
 * What a migration cannot do is tell a legitimate legacy record from one a
 * content script planted BEFORE the upgrade — that storage was writable by
 * design until now. It imports what an existing user has, so no one has to
 * re-pair, and the exposure it closes is from the upgrade onward
 * (SECURITY.md §Defense 4).
 *
 * Memoised per IndexedDB factory (= per profile) so the many callers that
 * need the vault ready — identity load, trust store, remote targets, popup —
 * share one run. A failed run is not memoised; the next caller retries.
 */

import { vaultFactory, vaultGet, vaultInitIfAbsent } from './vault.js';
import {
  generateExtensionIdentity,
  importLegacyIdentity,
  isExtensionIdentity,
} from './identity-keys.js';
import { normaliseRemoteTargets } from './remote-targets.js';

/** `chrome.storage.local` keys an older version kept secrets or trust in. */
export const LEGACY_IDENTITY_KEY = 'extensionIdentity';
export const LEGACY_TRUST_KEY = 'trustedMcps';
export const LEGACY_REMOTE_TARGETS_KEY = 'remoteBridges';
export const LEGACY_DISMISSED_KEY = 'dismissedScopeHashes';

const LEGACY_KEYS = [
  LEGACY_IDENTITY_KEY,
  LEGACY_TRUST_KEY,
  LEGACY_REMOTE_TARGETS_KEY,
  LEGACY_DISMISSED_KEY,
];

/**
 * `chrome.storage.session` key: the extension was updated onto an empty vault
 * and the import has not completed yet. `storage.session` is
 * restricted to trusted contexts, so a content script cannot set it.
 */
export const LEGACY_MIGRATION_FLAG = 'legacyVaultMigration';

/**
 * How long an empty vault in the service worker waits for onInstalled. Chrome
 * dispatches it right after the new worker starts; the wait only runs out on
 * a wake with no install event, i.e. a lost vault, which then mints fresh.
 */
export const INSTALL_SIGNAL_TIMEOUT_MS = 5_000;

interface Area {
  get: (k: string | string[]) => Promise<Record<string, unknown>>;
  set?: (kv: Record<string, unknown>) => Promise<void>;
  remove: (k: string | string[]) => Promise<void>;
}

function storageArea(name: 'local' | 'session'): Area | null {
  const c = (globalThis as unknown as { chrome?: { storage?: Partial<Record<string, Area>> } })
    .chrome;
  const a = c?.storage?.[name];
  return a && typeof a.get === 'function' && typeof a.remove === 'function' ? a : null;
}

/**
 * Is this `onInstalled` an update of the extension itself? Any version counts
 * — see the module comment for why this is not pinned to a "last legacy"
 * version. Chrome updates and shared-module updates do not.
 */
export function isExtensionUpdate(details: { reason: string; previousVersion?: string }): boolean {
  return details.reason === 'update';
}

let installSignal: { promise: Promise<boolean>; resolve: (v: boolean) => void } | null = null;

/**
 * Service-worker boot: make an empty vault wait (up to `timeoutMs`) for
 * `noteInstalled` before deciding between import and a fresh identity. Call
 * it before the first vault access, beside registering the onInstalled
 * listener that calls `noteInstalled`.
 */
export function armInstallSignal(timeoutMs: number = INSTALL_SIGNAL_TIMEOUT_MS): void {
  let settle!: (v: boolean) => void;
  const promise = new Promise<boolean>((r) => (settle = r));
  const timer = setTimeout(() => settle(false), timeoutMs);
  installSignal = {
    promise,
    resolve: (v) => {
      clearTimeout(timer);
      settle(v);
    },
  };
}

/** Test-only: forget any armed install signal. */
export function __resetInstallSignalForTests(): void {
  installSignal?.resolve(false);
  installSignal = null;
}

/**
 * The `chrome.runtime.onInstalled` listener's half. On an update onto a vault
 * that has no identity yet, authorise the one-time import (persisted in
 * `storage.session` so an interrupted worker can finish it); either way,
 * release a vault access waiting on `armInstallSignal`.
 */
export async function noteInstalled(details: {
  reason: string;
  previousVersion?: string;
}): Promise<void> {
  // An update onto an initialised vault has nothing to import, and a flag set
  // now would outlive it and authorise an import for a vault lost later in
  // the browser session.
  const authorised = isExtensionUpdate(details) && !(await vaultHasIdentity());
  if (authorised) {
    try {
      await storageArea('session')?.set?.({ [LEGACY_MIGRATION_FLAG]: true });
    } catch (e) {
      console.error('[fetchproxy] could not record the legacy-migration authorisation:', e);
    }
  }
  installSignal?.resolve(authorised);
}

async function vaultHasIdentity(): Promise<boolean> {
  try {
    return isExtensionIdentity(await vaultGet('identity'));
  } catch {
    // Unreadable vault: the import could not land anyway, and ensureVault
    // retries. Authorise, so a transient failure does not cost the pairings.
    return false;
  }
}

async function sessionFlagSet(): Promise<boolean> {
  const session = storageArea('session');
  if (!session) return false;
  try {
    return (await session.get(LEGACY_MIGRATION_FLAG))[LEGACY_MIGRATION_FLAG] === true;
  } catch {
    return false;
  }
}

async function clearSessionFlag(): Promise<void> {
  try {
    await storageArea('session')?.remove(LEGACY_MIGRATION_FLAG);
  } catch (e) {
    console.error('[fetchproxy] could not clear the legacy-migration authorisation:', e);
  }
}

/** May this (empty) vault import from storage.local? */
async function upgradeAuthorised(): Promise<boolean> {
  if (await sessionFlagSet()) return true;
  const signal = installSignal;
  if (!signal) return false;
  // One onInstalled per worker: whatever it said is used up by this run.
  const authorised = await signal.promise;
  if (installSignal === signal) installSignal = null;
  return authorised || (await sessionFlagSet());
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** `{ records: { [identityHash]: object } }`, dropping every non-object row. */
export function sanitiseTrustStore(v: unknown): { records: Record<string, unknown> } {
  const records: Record<string, unknown> = {};
  if (isPlainObject(v) && isPlainObject(v.records)) {
    for (const [k, r] of Object.entries(v.records)) if (isPlainObject(r)) records[k] = r;
  }
  return { records };
}

/** `{ [identityHash]: string[] }`, dropping every non-string entry. */
export function sanitiseDismissed(v: unknown): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  if (!isPlainObject(v)) return out;
  for (const [k, list] of Object.entries(v)) {
    if (!Array.isArray(list)) continue;
    const hashes = list.filter((h): h is string => typeof h === 'string');
    if (hashes.length > 0) out[k] = hashes;
  }
  return out;
}

async function purgeLegacy(area: Area | null): Promise<void> {
  if (!area) return;
  try {
    await area.remove(LEGACY_KEYS);
  } catch (e) {
    console.error('[fetchproxy] could not delete legacy storage.local keys:', e);
  }
}

async function run(): Promise<void> {
  const area = storageArea('local');
  if (isExtensionIdentity(await vaultGet('identity'))) {
    // Initialised. Anything under the legacy keys now was not written by this
    // extension's current state — a content script planted it, or it is the
    // leftover of a run interrupted before its purge — and is never imported.
    await vaultInitIfAbsent('legacyStoresMigrated', { legacyStoresMigrated: true });
    await clearSessionFlag();
    await purgeLegacy(area);
    return;
  }
  if (await upgradeAuthorised()) {
    let legacy: Record<string, unknown> = {};
    if (area) {
      try {
        legacy = await area.get(LEGACY_KEYS);
      } catch (e) {
        console.error('[fetchproxy] could not read legacy storage.local keys:', e);
      }
    }
    const imported = await importLegacyIdentity(legacy[LEGACY_IDENTITY_KEY]);
    // An upgrade brings its stores with it, pinned to the identity it had. If
    // another context (popup vs service worker) won the race, nothing is
    // written here and its initialisation stands.
    await vaultInitIfAbsent(
      'identity',
      imported
        ? {
            identity: imported,
            trustedMcps: sanitiseTrustStore(legacy[LEGACY_TRUST_KEY]),
            remoteBridges: normaliseRemoteTargets(legacy[LEGACY_REMOTE_TARGETS_KEY]),
            dismissedScopeHashes: sanitiseDismissed(legacy[LEGACY_DISMISSED_KEY]),
            legacyStoresMigrated: true,
          }
        : { identity: await generateExtensionIdentity(), legacyStoresMigrated: true },
      isExtensionIdentity,
    );
    // Consumed: a vault lost later in this browser session mints fresh.
    await clearSessionFlag();
  } else {
    // A fresh install, or a lost vault. Nothing in storage.local is ours.
    await vaultInitIfAbsent(
      'identity',
      { identity: await generateExtensionIdentity(), legacyStoresMigrated: true },
      isExtensionIdentity,
    );
  }
  await purgeLegacy(area);
}

const runs = new WeakMap<IDBFactory, Promise<void>>();

/** Resolve once the vault is initialised (migrating or minting as needed). */
export function ensureVault(): Promise<void> {
  const f = vaultFactory();
  let p = runs.get(f);
  if (!p) {
    p = run();
    runs.set(f, p);
    p.catch(() => runs.delete(f));
  }
  return p;
}
