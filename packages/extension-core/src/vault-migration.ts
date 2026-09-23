/**
 * First-run initialisation of the vault (`vault.ts`), including the ONE-TIME
 * migration out of `chrome.storage.local` for installs from 3.2.0 and earlier.
 *
 * Up to 3.2.0 the extension kept its identity keys (fleet-audit #253) and its
 * trust records, remote bridge targets and dismissed scope-update hashes
 * (#252) in `storage.local`, which every site's content script can read and
 * write. They now live in the vault; this module moves them there once.
 *
 * The rules that make this safe:
 *
 * - **storage.local is read only while the vault lacks what it would supply.**
 *   The identity (and, on an upgrade, everything migrated alongside it) is
 *   written in ONE transaction that first checks the identity is still absent
 *   (`vaultInitIfAbsent`), and the three stores carry their own
 *   `legacyStoresMigrated` marker. Once both exist, the legacy keys are
 *   deleted and never read again, so anything a content script writes to them
 *   afterwards is inert.
 * - **the stores are imported only alongside a legacy identity.** A trust
 *   record is meaningless without the identity it was pinned to, and an
 *   install with no legacy identity is a fresh one — so anything found under
 *   the legacy store keys on a fresh install was not written by this
 *   extension, and is discarded. (The one exception is a profile whose
 *   identity already moved under a build that migrated only the keys: its
 *   stores are imported once, under the marker.)
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

import { vaultFactory, vaultGet, vaultInitIfAbsent, type VaultKey } from './vault.js';
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

interface LegacyArea {
  get: (k: string | string[]) => Promise<Record<string, unknown>>;
  remove: (k: string | string[]) => Promise<void>;
}

function legacyArea(): LegacyArea | null {
  const c = (globalThis as { chrome?: { storage?: { local?: LegacyArea } } }).chrome;
  const local = c?.storage?.local;
  return local && typeof local.get === 'function' && typeof local.remove === 'function'
    ? local
    : null;
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

async function purgeLegacy(area: LegacyArea | null): Promise<void> {
  if (!area) return;
  try {
    await area.remove(LEGACY_KEYS);
  } catch (e) {
    console.error('[fetchproxy] could not delete legacy storage.local keys:', e);
  }
}

async function run(): Promise<void> {
  const area = legacyArea();
  const current = await vaultGet('identity');
  if (isExtensionIdentity(current) && (await vaultGet('legacyStoresMigrated')) === true) {
    // Fully initialised. Anything under the legacy keys now was written after
    // migration — by a content script, since nothing else writes them.
    await purgeLegacy(area);
    return;
  }
  let legacy: Record<string, unknown> = {};
  if (area) {
    try {
      legacy = await area.get(LEGACY_KEYS);
    } catch (e) {
      console.error('[fetchproxy] could not read legacy storage.local keys:', e);
    }
  }
  const stores: Partial<Record<VaultKey, unknown>> = {
    trustedMcps: sanitiseTrustStore(legacy[LEGACY_TRUST_KEY]),
    remoteBridges: normaliseRemoteTargets(legacy[LEGACY_REMOTE_TARGETS_KEY]),
    dismissedScopeHashes: sanitiseDismissed(legacy[LEGACY_DISMISSED_KEY]),
    legacyStoresMigrated: true,
  };
  if (!isExtensionIdentity(current)) {
    const imported = await importLegacyIdentity(legacy[LEGACY_IDENTITY_KEY]);
    // An upgrade brings its stores with it; a fresh install brings nothing
    // (and marks the import done so storage.local is never consulted again).
    // Either way: if another context (popup vs service worker) won the race,
    // nothing is written here and its initialisation stands.
    await vaultInitIfAbsent(
      'identity',
      imported
        ? { identity: imported, ...stores }
        : { identity: await generateExtensionIdentity(), legacyStoresMigrated: true },
      isExtensionIdentity,
    );
  }
  // The identity was already in the vault but the stores never followed it
  // (a build that moved only the keys). No-op if the marker is set.
  await vaultInitIfAbsent('legacyStoresMigrated', stores);
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
