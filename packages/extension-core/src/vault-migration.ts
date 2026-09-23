/**
 * First-run initialisation of the vault (`vault.ts`), including the ONE-TIME
 * migration out of `chrome.storage.local` for installs from 3.2.0 and earlier.
 *
 * The rule that makes this safe is that the vault's `identity` entry is the
 * sentinel: storage.local is consulted only while the vault has no identity,
 * and the identity plus everything migrated alongside it is written in ONE
 * transaction (`vaultInitIfAbsent`). Once it exists, the legacy keys are
 * deleted and never read again, so anything a content script writes to them
 * afterwards is inert.
 *
 * What the migration cannot do is tell a legitimate legacy record from one a
 * content script planted BEFORE the upgrade — that storage was writable by
 * design until now. It imports what an existing user has, so no one has to
 * re-pair, and the exposure it closes is from the upgrade onward (SECURITY.md
 * §Defense 4).
 *
 * Memoised per IndexedDB factory (= per profile) so the many callers that
 * need the vault ready — identity load, trust store, popup — share one run.
 * A failed run is not memoised; the next caller retries.
 */

import { vaultFactory, vaultGet, vaultInitIfAbsent } from './vault.js';
import {
  generateExtensionIdentity,
  importLegacyIdentity,
  isExtensionIdentity,
} from './identity-keys.js';

/** `chrome.storage.local` keys an older version kept secrets or trust in. */
export const LEGACY_IDENTITY_KEY = 'extensionIdentity';

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

const LEGACY_KEYS = [LEGACY_IDENTITY_KEY];

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
  if (isExtensionIdentity(await vaultGet('identity'))) {
    // Already initialised. Anything under the legacy keys now was written
    // after migration — by a content script, since nothing else writes them.
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
  const imported = await importLegacyIdentity(legacy[LEGACY_IDENTITY_KEY]);
  const identity = imported ?? (await generateExtensionIdentity());
  // If another context (popup vs service worker) won the race, nothing is
  // written here and its identity stands.
  await vaultInitIfAbsent('identity', { identity });
  await purgeLegacy(area);
}

const runs = new WeakMap<IDBFactory, Promise<void>>();

/** Resolve once the vault holds an identity (migrating or minting one). */
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
