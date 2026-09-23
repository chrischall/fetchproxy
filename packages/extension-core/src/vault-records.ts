/**
 * The two small user-decision stores that moved into the vault beside the
 * trust records (fleet-audit #252): the configured remote bridge targets and
 * the dismissed scope-update hashes.
 *
 * Both used to live in `chrome.storage.local`, which every site's content
 * script can write. A compromised renderer could therefore add a bridge for
 * this browser to dial, or suppress a scope-update offer the user never saw.
 * In the extension-origin IndexedDB (`vault.ts`) only the service worker and
 * the popup can reach them.
 *
 * Everything read is validated on the way out as well as on the way in, so a
 * row this code would not have written is never acted on.
 */

import { vaultGet, vaultUpdate } from './vault.js';
import { ensureVault, sanitiseDismissed } from './vault-migration.js';
import { normaliseRemoteTargets, type RemoteTarget } from './remote-targets.js';

/** The configured remote bridge targets, as the background would dial them. */
export async function loadRemoteTargets(): Promise<RemoteTarget[]> {
  await ensureVault();
  return normaliseRemoteTargets(await vaultGet('remoteBridges'));
}

/**
 * Replace the configured targets. Only rows `normaliseRemoteTargets` accepts
 * are kept, so the popup can never persist something the background would
 * silently refuse to dial.
 */
export async function saveRemoteTargets(targets: RemoteTarget[]): Promise<void> {
  await ensureVault();
  const next = normaliseRemoteTargets(targets);
  await vaultUpdate('remoteBridges', () => next);
}

/** `{ [identityHash]: scopeHash[] }` the user answered "keep as is" to. */
export async function loadDismissedScopeHashes(): Promise<Record<string, string[]>> {
  await ensureVault();
  return sanitiseDismissed(await vaultGet('dismissedScopeHashes'));
}

/** Remember one dismissal (idempotent), atomically against other writers. */
export async function recordDismissedScopeHash(
  identityHash: string,
  scopeHash: string,
): Promise<void> {
  await ensureVault();
  await vaultUpdate('dismissedScopeHashes', (cur) => {
    const dismissed = sanitiseDismissed(cur);
    const list = dismissed[identityHash] ?? [];
    if (!list.includes(scopeHash)) dismissed[identityHash] = [...list, scopeHash];
    return dismissed;
  });
}
