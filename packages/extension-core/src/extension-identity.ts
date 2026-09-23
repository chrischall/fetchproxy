/**
 * Long-term identity keypair for the fetchproxy browser extension.
 *
 * 0.4.0+ mutual-auth design: the MCP verifies the `ready` frame's
 * `sessionSig` against the Ed25519 pub in this identity, so a
 * fake-extension process dialing the WS port can't forge a matching
 * signature and the MCP tears the WS down before any inner traffic flows.
 *
 * This docblock used to say the MCP "stores" those pubs and checks each
 * connection against the stored ones. It didn't — until 1.12.0 (#208) the
 * check was against the identity presented in the same connection, which is
 * freshness, not continuity. It stores them now, which is what makes this
 * identity's PERSISTENCE load-bearing rather than incidental: a re-install
 * mints a new one, and every MCP will refuse it until the user re-pairs
 * deliberately.
 *
 * Persisted in the extension-origin IndexedDB vault (`vault.ts`) with the
 * private halves as NON-EXTRACTABLE `CryptoKey`s (`identity-keys.ts`). Before
 * the vault it was raw base64 in `chrome.storage.local["extensionIdentity"]`,
 * where every site's content script could read it (fleet-audit #253); the
 * first load after upgrading imports those keys, so the identity — and every
 * pairing pinned to it — survives, and deletes them from storage.local.
 *
 * Generated lazily on first read. Survives extension restarts because
 * MV3 service-worker state is wiped on every restart, but the vault persists.
 */

import { vaultGet } from './vault.js';
import { ensureVault } from './vault-migration.js';
import { isExtensionIdentity, type ExtensionIdentity } from './identity-keys.js';

export { signWithExtensionIdentity, type ExtensionIdentity } from './identity-keys.js';

/**
 * Read the persisted extension identity, migrating it out of
 * `chrome.storage.local` or minting a fresh one on the first call.
 * Subsequent calls return the same identity.
 */
export async function loadOrCreateExtensionIdentity(): Promise<ExtensionIdentity> {
  await ensureVault();
  const id = await vaultGet('identity');
  if (!isExtensionIdentity(id)) {
    throw new Error('extension identity missing from the vault after initialisation');
  }
  return id;
}
