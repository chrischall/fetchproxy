// Public surface of `@fetchproxy/extension-core`. Anything not re-
// exported here is package-private — tests reach into the source
// modules directly, but production callers (extension-chrome,
// extension-safari) should stick to this list.

export {
  isUrlAllowedForDomain,
  isUrlAllowedForAnyDomain,
  isTabUrlMatch,
} from './lib/url-match.js';
export { TrustStore, type TrustRecord, type TrustInput } from './trust-store.js';
export { SessionKeys, SessionEntry } from './session-keys.js';
export { ensureDomainTab, type EnsureDomainTabResult } from './ensure-domain-tab.js';
export { handleServerHello, type HandleHelloDeps, type HandleHelloResult } from './background.js';
