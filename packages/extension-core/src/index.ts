export { isUrlAllowedForDomain, isTabUrlMatch } from './lib/url-match.js';
export { TrustStore, type TrustRecord, type TrustInput } from './trust-store.js';
export { SessionKeys, SessionEntry } from './session-keys.js';
export { ensureDomainTab, type EnsureDomainTabResult } from './ensure-domain-tab.js';
export { handleServerHello, type HandleHelloDeps, type HandleHelloResult } from './background.js';
