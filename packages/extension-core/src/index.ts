// Public surface of `@fetchproxy/extension-core`. Anything not re-
// exported here is package-private — tests reach into the source
// modules directly, but production callers (extension-chrome,
// extension-safari) should stick to this list.

export {
  isUrlAllowedForDomain,
  isUrlAllowedForAnyDomain,
  cookieUrlFor,
  isTabUrlMatch,
  isTabUrlOnOrigin,
} from './lib/url-match.js';
export { TrustStore, type TrustRecord, type TrustInput } from './trust-store.js';
export { SessionKeys, SessionEntry } from './session-keys.js';
export { ensureDomainTab, type EnsureDomainTabResult } from './ensure-domain-tab.js';
export { handleServerHello, type HandleHelloDeps, type HandleHelloResult } from './background.js';
// 2.1.0: the remote bridge targets a user may configure. Exported because the
// validation is the contract a relay's own setup flow has to satisfy — a
// target this rejects is one the extension will never dial.
export {
  REMOTE_TARGETS_KEY,
  BRIDGE_SUBPROTOCOL,
  BRIDGE_TOKEN_SUBPROTOCOL_PREFIX,
  MAX_REMOTE_TARGETS,
  bridgeSubprotocols,
  normaliseRemoteTargets,
  remoteTargetDisplay,
  validateRemoteTargetToken,
  validateRemoteTargetUrl,
  type RemoteTarget,
} from './remote-targets.js';
