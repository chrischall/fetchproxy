/**
 * Background service worker for fetchproxy 0.2.0.
 *
 * Connects to one host MCP at ws://127.0.0.1:37149. The host multiplexes
 * all peer MCPs through that one pipe. Each MCP↔extension session has its
 * own AES-256-GCM session key derived via ECDH at handshake.
 *
 * 0.2.0 change: trust and the per-request allowlist key off `domains[]`
 * (a non-empty array) rather than a singular `domain`.
 *
 * handleServerHello (pure function below) is the security-critical decision
 * point: verify signature, look up trust, decide auto-trust vs pair-prompt vs
 * reject. The WS plumbing below routes frames to/from it and the popup.
 */

// This file stays the esbuild entry point for the MV3 service worker
// (`packages/extension-chrome/build.ts` maps `background` here, and
// `manifest.json` names the emitted `background.js` as the
// `service_worker`). Everything it used to define now lives under
// `./background/`; what remains is the boot call plus the re-exports that
// `./index.ts` and the test suite import from this path.
//
// `maybeBoot` is imported as a VALUE and called explicitly rather than
// pulled in for its side effect (`import './background/boot.js'`): the
// bundle is built with `bundle: true, format: 'esm'`, which tree-shakes,
// so a side-effect-only import could be dropped with no build error and
// a dead service worker.
import { maybeBoot } from './background/boot.js';

export { handleServerHello, type HandleHelloDeps, type HandleHelloResult } from './background/hello.js';

/** Re-exported so existing importers of `ChromeCookie` from this module
 *  (including tests) keep resolving it here. */
export type { ChromeCookie } from './chrome-api.js';

export { applyNeedsPairRecord, type AnyPendingRecord } from './background/pending-records.js';

// Re-exported so `tests/send-to-first-responsive-tab.test.ts` keeps importing
// it from here; it is deliberately still absent from `./index.ts`.
export { sendToFirstResponsiveTab, type SendToFirstResponsiveTabResult } from './lib/send-to-responsive-tab.js';

// Re-exported so `tests/background.test.ts` keeps importing the handler-level
// constants, gates and tab matchers from here.
export { resolveWriteCookiesRequest, cookieSetDetailsFor } from './background/handlers/cookies.js';
export { CAPTURE_EXTRA_INFO_SPEC } from './background/handlers/capture.js';
export { downloadValueFromItem } from './background/handlers/download.js';
export { resolveReadDomRequest, readDomTabMatcher } from './background/handlers/read-dom.js';
export {
  resolveGraphqlQueryRequest,
  graphqlTabMatcher,
  isGraphqlSoftMiss,
} from './background/handlers/graphql-query.js';

export {
  connectedIdentityHashes,
  grantedScopeFromApproval,
  applyGrantedScopeToSession,
  sessionScopeSnapshot,
  liveScopeApplications,
  type GrantedSessionScope,
} from './background/session-scope.js';

maybeBoot();
