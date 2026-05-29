export { FetchproxyServer } from './ws-server.js';
export type {
  FetchproxyServerOpts,
  FetchResult,
  FetchResultError,
  HttpResponse,
  RequestOpts,
  BodylessRequestOpts,
  ReadCookiesResult,
  ReadCookiesResultError,
  BridgeHealth,
  BridgeProbeResult,
} from './ws-server.js';
export {
  FetchproxyProtocolError,
  FetchproxyHttpError,
  FetchproxyBridgeDownError,
  FetchproxyTimeoutError,
} from './ws-server.js';
export { classifyFetchError } from './error-kind.js';
export type { FetchErrorKind } from './error-kind.js';
export { classifyBridgeError } from './classify-bridge-error.js';
export type { BridgeError } from './classify-bridge-error.js';
export {
  mapWithConcurrency,
  retryOnceOnTimeout,
  classifyRowError,
  BRIDGE_CONCURRENCY,
} from './bulk.js';
// Transport-resilience kit (#86): bot-wall classification + throttle +
// backoff + deadline. All pure (no I/O); independent + tree-shakeable.
export { classifyBotWall } from './bot-wall.js';
export type { BotWallResult, BotWallVendor } from './bot-wall.js';
export { TokenBucket } from './throttle.js';
export type { TokenBucketOptions } from './throttle.js';
export { backoffDelayMs } from './backoff.js';
export type { BackoffOptions } from './backoff.js';
export { withDeadline } from './deadline.js';
export type { DeadlineOutcome } from './deadline.js';
// Shared SSR-HTML / URL parsing helpers (pure, dependency-free) hoisted
// from the scraping portal-MCP cohort. Anything portal-specific (the
// `window.X` variable names, CDN-host filters, GraphQL bodies) stays in
// the consumer.
export {
  extractBalancedObject,
  extractGlobalAssign,
  extractImgTags,
  lastPathSegment,
} from './parse-html.js';
// Batch-paging primitives that pair with the fan-out kit above.
export { chunk, sleep } from './batch.js';
export type { Capability, FetchInit } from '@fetchproxy/protocol';
