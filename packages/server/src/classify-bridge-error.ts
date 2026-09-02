import {
  FetchproxyBridgeDownError,
  FetchproxyTimeoutError,
  FetchproxyHttpError,
  FetchproxyProtocolError,
} from './ws-server.js';
import { FetchproxySessionNotReadyError } from './session-ready.js';

/**
 * 0.8.0+: discriminator for the typed-error hierarchy a downstream
 * MCP catches at the boundary of a tool handler. Returns one of:
 *
 * - `'session_not_ready'` — 2.5.0: `FetchproxySessionNotReadyError` — the extension
 *                        never confirmed a session within the session-ready
 *                        timeout; `.reason` is `'pair-required'` (a code waits
 *                        in the popup — `.pairCode`) or `'not-ready'` (attached
 *                        but silent). Before 2.5.0 this fell through to `'other'`
 *                        and no healthcheck could name it.
 * - `'timeout'`        — `FetchproxyTimeoutError` (server's `fetchTimeoutMs` fired)
 * - `'bridge_down'`    — `FetchproxyBridgeDownError` (SW eviction; check `retryAttempted`)
 * - `'http'`           — `FetchproxyHttpError` (upstream status outside `expectStatus`)
 * - `'protocol'`       — base `FetchproxyProtocolError` not in the buckets above
 *                        (e.g. `no_tab`, `domain_denied`, generic bridge errors)
 * - `'other'`          — anything not a `FetchproxyProtocolError` subclass
 *                        (programmer errors, unrelated runtime errors, non-Errors)
 *
 * Use this instead of an `instanceof` ladder — order of `instanceof`
 * checks is easy to get wrong (parent before subclass collapses the
 * subclass arms onto `'protocol'`). The helper enforces the correct
 * ordering once and the rest of the cohort can switch on the string.
 *
 * @example
 *   import { classifyBridgeError } from '@fetchproxy/server';
 *
 *   try {
 *     await client.get('/foo');
 *   } catch (e) {
 *     switch (classifyBridgeError(e)) {
 *       case 'timeout':     return { error: 'bridge timed out',  hint: '…' };
 *       case 'bridge_down': return { error: 'extension SW down', hint: e.hint };
 *       case 'http':        return { error: `HTTP ${e.response.status}` };
 *       case 'protocol':    return { error: 'transport',         message: e.message };
 *       case 'other':       throw e;
 *     }
 *   }
 */
export type BridgeError =
  | 'session_not_ready'
  | 'timeout'
  | 'bridge_down'
  | 'http'
  | 'protocol'
  | 'other';

export function classifyBridgeError(err: unknown): BridgeError {
  if (err instanceof FetchproxySessionNotReadyError) return 'session_not_ready';
  if (err instanceof FetchproxyTimeoutError) return 'timeout';
  if (err instanceof FetchproxyBridgeDownError) return 'bridge_down';
  if (err instanceof FetchproxyHttpError) return 'http';
  if (err instanceof FetchproxyProtocolError) return 'protocol';
  return 'other';
}
