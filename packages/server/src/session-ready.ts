import type { SessionState } from './session.js';

/**
 * Default bound on waiting for the extension to confirm a usable session before
 * a request gives up. Generous enough for a user to approve a first-time pair,
 * but finite — an unbounded wait was the "timed out waiting for the browser
 * bridge" hang (the client-side guard masking an indefinite `await`).
 */
export const SESSION_READY_TIMEOUT_MS = 30_000;

/**
 * Thrown when the extension is connected but never confirms a session within the
 * timeout — instead of hanging forever on `await sessionReady`. Distinguishes
 * "approval pending" (a pair code is waiting for the user) from "no session"
 * (signed out / no `ready` frame), so callers get an actionable error rather than
 * one opaque timeout. Realizes the 0.5.2 intent ("surface the pair code … instead
 * of hanging on a missing session") at the send path.
 */
export class FetchproxySessionNotReadyError extends Error {
  readonly reason: 'pair-required' | 'not-ready';
  readonly pairCode: string | null;
  readonly mcpId: string;
  readonly hint: string;

  constructor(info: { mcpId: string; pairCode: string | null }) {
    const pairing = info.pairCode !== null && info.pairCode !== '';
    const hint = pairing
      ? `Open the ContextMint Bridge extension popup and approve pair code ${info.pairCode} for "${info.mcpId}", then retry.`
      : `The extension is connected but hasn't confirmed a session for "${info.mcpId}" — sign in to the target site in that browser (and approve the requested scope if it changed), then retry.`;
    super(
      `fetchproxy: ${pairing ? 'pairing not yet approved' : 'no confirmed browser session'} for "${info.mcpId}". ${hint}`,
    );
    this.name = 'FetchproxySessionNotReadyError';
    this.reason = pairing ? 'pair-required' : 'not-ready';
    // Normalize so the invariant `reason === 'not-ready' ↔ pairCode === null` holds
    // (an empty-string code would otherwise read as truthy for `pairCode !== null`).
    this.pairCode = pairing ? info.pairCode : null;
    this.mcpId = info.mcpId;
    this.hint = hint;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Thrown when the extension explicitly refuses a hello (2.6.0+). Distinct from
 * {@link FetchproxySessionNotReadyError}, which is a TIMEOUT and can only
 * guess: this one carries the extension's own reason, so the message names
 * what actually happened instead of listing causes that may all be satisfied.
 */
export class FetchproxyHelloRejectedError extends Error {
  readonly mcpId: string;
  readonly reason: string;

  constructor(info: { mcpId: string; reason: string }) {
    super(
      `fetchproxy: the extension refused the connection for "${info.mcpId}": ${info.reason}. ` +
        `This is the extension's own reason — it is not a timeout, and retrying ` +
        `unchanged will be refused the same way.`,
    );
    this.name = 'FetchproxyHelloRejectedError';
    this.mcpId = info.mcpId;
    this.reason = info.reason;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * The `@fetchproxy/server` release at which protocol 4 lands. Printed ONLY
 * when the far end is another MCP — that peer is this same package, so its
 * version is the thing to upgrade.
 *
 * It is never printed for the extension. The extension moved to
 * nullnet-app/contextmint-bridge and versions on its own release line
 * (starting at 1.0.0), so "update the extension to 3.0.0" would name a release
 * that will never exist. The contract between the two halves is the protocol
 * number, and that is what an extension-side refusal names.
 */
const MIN_SERVER_VERSION = '3.0.0';

/** Which end of the bridge spoke the other version. */
export type ProtocolVersionPeer = 'extension' | 'mcp';

/**
 * Thrown when the far end of the bridge speaks a different protocol version
 * (3.0.0 / protocol 4, Task 4.2).
 *
 * Until 3.0.0 this was not an error at all: `validateFrame` threw, the socket
 * was closed `1002 'protocol error'` — three words that say nothing about a
 * version — and the pending session was left alone, so the next call waited
 * out {@link SESSION_READY_TIMEOUT_MS} and then reported `not-ready` with a
 * hint blaming a signed-out session or a changed scope. A hang is the worst
 * failure mode a version mismatch can have: the person seeing it has nothing
 * to act on and no reason to suspect a version.
 *
 * So the message names BOTH versions and the thing to install, and names the
 * extension by its USER-FACING name — the person reading this in a claude.ai
 * tool error has a browser, not a package.
 */
export class FetchproxyProtocolVersionError extends Error {
  /** The protocol version this process speaks. */
  readonly ourVersion: number;
  /** The protocol version the far end announced in the hello we refused. */
  readonly theirVersion: number;
  readonly peer: ProtocolVersionPeer;

  constructor(info: { ourVersion: number; theirVersion: number; peer: ProtocolVersionPeer }) {
    const far =
      info.peer === 'extension'
        ? `the attached browser extension speaks ${info.theirVersion} — update ContextMint ` +
          `Bridge to a release that speaks fetchproxy protocol ${info.ourVersion}`
        : `the MCP holding the bridge port speaks ${info.theirVersion} — upgrade ` +
          `@fetchproxy/server to ${MIN_SERVER_VERSION} or later in that MCP`;
    super(
      `protocol version mismatch: this MCP speaks fetchproxy protocol ${info.ourVersion}, ${far}`,
    );
    this.name = 'FetchproxyProtocolVersionError';
    this.ourVersion = info.ourVersion;
    this.theirVersion = info.theirVersion;
    this.peer = info.peer;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * The same fact, cut to fit a WebSocket close frame.
 *
 * RFC 6455 caps a close reason at 123 bytes and `ws` throws above it, so the
 * sentence a person reads is {@link FetchproxyProtocolVersionError}'s and this
 * is what the far end's logs get. It still names BOTH versions, which is the
 * whole of what "out loud" means here — a close with no reason, or one naming
 * a single version, tells the reader nothing they can act on.
 */
export function protocolVersionCloseReason(info: {
  ourVersion: number;
  theirVersion: number;
  peer: ProtocolVersionPeer;
}): string {
  const far = info.peer === 'extension' ? 'the extension' : 'the other MCP';
  return (
    `protocol version mismatch: this MCP speaks ${info.ourVersion}, ` +
    `${far} speaks ${info.theirVersion}`
  );
}

/**
 * Await a session-ready promise, but reject with a
 * {@link FetchproxySessionNotReadyError} if it hasn't settled within
 * `timeoutMs` — converting an indefinite hang into a bounded, differentiated
 * error. A genuine rejection of `ready` (e.g. extension disconnected) propagates
 * unchanged. `timeoutMs <= 0` opts out of the bound.
 */
export async function awaitSessionReady(
  ready: Promise<SessionState>,
  opts: { mcpId: string; pendingPairCode: () => string | null; timeoutMs?: number },
): Promise<SessionState> {
  const ms = opts.timeoutMs ?? SESSION_READY_TIMEOUT_MS;
  if (ms <= 0) return ready;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new FetchproxySessionNotReadyError({ mcpId: opts.mcpId, pairCode: opts.pendingPairCode() }));
    }, ms);
    timer.unref?.();
  });
  try {
    return await Promise.race([ready, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
