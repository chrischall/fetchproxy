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
      ? `Open the Transporter extension popup and approve pair code ${info.pairCode} for "${info.mcpId}", then retry.`
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
