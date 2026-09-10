import { describe, it, expect } from 'vitest';
import {
  FetchproxyWaitedError,
  FetchproxyHintedError,
  FetchproxyProtocolError,
  FetchproxyTimeoutError,
  FetchproxyNoTabError,
  protocolErrorFrom,
  classifyBridgeError,
} from '../src/index.js';

/**
 * `capture_request_header`, `capture_redirect` and `download` answer
 * `{ ok: false, error: 'timeout' }` when their window closes with nothing
 * matched (protocol `frames.ts`). Type-based classification put that in the
 * `protocol` bucket, whose blanket hint is "extension/server version mismatch
 * — update both" — the same misdirection FetchproxyScopeError and
 * FetchproxyNoTabError were introduced to stop, arriving on what is by far the
 * most COMMON outcome of the three verbs rather than an unusual one.
 *
 * Measured on resy-mcp the day this landed: its capture leg times out against
 * an idle tab on every unattended mint, by design, and `/3/auth/refresh` does
 * the work. A user reading that output would have gone hunting a version
 * problem that did not exist.
 */
describe('protocolErrorFrom — a window the extension closed', () => {
  it('types a bare timeout rejection as a waited error', () => {
    expect(protocolErrorFrom('timeout')).toBeInstanceOf(FetchproxyWaitedError);
  });

  it('carries its own remedy, reachable by every consumer', () => {
    const err = protocolErrorFrom('timeout', 'capture');
    expect(err).toBeInstanceOf(FetchproxyHintedError);
    expect(err.hint).toMatch(/signed in/);
    expect(err.hint).not.toMatch(/version mismatch|update both/i);
  });

  // The two waits end differently, so one hint cannot serve both: a capture
  // ends when the PAGE makes a request, a download when the transfer finishes.
  it('names what would have ended THIS wait', () => {
    expect(protocolErrorFrom('timeout', 'capture').hint).toMatch(/idle tab/);
    expect(protocolErrorFrom('timeout', 'capture_redirect').hint).toMatch(/idle tab/);
    expect(protocolErrorFrom('timeout', 'download').hint).toMatch(/did not finish/);
  });

  // Every hinted error in this file ends by denying the version reading,
  // because that is the specific wrong turn each of them exists to prevent.
  it('says outright that this is not a version problem', () => {
    for (const op of ['capture', 'capture_redirect', 'download'] as const) {
      expect(protocolErrorFrom('timeout', op).hint).toMatch(/not a version problem/);
    }
  });

  /**
   * EXACT, not a substring. A message that merely contains the word is some
   * other failure describing itself, and claiming it would be this same
   * mis-hint pointed the other way — a real bridge fault told to go look at
   * the tab.
   */
  it('leaves a different failure that mentions the word alone', () => {
    const err = protocolErrorFrom('handshake timeout budget exceeded');
    expect(err).not.toBeInstanceOf(FetchproxyWaitedError);
    expect(err).toBeInstanceOf(FetchproxyProtocolError);
  });

  it('does not shadow the rejections matched beside it', () => {
    expect(protocolErrorFrom('no tab matching https://api.example.com/'))
      .toBeInstanceOf(FetchproxyNoTabError);
  });
});

describe('classifyBridgeError — the timeout bucket holds two classes', () => {
  it('reports a closed window as a timeout, not a protocol fault', () => {
    expect(classifyBridgeError(protocolErrorFrom('timeout', 'capture'))).toBe('timeout');
  });

  /**
   * Ordering, asserted rather than assumed: FetchproxyWaitedError subclasses
   * FetchproxyProtocolError, so its branch has to run BEFORE the protocol one
   * or it never runs at all and this whole change is inert.
   */
  it('is not swallowed by the ProtocolError branch it subclasses', () => {
    const err = protocolErrorFrom('timeout', 'capture');
    expect(err).toBeInstanceOf(FetchproxyProtocolError);
    expect(classifyBridgeError(err)).not.toBe('protocol');
  });

  it('still classifies the server-side deadline as a timeout', () => {
    const err = new FetchproxyTimeoutError({ url: 'https://x.example/', timeoutMs: 30_000 });
    expect(classifyBridgeError(err)).toBe('timeout');
  });

  /**
   * The consequence a caller has to know about, and the reason the
   * discriminator's JSDoc now spells it out: one string, two shapes. Reading
   * `timeoutMs` off the bucket without narrowing gets `undefined` from the
   * extension-side error rather than a number.
   */
  it('carries none of FetchproxyTimeoutError’s fields — narrow before reading them', () => {
    const waited = protocolErrorFrom('timeout', 'capture');
    expect(waited).not.toBeInstanceOf(FetchproxyTimeoutError);
    expect((waited as unknown as { timeoutMs?: number }).timeoutMs).toBeUndefined();
  });
});
