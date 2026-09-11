import { describe, it, expect } from 'vitest';
import type { SessionState } from '../src/session.js';
import {
  awaitSessionReady,
  FetchproxyHelloRejectedError,
  FetchproxySessionNotReadyError,
} from '../src/session-ready.js';

const fakeSession = {} as SessionState;
const never = (): Promise<SessionState> => new Promise<SessionState>(() => {});

describe('awaitSessionReady', () => {
  it('resolves with the session when ready settles before the timeout', async () => {
    const s = await awaitSessionReady(Promise.resolve(fakeSession), {
      mcpId: 'm',
      pendingPairCode: () => null,
      timeoutMs: 1000,
    });
    expect(s).toBe(fakeSession);
  });

  it('rejects with a pair-required error (incl. pair code) when a pairing is pending at timeout', async () => {
    const err = await awaitSessionReady(never(), {
      mcpId: 'setlist-mcp',
      pendingPairCode: () => '123-456',
      timeoutMs: 10,
    }).catch((e) => e);
    expect(err).toBeInstanceOf(FetchproxySessionNotReadyError);
    expect(err.reason).toBe('pair-required');
    expect(err.pairCode).toBe('123-456');
    expect(err.hint).toMatch(/123-456/);
    expect(err.message).toMatch(/pairing not yet approved/i);
  });

  it('rejects with a not-ready error when no pairing is pending at timeout', async () => {
    const err = await awaitSessionReady(never(), {
      mcpId: 'setlist-mcp',
      pendingPairCode: () => null,
      timeoutMs: 10,
    }).catch((e) => e);
    expect(err).toBeInstanceOf(FetchproxySessionNotReadyError);
    expect(err.reason).toBe('not-ready');
    expect(err.pairCode).toBeNull();
    expect(err.hint).toMatch(/sign in/i);
  });

  it('normalizes an empty-string pair code to a not-ready error with null pairCode', async () => {
    const err = await awaitSessionReady(never(), {
      mcpId: 'm',
      pendingPairCode: () => '',
      timeoutMs: 10,
    }).catch((e) => e);
    expect(err.reason).toBe('not-ready');
    expect(err.pairCode).toBeNull();
  });

  it('propagates a genuine rejection of the ready promise unchanged', async () => {
    const boom = new Error('extension disconnected before ready');
    await expect(
      awaitSessionReady(Promise.reject(boom), { mcpId: 'm', pendingPairCode: () => null, timeoutMs: 1000 }),
    ).rejects.toBe(boom);
  });

  it('opts out of the bound when timeoutMs <= 0', async () => {
    const s = await awaitSessionReady(Promise.resolve(fakeSession), {
      mcpId: 'm',
      pendingPairCode: () => null,
      timeoutMs: 0,
    });
    expect(s).toBe(fakeSession);
  });
});

describe('FetchproxyHelloRejectedError', () => {
  // The point of the frame behind it (#300): a refusal must arrive as itself
  // rather than as the timeout that used to stand in for it. A timeout can
  // only guess, and its hint guessed wrong — naming "signed out" and "scope
  // changed" for a connection whose real problem was neither.
  it('beats the timeout, carrying the extension\'s own reason', async () => {
    const rejected = Promise.reject(
      new FetchproxyHelloRejectedError({
        mcpId: 'resy-mcp:0.13.1:2259288954ecdf3d',
        reason: 'serverName/domains mismatch with trust record',
      }),
    );
    const err = await awaitSessionReady(rejected, {
      mcpId: 'resy-mcp:0.13.1:2259288954ecdf3d',
      pendingPairCode: () => null,
      timeoutMs: 30_000,
    }).catch((e: unknown) => e);

    // Not the timeout error, and not after 30 s.
    expect(err).toBeInstanceOf(FetchproxyHelloRejectedError);
    expect(err).not.toBeInstanceOf(FetchproxySessionNotReadyError);
    const e = err as FetchproxyHelloRejectedError;
    expect(e.reason).toBe('serverName/domains mismatch with trust record');
    expect(e.message).toContain('serverName/domains mismatch with trust record');
    // It must not repeat the timeout's guesses — that wording is what sent
    // people to check a sign-in and a scope that were both already fine.
    expect(e.message).not.toContain('sign in to the target site');
    expect(e.message).toContain('not a timeout');
  });
});
