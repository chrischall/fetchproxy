import { describe, it, expect } from 'vitest';
import type { SessionState } from './session.js';
import { awaitSessionReady, FetchproxySessionNotReadyError } from './session-ready.js';

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
