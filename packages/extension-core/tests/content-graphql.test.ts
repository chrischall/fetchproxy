// @vitest-environment jsdom

import { describe, it, expect, beforeAll } from 'vitest';

// content.ts registers a chrome.runtime.onMessage listener at module load,
// so a minimal `chrome` stub must exist before the (dynamic) import.
type RelayWindow = {
  addEventListener: (type: string, fn: (e: unknown) => void) => void;
  removeEventListener: (type: string, fn: (e: unknown) => void) => void;
  postMessage: (message: unknown, targetOrigin?: string) => void;
  location: { origin: string };
};

interface GraphqlRelayInit {
  operationName: string;
  variables: Record<string, unknown>;
  tabUrl?: string;
}

type GraphqlResult = { ok: true; data: unknown } | { ok: false; error: string };

let runGraphqlQuery: (
  init: GraphqlRelayInit,
  win?: RelayWindow,
  timeoutMs?: number,
) => Promise<GraphqlResult>;

beforeAll(async () => {
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: { onMessage: { addListener: () => {} } },
  };
  ({ runGraphqlQuery } = await import('../src/content.js'));
});

function makeFakeWindow(): {
  win: RelayWindow;
  posted: Array<{ __fetchproxy: string; reqId: number; operationName: string; variables: unknown }>;
  dispatch: (data: unknown, source?: unknown) => void;
} {
  const listeners: Record<string, Array<(e: unknown) => void>> = {};
  const posted: Array<{ __fetchproxy: string; reqId: number; operationName: string; variables: unknown }> = [];
  const win: RelayWindow = {
    addEventListener(type, fn) {
      (listeners[type] ||= []).push(fn);
    },
    removeEventListener(type, fn) {
      listeners[type] = (listeners[type] || []).filter((f) => f !== fn);
    },
    postMessage(message) {
      posted.push(message as (typeof posted)[number]);
    },
    location: { origin: 'https://www.opentable.com' },
  };
  const dispatch = (data: unknown, source: unknown = win): void => {
    for (const fn of listeners.message || []) fn({ source, data, origin: win.location.origin });
  };
  return { win, posted, dispatch };
}

describe('runGraphqlQuery (isolated-world → MAIN-world relay)', () => {
  it('posts a graphql-req and resolves with the matching graphql-res data', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    const p = runGraphqlQuery(
      { operationName: 'RestaurantsAvailability', variables: { partySize: 2 } },
      win,
      1000,
    );

    expect(posted).toHaveLength(1);
    const req = posted[0];
    expect(req.__fetchproxy).toBe('graphql-req');
    expect(req.operationName).toBe('RestaurantsAvailability');
    expect(req.variables).toEqual({ partySize: 2 });
    expect(typeof req.reqId).toBe('number');

    dispatch({ __fetchproxy: 'graphql-res', reqId: req.reqId, ok: true, data: { availability: [1, 2] } });

    await expect(p).resolves.toEqual({ ok: true, data: { availability: [1, 2] } });
  });

  it('relays an ok:false error (the "not yet observed" case) back through', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    const p = runGraphqlQuery({ operationName: 'X', variables: {} }, win, 1000);
    const reqId = posted[0].reqId;

    dispatch({
      __fetchproxy: 'graphql-res',
      reqId,
      ok: false,
      error: 'operation X not yet observed on this tab — open a restaurant page and retry',
    });

    const res = await p;
    expect(res.ok).toBe(false);
    expect((res as { error: string }).error).toContain('not yet observed');
  });

  it('times out when the MAIN world never replies', async () => {
    const { win } = makeFakeWindow();
    const res = await runGraphqlQuery({ operationName: 'X', variables: {} }, win, 10);
    expect(res.ok).toBe(false);
    expect((res as { error: string }).error).toContain('timed out');
  });

  it('ignores responses with a mismatched reqId or wrong source', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    const p = runGraphqlQuery({ operationName: 'X', variables: {} }, win, 1000);
    const reqId = posted[0].reqId;

    dispatch({ __fetchproxy: 'graphql-res', reqId: reqId + 999, ok: true, data: 'wrong' });
    dispatch({ __fetchproxy: 'graphql-res', reqId, ok: true, data: 'foreign' }, { not: 'the window' });
    dispatch({ __fetchproxy: 'graphql-res', reqId, ok: true, data: 'correct' });

    await expect(p).resolves.toEqual({ ok: true, data: 'correct' });
  });

  it('uses a monotonic counter for reqId (no Math.random)', async () => {
    const { win, posted } = makeFakeWindow();
    void runGraphqlQuery({ operationName: 'A', variables: {} }, win, 50);
    void runGraphqlQuery({ operationName: 'B', variables: {} }, win, 50);
    expect(posted[1].reqId).toBe(posted[0].reqId + 1);
  });

  it('rejects oversized variables without posting to the MAIN world', async () => {
    const { win, posted } = makeFakeWindow();
    const huge = 'x'.repeat(1024 * 1024 + 1); // just over MAX_REQUEST_BODY_BYTES (1 MB)
    const res = await runGraphqlQuery({ operationName: 'X', variables: { huge } }, win, 1000);
    expect(res.ok).toBe(false);
    expect((res as { error: string }).error).toContain('too large');
    expect(posted).toHaveLength(0);
  });

  it('rejects an oversized response instead of resolving with it', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    const p = runGraphqlQuery({ operationName: 'X', variables: {} }, win, 1000);
    const reqId = posted[0].reqId;
    const huge = 'x'.repeat(5 * 1024 * 1024 + 1); // just over MAX_RESPONSE_BODY_BYTES (5 MB)

    dispatch({ __fetchproxy: 'graphql-res', reqId, ok: true, data: { huge } });

    const res = await p;
    expect(res.ok).toBe(false);
    expect((res as { error: string }).error).toContain('too large');
  });

  it('removes its message listener after settling', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    const p = runGraphqlQuery({ operationName: 'X', variables: {} }, win, 1000);
    const reqId = posted[0].reqId;
    dispatch({ __fetchproxy: 'graphql-res', reqId, ok: true, data: 1 });
    await p;
    // A late duplicate must not throw or double-settle — listener is gone.
    expect(() => dispatch({ __fetchproxy: 'graphql-res', reqId, ok: true, data: 2 })).not.toThrow();
  });
});
