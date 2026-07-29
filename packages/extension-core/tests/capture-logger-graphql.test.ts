// @vitest-environment jsdom

import { describe, it, expect, beforeAll, vi } from 'vitest';

// capture-logger.ts runs MAIN-world side effects (CSRF sync + Apollo bridge
// install) at module load. Those are guarded off under vitest so the import
// is inert and we can drive `installApolloBridge` against a controlled fake
// window instead of the global jsdom one.
type BridgeWindow = {
  __APOLLO_CLIENT__?: unknown;
  addEventListener: (type: string, fn: (e: unknown) => void) => void;
  removeEventListener: (type: string, fn: (e: unknown) => void) => void;
  postMessage: (message: unknown, targetOrigin?: string) => void;
  setInterval: (fn: () => void, ms: number) => number;
  clearInterval: (id: number) => void;
  location: { origin: string };
};

let installApolloBridge: (win: BridgeWindow) => void;

beforeAll(async () => {
  ({ installApolloBridge } = await import('../src/capture-logger.js'));
});

const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

function makeFakeWindow(): {
  win: BridgeWindow & { __APOLLO_CLIENT__?: unknown };
  posted: unknown[];
  dispatch: (data: unknown, source?: unknown) => void;
} {
  const listeners: Record<string, Array<(e: unknown) => void>> = {};
  const posted: unknown[] = [];
  const win = {
    __APOLLO_CLIENT__: undefined as unknown,
    addEventListener(type: string, fn: (e: unknown) => void): void {
      (listeners[type] ||= []).push(fn);
    },
    removeEventListener(type: string, fn: (e: unknown) => void): void {
      listeners[type] = (listeners[type] || []).filter((f) => f !== fn);
    },
    postMessage(message: unknown): void {
      posted.push(message);
    },
    setInterval(): number {
      return 0;
    },
    clearInterval(): void {
      /* noop */
    },
    location: { origin: 'https://www.opentable.com' },
  };
  const dispatch = (data: unknown, source: unknown = win): void => {
    for (const fn of listeners.message || []) fn({ source, data, origin: win.location.origin });
  };
  return { win, posted, dispatch };
}

interface FakeClient {
  link: { request: ReturnType<typeof vi.fn> };
  query: ReturnType<typeof vi.fn>;
}

function makeClient(data: unknown): FakeClient {
  return {
    link: { request: vi.fn(() => 'ORIGINAL_LINK_RESULT') },
    query: vi.fn(async () => ({ data })),
  };
}

const DOC = { kind: 'Document', __id: 'RestaurantsAvailability-doc' };

describe('installApolloBridge (MAIN-world Apollo bridge)', () => {
  it('captures the live DocumentNode via link.request and routes client.query', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    const client = makeClient({ availability: [1, 2, 3] });
    win.__APOLLO_CLIENT__ = client;

    installApolloBridge(win);

    // Organic op flows through the wrapped link — records DOC, passes through.
    const passthrough = client.link.request({ operationName: 'RestaurantsAvailability', query: DOC }, 'FWD');
    expect(passthrough).toBe('ORIGINAL_LINK_RESULT');

    dispatch({
      __fetchproxy: 'graphql-req',
      reqId: 1,
      operationName: 'RestaurantsAvailability',
      variables: { partySize: 2 },
    });
    await flush();

    expect(client.query).toHaveBeenCalledWith({
      query: DOC,
      variables: { partySize: 2 },
      fetchPolicy: 'no-cache',
      errorPolicy: 'all',
    });
    expect(posted).toContainEqual({
      __fetchproxy: 'graphql-res',
      reqId: 1,
      ok: true,
      data: { availability: [1, 2, 3] },
    });
  });

  it('returns the typed "not yet observed" error when the op was never seen', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    const client = makeClient({ availability: [] });
    win.__APOLLO_CLIENT__ = client;

    installApolloBridge(win);

    dispatch({ __fetchproxy: 'graphql-req', reqId: 7, operationName: 'NeverSeen', variables: {} });
    await flush();

    expect(client.query).not.toHaveBeenCalled();
    expect(posted).toHaveLength(1);
    const res = posted[0] as { reqId: number; ok: boolean; error: string };
    expect(res.reqId).toBe(7);
    expect(res.ok).toBe(false);
    expect(res.error).toContain('not yet observed');
    expect(res.error).toContain('NeverSeen');
  });

  it('reports client.query rejection as ok:false with the error message', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    const client = makeClient(null);
    client.query.mockRejectedValueOnce(new Error('boom'));
    win.__APOLLO_CLIENT__ = client;

    installApolloBridge(win);
    client.link.request({ operationName: 'RestaurantsAvailability', query: DOC });

    dispatch({ __fetchproxy: 'graphql-req', reqId: 9, operationName: 'RestaurantsAvailability', variables: {} });
    await flush();

    expect(posted).toContainEqual({ __fetchproxy: 'graphql-res', reqId: 9, ok: false, error: 'boom' });
  });

  it('ignores messages whose source is not the window', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    const client = makeClient({ availability: [1] });
    win.__APOLLO_CLIENT__ = client;
    installApolloBridge(win);
    client.link.request({ operationName: 'RestaurantsAvailability', query: DOC });

    dispatch(
      { __fetchproxy: 'graphql-req', reqId: 3, operationName: 'RestaurantsAvailability', variables: {} },
      { some: 'other-window' },
    );
    await flush();

    expect(client.query).not.toHaveBeenCalled();
    expect(posted).toHaveLength(0);
  });

  it('ignores malformed / unrelated messages without throwing', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    const client = makeClient({ availability: [1] });
    win.__APOLLO_CLIENT__ = client;
    installApolloBridge(win);

    dispatch(null);
    dispatch('a string');
    dispatch({ __fetchproxy: 'something-else', reqId: 1, operationName: 'X' });
    dispatch({ __fetchproxy: 'graphql-req' }); // missing reqId/operationName
    dispatch({ __fetchproxy: 'graphql-req', reqId: 'x', operationName: 'RestaurantsAvailability' });
    await flush();

    expect(posted).toHaveLength(0);
  });

  it('does not throw when no Apollo client is present yet', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    // no __APOLLO_CLIENT__ set
    expect(() => installApolloBridge(win)).not.toThrow();

    dispatch({ __fetchproxy: 'graphql-req', reqId: 5, operationName: 'RestaurantsAvailability', variables: {} });
    await flush();

    const res = posted[0] as { reqId: number; ok: boolean; error: string };
    expect(res.reqId).toBe(5);
    expect(res.ok).toBe(false);
    expect(res.error).toContain('not yet observed');
  });
});
