// @vitest-environment jsdom

import { describe, it, expect, beforeAll, vi } from 'vitest';

/**
 * Regression cover for the load-time capture race (#261).
 *
 * `installApolloBridge` used to only POLL for `window.__APOLLO_CLIENT__`
 * every 500ms before wrapping `client.link.request`. A route's own load-time
 * query reliably fires inside that window, so the operation the user just
 * watched the page run was the one operation never recorded — and the error
 * told them to "open a page that triggers this operation", which is exactly
 * what does not work. Only *interacting* with the page (firing a second
 * query) populated the cache.
 *
 * Observed live on opentable.com with the bridge installed and 10 slot
 * buttons rendered from the operation's own result:
 *   { bridgeWrapped: true, slotsVisibleOnPage: 10, docCapturedFromPageLoad: false }
 *
 * The bridge must therefore be in place the moment Apollo ASSIGNS the client,
 * not up to a poll interval later.
 */

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

/**
 * Fake window whose `setInterval` NEVER fires. That is the whole point: it
 * isolates "wrapped at assignment" from "wrapped by a later poll tick", so a
 * test can only pass if the assignment path works.
 */
function makeFakeWindow(): {
  win: BridgeWindow;
  posted: unknown[];
  dispatch: (data: unknown) => void;
  pollsScheduled: () => number;
} {
  const listeners: Record<string, Array<(e: unknown) => void>> = {};
  const posted: unknown[] = [];
  let polls = 0;
  const win: BridgeWindow = {
    __APOLLO_CLIENT__: undefined,
    addEventListener(type, fn) {
      (listeners[type] ||= []).push(fn);
    },
    removeEventListener(type, fn) {
      listeners[type] = (listeners[type] || []).filter((f) => f !== fn);
    },
    postMessage(message) {
      posted.push(message);
    },
    setInterval() {
      polls += 1;
      return 0;
    },
    clearInterval() {
      /* noop */
    },
    location: { origin: 'https://www.opentable.com' },
  };
  const dispatch = (data: unknown): void => {
    for (const fn of listeners.message || []) fn({ source: win, data, origin: win.location.origin });
  };
  return { win, posted, dispatch, pollsScheduled: () => polls };
}

function makeClient(data: unknown) {
  return {
    link: { request: vi.fn(() => 'ORIGINAL_LINK_RESULT') },
    query: vi.fn(async () => ({ data })),
  };
}

const DOC = { kind: 'Document', __id: 'RestaurantsAvailability-doc' };

describe('installApolloBridge — client assigned after install (#261)', () => {
  it('captures the page’s FIRST query, dispatched right after assignment', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    installApolloBridge(win); // document_start: Apollo has not run yet

    // Apollo's constructor assigns the client, then the route immediately
    // fires its load-time query. No poll tick happens in between.
    const client = makeClient({ availability: [1, 2, 3] });
    win.__APOLLO_CLIENT__ = client;
    const passthrough = client.link.request(
      { operationName: 'RestaurantsAvailability', query: DOC },
      'FWD',
    );

    // Wrapping must never disturb the page's own request path.
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

  it('keeps the assigned client readable and identical (transparent accessor)', () => {
    const { win } = makeFakeWindow();
    installApolloBridge(win);

    const client = makeClient({});
    win.__APOLLO_CLIENT__ = client;

    // Devtools and the page itself read this back; it must be the same object.
    expect(win.__APOLLO_CLIENT__).toBe(client);

    // Reassignment (SPA re-creating its client) must re-wrap the new one.
    const second = makeClient({});
    win.__APOLLO_CLIENT__ = second;
    expect(win.__APOLLO_CLIENT__).toBe(second);
    second.link.request({ operationName: 'SecondOp', query: DOC });
    expect(second.link.request).toHaveBeenCalled();
  });

  it('still wraps a client that already exists at install time', () => {
    const { win } = makeFakeWindow();
    const client = makeClient({});
    win.__APOLLO_CLIENT__ = client;

    installApolloBridge(win);

    client.link.request({ operationName: 'RestaurantsAvailability', query: DOC });
    expect((client.link.request as unknown as { __fetchproxyWrapped?: boolean }).__fetchproxyWrapped).toBe(
      true,
    );
  });

  it('falls back to polling when the property cannot be redefined', () => {
    const { win, pollsScheduled } = makeFakeWindow();
    // A non-configurable property (another extension got there first, or the
    // page froze it) must not throw and must not lose the fallback.
    Object.defineProperty(win, '__APOLLO_CLIENT__', {
      value: undefined,
      writable: true,
      configurable: false,
    });

    expect(() => installApolloBridge(win)).not.toThrow();
    expect(pollsScheduled()).toBeGreaterThan(0);
  });
});
