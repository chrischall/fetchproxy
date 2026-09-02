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
let interceptClientAssignment: (win: BridgeWindow, onAssigned: () => void) => boolean;

beforeAll(async () => {
  ({ installApolloBridge, interceptClientAssignment } = await import('../src/capture-logger.js'));
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

/** Whether the bridge has instrumented this client's link. */
const wrapFlag = (c: { link: { request: unknown } }): boolean =>
  (c.link.request as { __fetchproxyWrapped?: boolean }).__fetchproxyWrapped === true;

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

    const first = makeClient({});
    win.__APOLLO_CLIENT__ = first;

    // Devtools and the page itself read this back; it must be the same object.
    expect(win.__APOLLO_CLIENT__).toBe(first);

    // Reassignment (SPA re-creating its client) must re-wrap the NEW client's
    // link. Asserting the mock "was called" would pass without any wrapping at
    // all — the wrap flag is the thing that actually proves re-instrumentation.
    const second = makeClient({});
    win.__APOLLO_CLIENT__ = second;
    expect(win.__APOLLO_CLIENT__).toBe(second);
    expect(wrapFlag(second)).toBe(true);
    expect(wrapFlag(first)).toBe(true);
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

  it('serves an op recorded through a REPLACED client (docs survive the swap)', async () => {
    const { win, posted, dispatch } = makeFakeWindow();
    installApolloBridge(win);

    const first = makeClient({ from: 'first' });
    win.__APOLLO_CLIENT__ = first;
    first.link.request({ operationName: 'FirstOp', query: DOC });

    // The app re-creates its client (route change / auth refresh).
    const second = makeClient({ from: 'second' });
    win.__APOLLO_CLIENT__ = second;
    const SECOND_DOC = { kind: 'Document', __id: 'second-doc' };
    second.link.request({ operationName: 'SecondOp', query: SECOND_DOC });

    // An op seen only through the NEW client must be answerable...
    dispatch({ __fetchproxy: 'graphql-req', reqId: 21, operationName: 'SecondOp', variables: {} });
    await flush();
    expect(second.query).toHaveBeenCalledWith({
      query: SECOND_DOC,
      variables: {},
      fetchPolicy: 'no-cache',
      errorPolicy: 'all',
    });
    expect(posted).toContainEqual({
      __fetchproxy: 'graphql-res',
      reqId: 21,
      ok: true,
      data: { from: 'second' },
    });

    // ...and one recorded before the swap must not be lost.
    dispatch({ __fetchproxy: 'graphql-req', reqId: 22, operationName: 'FirstOp', variables: {} });
    await flush();
    expect(second.query).toHaveBeenCalledWith({
      query: DOC,
      variables: {},
      fetchPolicy: 'no-cache',
      errorPolicy: 'all',
    });
  });

  it('stays readable when a prior GETTER exists but no setter', () => {
    const { win } = makeFakeWindow();
    // A devtools hook or another extension installed a read-only accessor.
    // Chaining the getter while owning the setter would strand every value
    // the page assigns: written to our storage, read back from theirs.
    let theirs: unknown = undefined;
    Object.defineProperty(win, '__APOLLO_CLIENT__', {
      configurable: true,
      get: () => theirs,
    });

    installApolloBridge(win);

    const client = makeClient({});
    win.__APOLLO_CLIENT__ = client;

    expect(win.__APOLLO_CLIENT__).toBe(client);
    expect(wrapFlag(client)).toBe(true);
  });

  it('delegates to a prior getter+setter pair and stays readable', () => {
    const { win } = makeFakeWindow();
    let theirs: unknown = undefined;
    const seen: unknown[] = [];
    Object.defineProperty(win, '__APOLLO_CLIENT__', {
      configurable: true,
      get: () => theirs,
      set: (v) => {
        seen.push(v);
        theirs = v;
      },
    });

    installApolloBridge(win);

    const client = makeClient({});
    win.__APOLLO_CLIENT__ = client;

    // Their setter still runs (side effects preserved) and the value reads back.
    expect(seen).toEqual([client]);
    expect(win.__APOLLO_CLIENT__).toBe(client);
    expect(wrapFlag(client)).toBe(true);
  });

  it('seeds storage from a prior getter (interceptClientAssignment directly)', () => {
    // Driven through `interceptClientAssignment` rather than
    // `installApolloBridge`: the latter's initial `tryWrap()` succeeds against
    // any client with a usable link and returns BEFORE installing the
    // interceptor, so a test that goes through it reads the ORIGINAL getter
    // and passes whether or not seeding works.
    const { win } = makeFakeWindow();
    const existing = makeClient({});
    Object.defineProperty(win, '__APOLLO_CLIENT__', {
      configurable: true,
      get: () => existing,
    });

    expect(interceptClientAssignment(win, () => {})).toBe(true);

    // Read now goes through OUR accessor (getter-only prior ⇒ we own storage),
    // so the pre-existing value only survives if it was seeded across.
    expect(win.__APOLLO_CLIENT__).toBe(existing);
  });

  it('survives a prior getter that throws', () => {
    const { win } = makeFakeWindow();
    Object.defineProperty(win, '__APOLLO_CLIENT__', {
      configurable: true,
      get: () => {
        throw new Error('hostile getter');
      },
    });

    expect(() => interceptClientAssignment(win, () => {})).not.toThrow();
    expect(win.__APOLLO_CLIENT__).toBeUndefined();

    const client = makeClient({});
    win.__APOLLO_CLIENT__ = client;
    expect(win.__APOLLO_CLIENT__).toBe(client);
  });

  it('reaches the interceptor when the existing client has no usable link', () => {
    // The real path to seeding: `tryWrap()` fails (nothing to wrap), so
    // `installApolloBridge` goes on to install the interceptor while a prior
    // getter still holds a value.
    const { win } = makeFakeWindow();
    const linkless = { query: vi.fn(async () => ({ data: {} })) };
    Object.defineProperty(win, '__APOLLO_CLIENT__', {
      configurable: true,
      get: () => linkless,
    });

    installApolloBridge(win);

    expect(win.__APOLLO_CLIENT__).toBe(linkless);
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
