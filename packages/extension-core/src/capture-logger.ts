/**
 * MAIN-world bridge script. The isolated-world content script can read
 * cookies + run `window.fetch` with `credentials: 'include'`, but it
 * CAN'T see page-level globals like `window.__CSRF_TOKEN__` (those live
 * in the page MAIN world, isolated from the extension's content scripts).
 *
 * This script runs in MAIN world and does two things:
 *
 *  1. Copies a small set of well-known page globals onto
 *     `document.documentElement.dataset` so the isolated-world content
 *     script can pick them up and forward them as headers on the fetch.
 *     v1 hardcodes one mapping: `window.__CSRF_TOKEN__` →
 *     `data-fetchproxy-csrf`, which `content.ts` reads + sets as
 *     `x-csrf-token` on every fetch. This is what OpenTable + similar
 *     Akamai-fronted sites need to clear their bot check.
 *
 *  2. Runs the Apollo GraphQL bridge (`graphql` capability). Some
 *     endpoints (OpenTable's `RestaurantsAvailability`) reject the
 *     isolated world's pristine `fetch` at Akamai's edge — the sensor
 *     telemetry lives inside the page's own Apollo link chain, not on
 *     `window.fetch`. So we route those operations through the page's
 *     real `window.__APOLLO_CLIENT__`: we wrap `client.link.request` to
 *     capture the live `RestaurantsAvailability` DocumentNode (it has no
 *     printable source and its persisted hash is added by a lower link,
 *     so it can only be reused, never hardcoded), then answer isolated-
 *     world `postMessage` requests by invoking `client.query` with that
 *     captured document + the MCP's variables. Whatever telemetry link
 *     OpenTable wired in runs automatically — this IS the organic path.
 *
 * Security: dataset attributes are readable by any same-origin script.
 * The page's own scripts already have window.__CSRF_TOKEN__, so this
 * doesn't expand the same-origin attack surface. Cross-origin code
 * cannot read another origin's DOM datasets. The Apollo bridge only
 * accepts messages where `event.source === window` (our own window's
 * message bus, shared by MAIN + isolated worlds — a cross-origin frame
 * has a different `source`) carrying the private `__fetchproxy` marker,
 * and only ever invokes operations the page's own client has observed.
 */

import { notYetObservedError } from './lib/graphql-observed.js';

/* eslint-disable @typescript-eslint/no-explicit-any */

declare global {
  interface Window {
    __CSRF_TOKEN__?: string;
    __APOLLO_CLIENT__?: unknown;
  }
}

const SYNC_INTERVAL_MS = 2000;
const DATASET_KEY = 'fetchproxyCsrf';

function syncCsrf(): void {
  const token = window.__CSRF_TOKEN__;
  if (typeof token === 'string' && token.length > 0) {
    document.documentElement.dataset[DATASET_KEY] = token;
  } else {
    delete document.documentElement.dataset[DATASET_KEY];
  }
}

// ---------------------------------------------------------------------------
// Apollo GraphQL bridge (MAIN world)
// ---------------------------------------------------------------------------

const APOLLO_POLL_INTERVAL_MS = 500;

/** The private marker on the isolated ⇄ MAIN `postMessage` envelope. */
const REQ_MARKER = 'graphql-req';
const RES_MARKER = 'graphql-res';

interface ApolloOperationLike {
  operationName?: string;
  query?: unknown;
}

interface ApolloLinkLike {
  request?: (operation: ApolloOperationLike, forward?: unknown) => unknown;
}

interface ApolloClientLike {
  link?: ApolloLinkLike;
  query?: (opts: {
    query: unknown;
    variables: unknown;
    fetchPolicy: string;
    errorPolicy: string;
  }) => Promise<{ data?: unknown; errors?: readonly unknown[] } | undefined>;
}

/**
 * Subset of `Window` the Apollo bridge touches. A fake stand-in is used in
 * unit tests so the strict `event.source === window` guard is exercised
 * without depending on jsdom's `postMessage` delivery semantics.
 */
export interface ApolloBridgeWindow {
  __APOLLO_CLIENT__?: unknown;
  addEventListener: (type: string, fn: (e: any) => void) => void;
  postMessage: (message: unknown, targetOrigin?: string) => void;
  setInterval: (fn: () => void, ms: number) => any;
  clearInterval: (id: any) => void;
  location?: { origin?: string };
}

function post(win: ApolloBridgeWindow, message: unknown): void {
  try {
    win.postMessage(message, win.location?.origin ?? '*');
  } catch {
    // A failed post-back can't be surfaced anywhere useful; the isolated
    // world's request will simply time out. Never throw out of the bridge.
  }
}

/**
 * Wrap `client.link.request` so every operation that flows through the
 * page's Apollo link chain records its live DocumentNode by operationName.
 * Idempotent (won't double-wrap). Returns false if the client has no
 * usable link yet (caller keeps polling). Recording never breaks the real
 * request path — the wrapper always calls through to the original.
 */
export function recordDocsFromLink(
  client: ApolloClientLike,
  docsByOp: Map<string, unknown>,
): boolean {
  const link = client.link;
  if (!link || typeof link.request !== 'function') return false;
  if ((link.request as any).__fetchproxyWrapped) return true;
  const original = link.request.bind(link);
  const wrapped = function (operation: ApolloOperationLike, forward?: unknown): unknown {
    try {
      if (
        operation &&
        typeof operation.operationName === 'string' &&
        operation.query !== undefined &&
        operation.query !== null
      ) {
        docsByOp.set(operation.operationName, operation.query);
      }
    } catch {
      // Recording is best-effort; never let it break the page's request.
    }
    return original(operation, forward);
  };
  (wrapped as any).__fetchproxyWrapped = true;
  link.request = wrapped;
  return true;
}

async function handleGraphqlRequest(
  win: ApolloBridgeWindow,
  docsByOp: Map<string, unknown>,
  client: ApolloClientLike | undefined,
  reqId: number,
  operationName: string,
  variables: unknown,
): Promise<void> {
  const doc = docsByOp.get(operationName);
  if (doc === undefined || !client || typeof client.query !== 'function') {
    post(win, {
      __fetchproxy: RES_MARKER,
      reqId,
      ok: false,
      error: notYetObservedError(operationName),
    });
    return;
  }
  try {
    const safeVars =
      variables && typeof variables === 'object' && !Array.isArray(variables)
        ? (variables as Record<string, unknown>)
        : {};
    const res = await client.query({
      query: doc,
      variables: safeVars,
      fetchPolicy: 'no-cache',
      errorPolicy: 'all',
    });
    // `errorPolicy: 'all'` is precisely the policy under which Apollo does
    // NOT throw on a GraphQL-level error — client.query resolves with
    // `{ data: null | undefined, errors: [...] }` instead (e.g. an expired
    // session, or an error on a non-nullable root field). That must surface
    // as an `ok: false` protocol failure here, where `res.errors` is still
    // in hand — letting `data: null` through as `ok: true` fails
    // `assertObject` in validateInnerResponse and, via host.ts's catch-all,
    // tears down the extension WebSocket for every MCP on the concentrator.
    const errors = Array.isArray(res?.errors) ? res.errors : undefined;
    if (errors && errors.length > 0) {
      const messages = errors.map((e) =>
        e && typeof e === 'object' && 'message' in e ? String((e as { message: unknown }).message) : String(e),
      );
      post(win, {
        __fetchproxy: RES_MARKER,
        reqId,
        ok: false,
        error: `graphql errors: ${messages.join('; ')}`,
      });
      return;
    }
    if (res?.data === null || res?.data === undefined) {
      post(win, {
        __fetchproxy: RES_MARKER,
        reqId,
        ok: false,
        error: 'graphql query resolved with no data and no errors',
      });
      return;
    }
    post(win, { __fetchproxy: RES_MARKER, reqId, ok: true, data: res.data });
  } catch (e) {
    post(win, {
      __fetchproxy: RES_MARKER,
      reqId,
      ok: false,
      error: (e as Error)?.message ?? String(e),
    });
  }
}

/**
 * Wrap `__APOLLO_CLIENT__` in a transparent accessor so `onAssigned` runs the
 * instant Apollo assigns the client, before the page can dispatch anything
 * through it.
 *
 * Polling alone loses the page's OWN load-time query: Apollo constructs the
 * client and the route fires its first operation in the same task, while the
 * next poll tick is up to `APOLLO_POLL_INTERVAL_MS` away. That made the one
 * operation the user just watched run the one operation never recorded, and
 * the resulting error told them to open a page that triggers it — the exact
 * thing that does not work (#261).
 *
 * The accessor must be invisible to everyone else: it chains to a getter or
 * setter that is already there (devtools hook, another extension) instead of
 * replacing it, and it never lets a recording failure escape into the page's
 * assignment. Returns false when the property can't be redefined, so the
 * caller keeps its polling fallback.
 */
export function interceptClientAssignment(
  win: ApolloBridgeWindow,
  onAssigned: () => void,
): boolean {
  try {
    const prior = Object.getOwnPropertyDescriptor(win, '__APOLLO_CLIENT__');
    if (prior && prior.configurable === false) return false;
    const priorGet = prior && typeof prior.get === 'function' ? prior.get : undefined;
    const priorSet = prior && typeof prior.set === 'function' ? prior.set : undefined;
    // Reads and writes must land in the SAME place. Delegating the getter while
    // owning the setter (the shape a prior getter-only accessor produces) would
    // strand every client the page assigns: written to `stored`, read back from
    // theirs — leaving `__APOLLO_CLIENT__` permanently undefined, which breaks
    // the page, devtools, and this bridge's own read of it.
    const delegate = priorGet !== undefined && priorSet !== undefined;
    let stored: unknown;
    if (prior && 'value' in prior) stored = prior.value;
    else if (priorGet !== undefined) {
      // Seed from the prior getter so a value that already exists behind it
      // survives the swap.
      try {
        stored = priorGet.call(win);
      } catch {
        stored = undefined;
      }
    }
    Object.defineProperty(win, '__APOLLO_CLIENT__', {
      configurable: true,
      enumerable: prior ? prior.enumerable !== false : true,
      get(this: unknown): unknown {
        return delegate ? (priorGet as () => unknown).call(this) : stored;
      },
      set(this: unknown, value: unknown): void {
        if (!delegate) stored = value;
        // Run any prior setter either way, so another extension's side effects
        // still fire even when we own the storage.
        if (priorSet !== undefined) {
          try {
            priorSet.call(this, value);
          } catch {
            // Their setter throwing is their problem, not the page's.
          }
        }
        try {
          onAssigned();
        } catch {
          // The page is mid-assignment; a recording failure must not surface
          // as an exception thrown from `window.__APOLLO_CLIENT__ = client`.
        }
      },
    });
    return true;
  } catch {
    // Frozen window, hostile descriptor, exotic environment — the poll below
    // is still a correct (just slower) way to find the client.
    return false;
  }
}

/**
 * Install the Apollo bridge on `win`. Registers the `message` listener
 * immediately (so a request that arrives before the client exists gets a
 * clean "not yet observed" answer rather than being dropped), then wraps
 * `__APOLLO_CLIENT__`'s link by two paths: an assignment interceptor, which
 * catches the client the moment Apollo creates it (and so catches the page's
 * own first query), and a poll, which stays as the fallback for a client that
 * already exists, one whose `link` isn't usable yet at assignment time, and
 * any window where the property can't be redefined.
 */
export function installApolloBridge(win: ApolloBridgeWindow): void {
  const docsByOp = new Map<string, unknown>();
  // The client that is currently instrumented — NOT a boolean. An app that
  // re-creates its Apollo client (route change, auth refresh) assigns a fresh
  // one whose link has never been wrapped; latching on "we wrapped something
  // once" would leave the bridge deaf to every operation after that swap.
  // `docsByOp` is deliberately shared, so documents survive the swap.
  let wrappedClient: unknown = null;

  const tryWrap = (): boolean => {
    const client = win.__APOLLO_CLIENT__ as ApolloClientLike | undefined;
    if (!client) return false;
    if (client === wrappedClient) return true;
    if (recordDocsFromLink(client, docsByOp)) {
      wrappedClient = client;
      return true;
    }
    return false;
  };

  win.addEventListener('message', (event: any) => {
    try {
      if (!event || event.source !== win) return;
      const data = event.data;
      if (!data || typeof data !== 'object' || data.__fetchproxy !== REQ_MARKER) return;
      if (typeof data.reqId !== 'number' || typeof data.operationName !== 'string') return;
      void handleGraphqlRequest(
        win,
        docsByOp,
        win.__APOLLO_CLIENT__ as ApolloClientLike | undefined,
        data.reqId,
        data.operationName,
        data.variables,
      ).catch(() => {
        /* handleGraphqlRequest never rejects, but stay defensive. */
      });
    } catch {
      // Never throw out of a window 'message' listener.
    }
  });

  if (tryWrap()) return;

  // Best-effort: closes the race against the page's load-time query.
  interceptClientAssignment(win, tryWrap);

  // Kept regardless — `tryWrap` can legitimately fail at assignment (a client
  // whose `link` isn't wired yet), and the interceptor may not have installed
  // at all. Cleared by the first tick that finds the link, as before.
  const timer = win.setInterval(() => {
    if (tryWrap()) win.clearInterval(timer);
  }, APOLLO_POLL_INTERVAL_MS);
}

// ---------------------------------------------------------------------------
// Module-load side effects (skipped under vitest so tests drive the exported
// functions against a controlled fake window instead of the global one).
// ---------------------------------------------------------------------------

// Reference `process` via globalThis so this browser-targeted bundle (whose
// tsconfig omits node types) doesn't need them; the value is only truthy
// under vitest.
const underTest = !!(globalThis as any)?.process?.env?.VITEST;

if (!underTest && typeof window !== 'undefined') {
  // First sync immediately so a fetch issued right after extension load
  // has the token; then refresh every 2s in case the page rotates it.
  syncCsrf();
  setInterval(syncCsrf, SYNC_INTERVAL_MS);
  installApolloBridge(window as unknown as ApolloBridgeWindow);
}
