// @vitest-environment jsdom

import { describe, it, expect, beforeAll, vi } from 'vitest';

/**
 * The two halves of the in-page fetch path:
 *   - `runInPageFetch` (content.ts, ISOLATED world) — relays and validates.
 *   - `installFetchBridge` (capture-logger.ts, MAIN world) — performs it.
 *
 * Both worlds share one message bus, so the isolated side must treat every
 * reply as untrusted: page script can forge a `fetch-res`. It gains nothing
 * by doing so (it could issue the request itself, and the reply only returns
 * to the MCP that asked), but a malformed shape reaching the server's
 * validators would tear down the socket for every MCP on the concentrator.
 */

let runInPageFetch: (
  init: { url: string; method: string; headers?: Record<string, string>; body?: string; tabUrl: string },
  win: FakeWin,
  timeoutMs?: number,
) => Promise<unknown>;
let installFetchBridge: (win: FakeMainWin) => void;

beforeAll(async () => {
  // content.ts registers a chrome.runtime.onMessage listener at module load,
  // so a minimal `chrome` stub must exist before the (dynamic) import.
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: { onMessage: { addListener: () => {} } },
  };
  ({ runInPageFetch } = await import('../src/content.js'));
  ({ installFetchBridge } = await import('../src/capture-logger.js'));
});

interface FakeWin {
  addEventListener: (t: string, fn: (e: MessageEvent) => void) => void;
  removeEventListener: (t: string, fn: (e: MessageEvent) => void) => void;
  postMessage: (m: unknown, o?: string) => void;
  location: { origin: string };
}
type FakeMainWin = Record<string, unknown>;

const INIT = {
  url: 'https://www.opentable.com/dapi/fe/gql?optype=mutation',
  method: 'POST',
  headers: { 'x-csrf-token': 'tok' },
  body: '{"operationName":"BookDetailsStandardSlotLock"}',
  tabUrl: 'https://www.opentable.com/',
};

/** Isolated-world stand-in; `reply` posts back as if the MAIN world answered. */
function makeIsolatedWin(): {
  win: FakeWin;
  posted: Record<string, unknown>[];
  reply: (payload: Record<string, unknown>) => void;
  listenerCount: () => number;
} {
  const listeners: ((e: MessageEvent) => void)[] = [];
  const posted: Record<string, unknown>[] = [];
  const win: FakeWin = {
    addEventListener: (_t, fn) => void listeners.push(fn),
    removeEventListener: (_t, fn) => {
      const i = listeners.indexOf(fn);
      if (i >= 0) listeners.splice(i, 1);
    },
    postMessage: (m) => void posted.push(m as Record<string, unknown>),
    location: { origin: 'https://www.opentable.com' },
  };
  const reply = (payload: Record<string, unknown>): void => {
    for (const fn of [...listeners]) {
      fn({ source: win, data: payload } as unknown as MessageEvent);
    }
  };
  return { win, posted, reply, listenerCount: () => listeners.length };
}

describe('runInPageFetch (isolated → MAIN relay)', () => {
  it('posts a fetch-req carrying url/method/headers/body, and resolves the reply', async () => {
    const { win, posted, reply } = makeIsolatedWin();
    const p = runInPageFetch(INIT, win);

    expect(posted).toHaveLength(1);
    expect(posted[0]).toMatchObject({
      __fetchproxy: 'fetch-req',
      url: INIT.url,
      method: 'POST',
      headers: { 'x-csrf-token': 'tok' },
      body: INIT.body,
    });

    reply({
      __fetchproxy: 'fetch-res',
      reqId: posted[0]!.reqId,
      ok: true,
      status: 200,
      url: INIT.url,
      body: '{"data":{"lockSlot":{}}}',
    });

    await expect(p).resolves.toEqual({
      ok: true,
      status: 200,
      url: INIT.url,
      body: '{"data":{"lockSlot":{}}}',
    });
  });

  it('ignores a reply bearing a different reqId', async () => {
    const { win, posted, reply } = makeIsolatedWin();
    const p = runInPageFetch(INIT, win, 50);
    reply({ __fetchproxy: 'fetch-res', reqId: (posted[0]!.reqId as number) + 999, ok: true, status: 200, url: 'x', body: 'y' });
    // Nothing matched, so it must fall through to the timeout, not resolve.
    await expect(p).resolves.toMatchObject({ ok: false });
  });

  it('rejects a forged reply whose status/url/body are the wrong types', async () => {
    for (const bad of [
      { ok: true, status: '200', url: 'u', body: 'b' },
      { ok: true, status: 200, url: 5, body: 'b' },
      { ok: true, status: 200, url: 'u', body: { not: 'a string' } },
    ]) {
      const { win, posted, reply } = makeIsolatedWin();
      const p = runInPageFetch(INIT, win, 50);
      reply({ __fetchproxy: 'fetch-res', reqId: posted[0]!.reqId, ...bad });
      const r = (await p) as { ok: boolean; error: string };
      expect(r.ok).toBe(false);
      expect(r.error).toMatch(/non-numeric status|non-string url\/body/);
    }
  });

  it('caps an oversized body instead of forwarding it to the background', async () => {
    const { win, posted, reply } = makeIsolatedWin();
    const p = runInPageFetch(INIT, win, 50);
    reply({
      __fetchproxy: 'fetch-res',
      reqId: posted[0]!.reqId,
      ok: true,
      status: 200,
      url: 'u',
      body: 'x'.repeat(5 * 1024 * 1024 + 1),
    });
    const r = (await p) as { ok: boolean; error: string };
    expect(r.ok).toBe(false);
    expect(r.error).toContain('response body too large');
  });

  it('surfaces an ok:false reply and removes its listener on settle', async () => {
    const { win, posted, reply, listenerCount } = makeIsolatedWin();
    const p = runInPageFetch(INIT, win);
    reply({ __fetchproxy: 'fetch-res', reqId: posted[0]!.reqId, ok: false, error: 'fetch threw: boom' });
    await expect(p).resolves.toEqual({ ok: false, error: 'fetch threw: boom' });
    expect(listenerCount()).toBe(0);
  });

  it('times out rather than hanging when the MAIN world never answers', async () => {
    const { win } = makeIsolatedWin();
    const r = (await runInPageFetch(INIT, win, 20)) as { ok: boolean; error: string };
    expect(r.ok).toBe(false);
    expect(r.error).toContain('timed out');
  });
});

describe('installFetchBridge (MAIN world)', () => {
  function makeMainWin(fetchImpl: unknown): {
    win: FakeMainWin;
    posted: Record<string, unknown>[];
    dispatch: (data: unknown, source?: unknown) => void;
  } {
    const listeners: ((e: unknown) => void)[] = [];
    const posted: Record<string, unknown>[] = [];
    const win: FakeMainWin = {
      fetch: fetchImpl,
      addEventListener: (_t: string, fn: (e: unknown) => void) => void listeners.push(fn),
      postMessage: (m: unknown) => void posted.push(m as Record<string, unknown>),
      location: { origin: 'https://www.opentable.com' },
    };
    const dispatch = (data: unknown, source: unknown = win): void => {
      for (const fn of listeners) fn({ source, data });
    };
    return { win, posted, dispatch };
  }

  const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

  it('performs the fetch with credentials and posts the result back', async () => {
    const fetchMock = vi.fn(async () => ({
      status: 200,
      url: 'https://www.opentable.com/dapi/fe/gql',
      text: async () => '{"data":{"lockSlot":{"slotLockId":1}}}',
    }));
    const { win, posted, dispatch } = makeMainWin(fetchMock);
    installFetchBridge(win as never);

    dispatch({
      __fetchproxy: 'fetch-req',
      reqId: 7,
      url: 'https://www.opentable.com/dapi/fe/gql',
      method: 'POST',
      headers: { 'x-csrf-token': 'tok' },
      body: '{}',
    });
    await flush();

    expect(fetchMock).toHaveBeenCalledWith('https://www.opentable.com/dapi/fe/gql', {
      method: 'POST',
      headers: { 'x-csrf-token': 'tok' },
      body: '{}',
      credentials: 'include',
    });
    expect(posted).toContainEqual({
      __fetchproxy: 'fetch-res',
      reqId: 7,
      ok: true,
      status: 200,
      url: 'https://www.opentable.com/dapi/fe/gql',
      body: '{"data":{"lockSlot":{"slotLockId":1}}}',
    });
  });

  it('reports a throwing fetch as ok:false instead of dying', async () => {
    const { win, posted, dispatch } = makeMainWin(async () => {
      throw new Error('network down');
    });
    installFetchBridge(win as never);
    dispatch({ __fetchproxy: 'fetch-req', reqId: 8, url: 'https://www.opentable.com/x', method: 'GET' });
    await flush();
    expect(posted[0]).toMatchObject({ __fetchproxy: 'fetch-res', reqId: 8, ok: false });
    expect(String(posted[0]!.error)).toContain('network down');
  });

  it('ignores messages from another window and non-fetch-req envelopes', async () => {
    const fetchMock = vi.fn();
    const { win, posted, dispatch } = makeMainWin(fetchMock);
    installFetchBridge(win as never);

    dispatch({ __fetchproxy: 'fetch-req', reqId: 1, url: 'https://x/', method: 'GET' }, { other: 'window' });
    dispatch({ __fetchproxy: 'graphql-req', reqId: 2, operationName: 'X' });
    dispatch({ __fetchproxy: 'fetch-req', reqId: 3 }); // no url
    await flush();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(posted).toHaveLength(0);
  });
});
