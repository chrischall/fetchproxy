// @vitest-environment jsdom
import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';

/**
 * S-SEC-4 — the page's `window.__CSRF_TOKEN__` is no longer copied into a
 * `<html data-fetchproxy-csrf>` attribute on every site. It lived there,
 * refreshed every 2s, on every page the user visited, where CSS attribute
 * selectors (an HTML/CSS injection with no script) could exfiltrate it. The
 * isolated world now asks the MAIN world for it over the shared message bus,
 * and only while serving a fetch the background already approved.
 */

type CsrfWin = {
  __CSRF_TOKEN__?: unknown;
  addEventListener: (t: string, fn: (e: MessageEvent) => void) => void;
  removeEventListener: (t: string, fn: (e: MessageEvent) => void) => void;
  postMessage: (m: unknown, o?: string) => void;
  location: { origin: string };
};

let installCsrfBridge: (win: CsrfWin) => void;
let readPageCsrfToken: (win: CsrfWin, timeoutMs?: number) => Promise<string | undefined>;
let runFetch: (
  init: Record<string, unknown>,
  getCsrf?: () => Promise<string | undefined>,
) => Promise<unknown>;

beforeAll(async () => {
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: { onMessage: { addListener: () => {} } },
  };
  ({ installCsrfBridge } = (await import('../src/capture-logger.js')) as unknown as {
    installCsrfBridge: typeof installCsrfBridge;
  });
  ({ readPageCsrfToken, runFetch } = (await import('../src/content.js')) as unknown as {
    readPageCsrfToken: typeof readPageCsrfToken;
    runFetch: typeof runFetch;
  });
});

/** One window object shared by both worlds, as in a real tab; delivery is async. */
function makeWin(token?: unknown): {
  win: CsrfWin;
  posted: unknown[];
  deliver: (source: unknown, data: unknown) => void;
} {
  const listeners: ((e: MessageEvent) => void)[] = [];
  const posted: unknown[] = [];
  const win: CsrfWin = {
    __CSRF_TOKEN__: token,
    addEventListener: (_t, fn) => void listeners.push(fn),
    removeEventListener: (_t, fn) => {
      const i = listeners.indexOf(fn);
      if (i >= 0) listeners.splice(i, 1);
    },
    postMessage: (m) => {
      posted.push(m);
      queueMicrotask(() => {
        for (const fn of [...listeners]) fn({ source: win, data: m } as unknown as MessageEvent);
      });
    },
    location: { origin: 'https://www.opentable.com' },
  };
  const deliver = (source: unknown, data: unknown): void => {
    for (const fn of [...listeners]) fn({ source, data } as unknown as MessageEvent);
  };
  return { win, posted, deliver };
}

describe('CSRF token on demand (S-SEC-4)', () => {
  it('the MAIN-world bridge answers a request with the page token', async () => {
    const { win } = makeWin('tok-page');
    installCsrfBridge(win);
    await expect(readPageCsrfToken(win, 200)).resolves.toBe('tok-page');
  });

  it('resolves undefined when the page defines no token', async () => {
    const { win } = makeWin(undefined);
    installCsrfBridge(win);
    await expect(readPageCsrfToken(win, 200)).resolves.toBeUndefined();
  });

  it('resolves undefined on timeout when no MAIN-world bridge answers', async () => {
    const { win } = makeWin('tok-page');
    await expect(readPageCsrfToken(win, 20)).resolves.toBeUndefined();
  });

  it('ignores a reply from another source', async () => {
    const { win, posted, deliver } = makeWin('tok');
    const p = readPageCsrfToken(win, 30);
    const reqId = (posted[0] as { reqId: number }).reqId;
    deliver({ not: 'this window' }, { __fetchproxy: 'csrf-res', reqId, token: 'evil' });
    await expect(p).resolves.toBeUndefined();
  });

  it('never writes the token into the DOM', async () => {
    const { win } = makeWin('tok-page');
    installCsrfBridge(win);
    await readPageCsrfToken(win, 200);
    expect(document.documentElement.dataset.fetchproxyCsrf).toBeUndefined();
    expect(document.documentElement.hasAttribute('data-fetchproxy-csrf')).toBe(false);
  });

  describe('runFetch', () => {
    const fetchMock = vi.fn();
    beforeEach(() => {
      fetchMock.mockReset();
      fetchMock.mockResolvedValue({ status: 200, url: 'u', text: async () => '{}' });
      (globalThis as { fetch?: unknown }).fetch = fetchMock;
    });

    it('injects the token fetched on demand', async () => {
      await runFetch(
        {
          url: 'https://www.opentable.com/x',
          method: 'POST',
          body: '{}',
          tabUrl: 'https://www.opentable.com/',
        },
        async () => 'tok-demand',
      );
      const init = fetchMock.mock.calls[0]![1] as { headers: Record<string, string> };
      expect(init.headers['x-csrf-token']).toBe('tok-demand');
    });

    it('ignores a page-set data-fetchproxy-csrf attribute', async () => {
      document.documentElement.dataset.fetchproxyCsrf = 'stale-attr';
      await runFetch(
        { url: 'https://www.opentable.com/x', method: 'GET', tabUrl: 'https://www.opentable.com/' },
        async () => undefined,
      );
      delete document.documentElement.dataset.fetchproxyCsrf;
      const init = fetchMock.mock.calls[0]![1] as { headers: Record<string, string> };
      expect(init.headers['x-csrf-token']).toBeUndefined();
    });

    it('a caller-supplied token skips the page round-trip and the requireCsrf soft miss', async () => {
      const getCsrf = vi.fn(async () => undefined);
      const res = await runFetch(
        {
          url: 'https://www.opentable.com/x',
          method: 'POST',
          body: '{}',
          tabUrl: 'https://www.opentable.com/',
          headers: { 'X-Csrf-Token': 'caller-tok' },
          requireCsrf: true,
        },
        getCsrf,
      );
      expect(getCsrf).not.toHaveBeenCalled();
      expect((res as { ok: boolean }).ok).toBe(true);
      const init = fetchMock.mock.calls[0]![1] as { headers: Record<string, string> };
      expect(init.headers['X-Csrf-Token']).toBe('caller-tok');
      expect(init.headers['x-csrf-token']).toBeUndefined();
    });
  });
});
