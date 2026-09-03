// @vitest-environment jsdom
import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';

/**
 * #286 — a write prefers a relay tab that can inject `x-csrf-token`.
 *
 * Background side: the fetch handler walks matching tabs with `requireCsrf`
 * first, and only when every tab soft-misses re-sends without it. Content
 * side: `runFetch` answers the typed soft miss instead of issuing a request
 * the site would 403, and injects the header when the tab has one.
 */

const sent: { mcpId: string; inner: Record<string, unknown> }[] = [];
vi.mock('../src/background/send-inner.js', () => ({
  sendInner: async (mcpId: string, inner: Record<string, unknown>) => {
    sent.push({ mcpId, inner });
  },
}));

// content.ts registers a chrome.runtime.onMessage listener at module load.
(globalThis as { chrome?: unknown }).chrome = {
  runtime: { onMessage: { addListener: () => {} } },
};
const { handleFetchRequest } = await import('../src/background/handlers/fetch.js');
const { runFetch } = await import('../src/content.js');
const { csrfSoftMiss, isCsrfSoftMiss, prefersCsrfTab } = await import(
  '../src/lib/csrf-soft-miss.js'
);

const MCP_ID = 'opentable-mcp:1.0.0:aaaaaaaaaaaaaaaa';
const DOMAINS = ['opentable.com'];
const HOME = 'https://www.opentable.com/';
const RESTAURANT = 'https://www.opentable.com/r/sophias-lounge';
const DASHBOARD = 'https://www.opentable.com/user/dining-dashboard';

const req = (method: string) => ({
  type: 'request' as const,
  id: 7,
  op: 'fetch' as const,
  init: {
    url: 'https://www.opentable.com/dapi/fe/gql?optype=mutation',
    method,
    body: '{}',
    tabUrl: HOME,
  },
});

type Sent = { tabId: number; init: { tabUrl: string; requireCsrf?: boolean } };

/** Tabs in `chrome.tabs.query` order; `csrfTabs` answer writes, the rest soft-miss on a requireCsrf pass. */
function installTabs(tabs: { id: number; url: string }[], csrfTabs: number[]): Sent[] {
  const messages: Sent[] = [];
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: { onMessage: { addListener: () => {} } },
    tabs: {
      query: async () => tabs,
      sendMessage: async (tabId: number, message: { init: Sent['init'] }) => {
        messages.push({ tabId, init: message.init });
        if (message.init.requireCsrf === true && !csrfTabs.includes(tabId)) {
          return csrfSoftMiss(message.init.tabUrl);
        }
        return { ok: true, status: 200, url: `served-by-${tabId}`, body: '{}' };
      },
    },
  };
  return messages;
}

describe('fetch handler: CSRF-bearing relay tab preference (#286)', () => {
  beforeEach(() => {
    sent.length = 0;
  });
  afterEach(() => {
    (globalThis as { chrome?: unknown }).chrome = {
      runtime: { onMessage: { addListener: () => {} } },
    };
  });

  it('walks past a csrf-less homepage tab to the restaurant tab for a POST', async () => {
    const messages = installTabs(
      [
        { id: 1, url: HOME },
        { id: 2, url: RESTAURANT },
        { id: 3, url: DASHBOARD },
      ],
      [2, 3],
    );
    await handleFetchRequest(MCP_ID, req('POST'), DOMAINS);

    expect(messages.map((m) => [m.tabId, m.init.requireCsrf])).toEqual([
      [1, true],
      [2, true],
    ]);
    expect(sent[0]!.inner).toMatchObject({ ok: true, op: 'fetch', url: 'served-by-2' });
  });

  it('falls back to the first responsive tab when no tab has a token', async () => {
    const messages = installTabs(
      [
        { id: 1, url: HOME },
        { id: 2, url: RESTAURANT },
      ],
      [],
    );
    await handleFetchRequest(MCP_ID, req('POST'), DOMAINS);

    // Pass 1 asks both (both miss); pass 2 re-sends to the first without the marker.
    expect(messages.map((m) => [m.tabId, m.init.requireCsrf])).toEqual([
      [1, true],
      [2, true],
      [1, undefined],
    ]);
    expect(sent[0]!.inner).toMatchObject({ ok: true, op: 'fetch', url: 'served-by-1' });
  });

  it('does not walk for a GET — the first matching tab serves it', async () => {
    const messages = installTabs(
      [
        { id: 1, url: HOME },
        { id: 2, url: RESTAURANT },
      ],
      [2],
    );
    await handleFetchRequest(MCP_ID, req('GET'), DOMAINS);

    expect(messages.map((m) => [m.tabId, m.init.requireCsrf])).toEqual([[1, undefined]]);
    expect(sent[0]!.inner).toMatchObject({ ok: true, url: 'served-by-1' });
  });

  it('still reports no-tab when nothing matches', async () => {
    installTabs([], []);
    await handleFetchRequest(MCP_ID, req('POST'), DOMAINS);
    expect(sent[0]!.inner).toMatchObject({ ok: false, op: 'fetch' });
    expect(String(sent[0]!.inner.error)).toContain('no tab matching');
  });
});

describe('content script: runFetch under requireCsrf', () => {
  const fetchMock = vi.fn();
  beforeEach(() => {
    fetchMock.mockReset();
    fetchMock.mockResolvedValue({
      status: 200,
      url: 'https://www.opentable.com/dapi/x',
      text: async () => '{}',
    });
    (globalThis as { fetch?: unknown }).fetch = fetchMock;
    delete document.documentElement.dataset.fetchproxyCsrf;
  });

  it('soft-misses without touching the network when the tab has no token', async () => {
    const res = await runFetch({
      url: 'https://www.opentable.com/dapi/x',
      method: 'POST',
      body: '{}',
      tabUrl: HOME,
      requireCsrf: true,
    });
    expect(isCsrfSoftMiss(res)).toBe(true);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('serves the request with x-csrf-token when the tab has one', async () => {
    document.documentElement.dataset.fetchproxyCsrf = 'tok-placeholder';
    const res = await runFetch({
      url: 'https://www.opentable.com/dapi/x',
      method: 'POST',
      body: '{}',
      tabUrl: RESTAURANT,
      requireCsrf: true,
    });
    expect(res).toMatchObject({ ok: true, status: 200 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const init = fetchMock.mock.calls[0]![1] as { headers: Record<string, string> };
    expect(init.headers['x-csrf-token']).toBe('tok-placeholder');
  });

  it('without the marker a csrf-less tab issues the request as before', async () => {
    const res = await runFetch({
      url: 'https://www.opentable.com/dapi/x',
      method: 'POST',
      body: '{}',
      tabUrl: HOME,
    });
    expect(res).toMatchObject({ ok: true, status: 200 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe('prefersCsrfTab', () => {
  it('is true for writes and false for reads', () => {
    expect(prefersCsrfTab('POST')).toBe(true);
    expect(prefersCsrfTab('delete')).toBe(true);
    expect(prefersCsrfTab('GET')).toBe(false);
    expect(prefersCsrfTab('head')).toBe(false);
  });
});
