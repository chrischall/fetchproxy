import { describe, expect, it, beforeEach, vi } from 'vitest';

/**
 * S-SEC-1 — the fetch verb's `tabUrl` must be on one of the MCP's approved
 * domains, exactly as `graphql_query` and legacy `read_cookies` already
 * check theirs. Otherwise an MCP approved only for evil.example could pick
 * the user's bank tab to relay its request (and pick up that page's CSRF
 * token on the way).
 */

const sent: { mcpId: string; inner: Record<string, unknown> }[] = [];
vi.mock('../src/background/send-inner.js', () => ({
  sendInner: async (mcpId: string, inner: Record<string, unknown>) => {
    sent.push({ mcpId, inner });
  },
}));

const { handleFetchRequest } = await import('../src/background/handlers/fetch.js');

const MCP_ID = 'evil-mcp:1.0.0:aaaaaaaaaaaaaaaa';

function installTabs(tabs: { id: number; url: string }[]): number[] {
  const messaged: number[] = [];
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: { onMessage: { addListener: () => {} } },
    tabs: {
      query: async () => tabs,
      sendMessage: async (tabId: number) => {
        messaged.push(tabId);
        return { ok: true, status: 200, url: 'x', body: '{}' };
      },
    },
  };
  return messaged;
}

describe('fetch handler: tabUrl is domain-checked (S-SEC-1)', () => {
  beforeEach(() => {
    sent.length = 0;
  });

  it('refuses a tabUrl outside the approved domains and never messages that tab', async () => {
    const messaged = installTabs([{ id: 1, url: 'https://bank.example/' }]);
    await handleFetchRequest(
      MCP_ID,
      {
        type: 'request',
        id: 3,
        op: 'fetch',
        init: { url: 'https://evil.example/c', method: 'GET', tabUrl: 'https://bank.example/' },
      },
      ['evil.example'],
    );
    expect(messaged).toEqual([]);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.inner).toMatchObject({ ok: false, op: 'fetch' });
    expect(String(sent[0]!.inner.error)).toMatch(/tabUrl https:\/\/bank\.example\/ not in domains/);
  });

  it('still relays through a declared-domain tab for an API-only host (viaTab pattern)', async () => {
    const messaged = installTabs([{ id: 2, url: 'https://www.example.com/app' }]);
    await handleFetchRequest(
      MCP_ID,
      {
        type: 'request',
        id: 4,
        op: 'fetch',
        init: {
          url: 'https://api.example.com/v1/me',
          method: 'GET',
          tabUrl: 'https://www.example.com/',
        },
      },
      ['example.com'],
    );
    expect(messaged).toEqual([2]);
    expect(sent[0]!.inner).toMatchObject({ ok: true });
  });

  for (const [declared, tabUrl, realTab] of [
    ['shop.com', 'https://shop.com', 'https://shop.com.au/account'],
    ['bank.co', 'https://bank.co', 'https://bank.com/'],
    ['bank.co', 'https://bank.co', 'https://bank.co.uk/'],
  ] as const) {
    it(`never relays through ${realTab} for a slashless tabUrl ${tabUrl} on ${declared}`, async () => {
      const messaged = installTabs([{ id: 9, url: realTab }]);
      await handleFetchRequest(
        MCP_ID,
        {
          type: 'request',
          id: 5,
          op: 'fetch',
          init: { url: `https://${declared}/api`, method: 'POST', body: '{}', tabUrl },
        },
        [declared],
      );
      expect(messaged).toEqual([]);
      expect(sent.at(-1)!.inner).toMatchObject({ ok: false });
    });
  }
});

describe('legacy read_cookies picks only tabs on approved domains (S-SEC-1)', () => {
  beforeEach(() => {
    sent.length = 0;
  });

  it('never reads document.cookie from a look-alike host', async () => {
    const { handleReadCookiesRequest } = await import('../src/background/handlers/cookies.js');
    const messaged = installTabs([{ id: 3, url: 'https://shop.com.au/account' }]);
    await handleReadCookiesRequest(
      MCP_ID,
      { type: 'request', id: 6, op: 'read_cookies', init: { tabUrl: 'https://shop.com' } } as never,
      ['shop.com'],
    );
    expect(messaged).toEqual([]);
    expect(sent.at(-1)!.inner).toMatchObject({ ok: false, op: 'read_cookies' });
  });
});
