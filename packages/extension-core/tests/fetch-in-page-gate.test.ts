import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';

/**
 * The capability gate on `init.inPage`.
 *
 * `inPage` hands a request to the page's MAIN world, where page script can
 * see and patch `window.fetch`. That is a privilege, so it must be refused
 * for any MCP that did not declare `fetch_in_page` and get it approved at
 * pair time — and refused BEFORE the request reaches a tab, not after.
 */

const sent: { mcpId: string; inner: Record<string, unknown> }[] = [];
vi.mock('../src/background/send-inner.js', () => ({
  sendInner: async (mcpId: string, inner: Record<string, unknown>) => {
    sent.push({ mcpId, inner });
  },
}));

const { handleFetchRequest } = await import('../src/background/handlers/fetch.js');
const { mcpCapabilities } = await import('../src/background/session-scope.js');

const MCP_ID = 'opentable-mcp:1.0.0:aaaaaaaaaaaaaaaa';
const DOMAINS = ['opentable.com'];

const req = (inPage?: boolean) => ({
  type: 'request' as const,
  id: 1,
  op: 'fetch' as const,
  init: {
    url: 'https://www.opentable.com/dapi/fe/gql?optype=mutation',
    method: 'POST',
    tabUrl: 'https://www.opentable.com/',
    ...(inPage === undefined ? {} : { inPage }),
  },
});

function installTabs(): { messages: unknown[] } {
  const messages: unknown[] = [];
  (globalThis as { chrome?: unknown }).chrome = {
    tabs: {
      query: async () => [{ id: 1, url: 'https://www.opentable.com/r/x' }],
      sendMessage: async (_id: number, message: unknown) => {
        messages.push(message);
        return { ok: true, status: 200, url: 'https://www.opentable.com/dapi/fe/gql', body: '{}' };
      },
    },
  };
  return { messages };
}

describe('fetch inPage capability gate', () => {
  beforeEach(() => {
    sent.length = 0;
  });
  afterEach(() => {
    mcpCapabilities.delete(MCP_ID);
    delete (globalThis as { chrome?: unknown }).chrome;
  });

  it('refuses inPage when the MCP did not declare fetch_in_page', async () => {
    mcpCapabilities.set(MCP_ID, ['fetch']);
    const { messages } = installTabs();

    await handleFetchRequest(MCP_ID, req(true), DOMAINS);

    expect(sent).toHaveLength(1);
    expect(sent[0]!.inner).toMatchObject({ ok: false, op: 'fetch', id: 1 });
    expect(String(sent[0]!.inner.error)).toContain('fetch_in_page');
    // Refused before any tab was touched — the request never leaves the background.
    expect(messages).toHaveLength(0);
  });

  it('refuses inPage for an MCP with no declared capabilities at all', async () => {
    const { messages } = installTabs();
    await handleFetchRequest(MCP_ID, req(true), DOMAINS);
    expect(sent[0]!.inner).toMatchObject({ ok: false, op: 'fetch' });
    expect(messages).toHaveLength(0);
  });

  it('forwards inPage to the tab when the capability IS declared', async () => {
    mcpCapabilities.set(MCP_ID, ['fetch', 'fetch_in_page']);
    const { messages } = installTabs();

    await handleFetchRequest(MCP_ID, req(true), DOMAINS);

    expect(messages).toHaveLength(1);
    expect(messages[0]).toMatchObject({
      kind: 'fetchproxy-fetch',
      init: { inPage: true },
    });
    expect(sent[0]!.inner).toMatchObject({ ok: true, op: 'fetch', status: 200 });
  });

  it('leaves an ordinary fetch alone — no capability needed, no inPage forwarded', async () => {
    mcpCapabilities.set(MCP_ID, ['fetch']);
    const { messages } = installTabs();

    await handleFetchRequest(MCP_ID, req(), DOMAINS);

    expect(sent[0]!.inner).toMatchObject({ ok: true, op: 'fetch' });
    expect((messages[0] as { init: Record<string, unknown> }).init).not.toHaveProperty('inPage');
  });

  it('treats inPage:false as an ordinary fetch (no capability required)', async () => {
    mcpCapabilities.set(MCP_ID, ['fetch']);
    installTabs();

    await handleFetchRequest(MCP_ID, req(false), DOMAINS);

    expect(sent[0]!.inner).toMatchObject({ ok: true, op: 'fetch' });
  });
});
