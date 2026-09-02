import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';

/**
 * The tab-shadowing fix, exercised through the real verb handler rather than
 * through `sendToFirstResponsiveTab` directly.
 *
 * `graphql-tab-fallthrough.test.ts` covers the helper and the predicate. This
 * file covers the WIRING between them: that `handleGraphqlQueryRequest`
 * actually hands its predicate to the helper, and that what comes back reaches
 * the MCP as an `ok: true` response. Drop the `isGraphqlSoftMiss` argument at
 * the callsite and the other file still passes — this one fails.
 */

const sent: { mcpId: string; inner: Record<string, unknown> }[] = [];
vi.mock('../src/background/send-inner.js', () => ({
  sendInner: async (mcpId: string, inner: Record<string, unknown>) => {
    sent.push({ mcpId, inner });
  },
}));

const { handleGraphqlQueryRequest } = await import('../src/background/handlers/graphql-query.js');
const { mcpCapabilities, mcpGraphqlOps } = await import('../src/background/session-scope.js');
const { notYetObservedError } = await import('../src/lib/graphql-observed.js');

const MCP_ID = 'opentable-mcp:1.0.0:aaaaaaaaaaaaaaaa';
const DOMAINS = ['opentable.com'];

const request = {
  type: 'request' as const,
  op: 'graphql_query' as const,
  id: 1,
  init: { name: 'availability', variables: { restaurantIds: [985138] }, tabUrl: 'https://www.opentable.com/' },
};

interface FakeTab {
  id?: number;
  url?: string;
}

function installTabs(tabs: FakeTab[], replies: Map<number, unknown>): number[] {
  const attempted: number[] = [];
  (globalThis as { chrome?: unknown }).chrome = {
    tabs: {
      query: async () => tabs,
      sendMessage: async (tabId: number) => {
        attempted.push(tabId);
        if (!replies.has(tabId)) throw new Error(`unexpected sendMessage to tabId=${tabId}`);
        return replies.get(tabId);
      },
    },
  };
  return attempted;
}

describe('handleGraphqlQueryRequest tab fallthrough (wiring)', () => {
  beforeEach(() => {
    sent.length = 0;
    mcpCapabilities.set(MCP_ID, ['fetch', 'graphql']);
    mcpGraphqlOps.set(MCP_ID, [{ name: 'availability', operationName: 'RestaurantsAvailability' }]);
  });

  afterEach(() => {
    mcpCapabilities.delete(MCP_ID);
    mcpGraphqlOps.delete(MCP_ID);
    delete (globalThis as { chrome?: unknown }).chrome;
  });

  it('walks past a shadowing tab and returns the observing tab’s data to the MCP', async () => {
    const attempted = installTabs(
      [
        // Dashboard tab: content script loaded, never fired the operation.
        { id: 1, url: 'https://www.opentable.com/my/dashboard' },
        // Restaurant tab: has the DocumentNode.
        { id: 2, url: 'https://www.opentable.com/r/sophias-lounge' },
      ],
      new Map<number, unknown>([
        [1, { ok: false, error: notYetObservedError('RestaurantsAvailability') }],
        [2, { ok: true, data: { availability: [{ restaurantId: 985138 }] } }],
      ]),
    );

    await handleGraphqlQueryRequest(MCP_ID, request, DOMAINS);

    expect(attempted).toEqual([1, 2]);
    expect(sent).toHaveLength(1);
    expect(sent[0]!.inner).toMatchObject({
      type: 'response',
      id: 1,
      ok: true,
      op: 'graphql_query',
      data: { availability: [{ restaurantId: 985138 }] },
    });
  });

  it('still reports the miss when NO matching tab has observed the operation', async () => {
    installTabs(
      [
        { id: 1, url: 'https://www.opentable.com/my/dashboard' },
        { id: 2, url: 'https://www.opentable.com/help' },
      ],
      new Map<number, unknown>([
        [1, { ok: false, error: notYetObservedError('RestaurantsAvailability') }],
        [2, { ok: false, error: notYetObservedError('RestaurantsAvailability') }],
      ]),
    );

    await handleGraphqlQueryRequest(MCP_ID, request, DOMAINS);

    expect(sent).toHaveLength(1);
    expect(sent[0]!.inner).toMatchObject({ ok: false, op: 'graphql_query' });
    // The remedy must survive the fan-out — this is still the right advice.
    expect(String(sent[0]!.inner.error)).toContain('not yet observed on this tab');
  });

  it('does not replay a real error against the remaining tabs', async () => {
    const attempted = installTabs(
      [
        { id: 1, url: 'https://www.opentable.com/r/a' },
        { id: 2, url: 'https://www.opentable.com/r/b' },
      ],
      new Map<number, unknown>([
        [1, { ok: false, error: 'graphql errors: session expired' }],
        [2, { ok: true, data: { availability: [] } }],
      ]),
    );

    await handleGraphqlQueryRequest(MCP_ID, request, DOMAINS);

    // A real failure is a real answer: stop there rather than sending the same
    // credentialed query at every other tab on the origin.
    expect(attempted).toEqual([1]);
    expect(sent[0]!.inner).toMatchObject({ ok: false, op: 'graphql_query' });
    expect(sent[0]!.inner.error).toBe('graphql errors: session expired');
  });
});
