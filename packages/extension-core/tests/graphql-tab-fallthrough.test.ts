import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { sendToFirstResponsiveTab, isGraphqlSoftMiss } from '../src/background.js';
import {
  notYetObservedError,
  isNotYetObservedError,
} from '../src/lib/graphql-observed.js';

/**
 * Regression cover for the tab-shadowing bug: one stale same-origin tab
 * that never fired the operation permanently shadowed the tab that had,
 * because `sendToFirstResponsiveTab` stopped at the first tab to answer
 * *at all* — and a `{ok:false, "not yet observed"}` counts as an answer.
 *
 * Observed live against opentable.com: the restaurant tab had the
 * DocumentNode recorded and returned real availability when driven
 * directly, but `opentable_find_slots` never reached it. A marker listener
 * planted in that tab logged zero inbound requests.
 */

interface FakeTab {
  id?: number;
  url?: string;
}

type SendMessageBehavior =
  | { kind: 'reply'; response: unknown }
  | { kind: 'throw'; error: string };

function installFakeChrome(
  tabs: FakeTab[],
  perTabBehavior: Map<number, SendMessageBehavior>,
): { messagesSent: { tabId: number; message: unknown }[] } {
  const messagesSent: { tabId: number; message: unknown }[] = [];
  (globalThis as { chrome?: unknown }).chrome = {
    tabs: {
      query: async () => tabs,
      sendMessage: async (tabId: number, message: unknown) => {
        messagesSent.push({ tabId, message });
        const beh = perTabBehavior.get(tabId);
        if (!beh) throw new Error(`unexpected sendMessage to tabId=${tabId}`);
        if (beh.kind === 'throw') throw new Error(beh.error);
        return beh.response;
      },
    },
  };
  return { messagesSent };
}

// NOTE: these tests drive the REAL `isGraphqlSoftMiss` the handler passes to
// `sendToFirstResponsiveTab` (see graphql-query.ts), not a local copy of it.
// A hand-rolled stand-in here would keep passing while the shipped predicate
// drifted, which is exactly the regression this file exists to catch.
const graphqlSoftMiss = isGraphqlSoftMiss;

describe('graphql_query multi-tab fallthrough', () => {
  beforeEach(() => {
    delete (globalThis as { chrome?: unknown }).chrome;
  });
  afterEach(() => {
    delete (globalThis as { chrome?: unknown }).chrome;
  });

  it('recognises the not-yet-observed miss for any operation name', () => {
    expect(isNotYetObservedError(notYetObservedError('RestaurantsAvailability'))).toBe(true);
    expect(isNotYetObservedError(notYetObservedError('AnythingElse'))).toBe(true);
    // A real GraphQL/network failure is NOT a soft miss — it must stop the fan-out
    // rather than send the same query at every other tab on the origin.
    expect(isNotYetObservedError('Response not successful: Received status code 400')).toBe(false);
    expect(isNotYetObservedError(undefined)).toBe(false);
  });

  it('isGraphqlSoftMiss classifies whole tab responses, not just error text', () => {
    // The one shape that means "ask another tab".
    expect(
      isGraphqlSoftMiss({ ok: false, error: notYetObservedError('RestaurantsAvailability') }),
    ).toBe(true);

    // A success is never a miss, even if something echoes the phrase in data.
    expect(isGraphqlSoftMiss({ ok: true, data: { note: 'not yet observed on this tab' } })).toBe(
      false,
    );
    // A real failure is a real answer — stop, don't replay it at every tab.
    expect(isGraphqlSoftMiss({ ok: false, error: 'graphql errors: session expired' })).toBe(false);
    expect(isGraphqlSoftMiss({ ok: false, error: 'Received status code 400' })).toBe(false);
    // Malformed / absent responses must not be mistaken for a miss.
    expect(isGraphqlSoftMiss(undefined)).toBe(false);
    expect(isGraphqlSoftMiss(null)).toBe(false);
    expect(isGraphqlSoftMiss('not yet observed on this tab')).toBe(false);
    expect(isGraphqlSoftMiss({ error: notYetObservedError('Op') })).toBe(false);
  });

  it('falls through a shadowing tab to the tab that observed the operation', async () => {
    const { messagesSent } = installFakeChrome(
      [
        // The dashboard tab: content script loaded, Apollo client never
        // fired RestaurantsAvailability. Earlier in chrome.tabs.query order.
        { id: 60, url: 'https://www.opentable.com/my/dashboard' },
        // The restaurant tab: has the DocumentNode.
        { id: 61, url: 'https://www.opentable.com/r/sophias-lounge' },
      ],
      new Map<number, SendMessageBehavior>([
        [60, { kind: 'reply', response: { ok: false, error: notYetObservedError('RestaurantsAvailability') } }],
        [61, { kind: 'reply', response: { ok: true, data: { availability: [{ restaurantId: 985138 }] } } }],
      ]),
    );
    const result = await sendToFirstResponsiveTab(
      (url) => url.startsWith('https://www.opentable.com/'),
      (tabUrl) => ({ kind: 'fetchproxy-graphql-query', tabUrl }),
      'https://www.opentable.com/',
      graphqlSoftMiss,
    );
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect(result.response).toEqual({ ok: true, data: { availability: [{ restaurantId: 985138 }] } });
      expect(result.tabUrl).toBe('https://www.opentable.com/r/sophias-lounge');
    }
    // Both tabs attempted, in order — the shadowing tab no longer terminates the walk.
    expect(messagesSent.map((m) => m.tabId)).toEqual([60, 61]);
  });

  it('returns the first soft miss when NO tab has observed the operation', async () => {
    installFakeChrome(
      [
        { id: 70, url: 'https://www.opentable.com/a' },
        { id: 71, url: 'https://www.opentable.com/b' },
      ],
      new Map<number, SendMessageBehavior>([
        [70, { kind: 'reply', response: { ok: false, error: notYetObservedError('RestaurantsAvailability') } }],
        [71, { kind: 'reply', response: { ok: false, error: notYetObservedError('RestaurantsAvailability') } }],
      ]),
    );
    const result = await sendToFirstResponsiveTab(
      (url) => url.startsWith('https://www.opentable.com/'),
      () => ({ kind: 'noop' }),
      'https://www.opentable.com/',
      graphqlSoftMiss,
    );
    // The actionable "open a page that triggers it" hint must survive — that
    // is still the correct remedy when genuinely no tab has the operation.
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect((result.response as { error: string }).error).toContain('not yet observed on this tab');
    }
  });

  it('does not fall through on a real error response (only soft misses)', async () => {
    const { messagesSent } = installFakeChrome(
      [
        { id: 80, url: 'https://www.opentable.com/a' },
        { id: 81, url: 'https://www.opentable.com/b' },
      ],
      new Map<number, SendMessageBehavior>([
        [80, { kind: 'reply', response: { ok: false, error: 'graphql errors: session expired' } }],
        [81, { kind: 'reply', response: { ok: true, data: {} } }],
      ]),
    );
    const result = await sendToFirstResponsiveTab(
      (url) => url.startsWith('https://www.opentable.com/'),
      () => ({ kind: 'noop' }),
      'https://www.opentable.com/',
      graphqlSoftMiss,
    );
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect((result.response as { error: string }).error).toBe('graphql errors: session expired');
    }
    expect(messagesSent).toHaveLength(1);
  });

  it('still skips Receiving-end tabs while falling through soft misses', async () => {
    const { messagesSent } = installFakeChrome(
      [
        { id: 90, url: 'https://www.opentable.com/stale' },
        { id: 91, url: 'https://www.opentable.com/dashboard' },
        { id: 92, url: 'https://www.opentable.com/r/x' },
      ],
      new Map<number, SendMessageBehavior>([
        [90, { kind: 'throw', error: 'Could not establish connection. Receiving end does not exist.' }],
        [91, { kind: 'reply', response: { ok: false, error: notYetObservedError('Op') } }],
        [92, { kind: 'reply', response: { ok: true, data: { hit: true } } }],
      ]),
    );
    const result = await sendToFirstResponsiveTab(
      (url) => url.startsWith('https://www.opentable.com/'),
      () => ({ kind: 'noop' }),
      'https://www.opentable.com/',
      graphqlSoftMiss,
    );
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect(result.response).toEqual({ ok: true, data: { hit: true } });
    }
    expect(messagesSent.map((m) => m.tabId)).toEqual([90, 91, 92]);
  });

  it('without the predicate, the first answer still wins (other verbs unchanged)', async () => {
    const { messagesSent } = installFakeChrome(
      [
        { id: 100, url: 'https://www.opentable.com/a' },
        { id: 101, url: 'https://www.opentable.com/b' },
      ],
      new Map<number, SendMessageBehavior>([
        [100, { kind: 'reply', response: { ok: false, error: notYetObservedError('Op') } }],
        [101, { kind: 'reply', response: { ok: true } }],
      ]),
    );
    const result = await sendToFirstResponsiveTab(
      (url) => url.startsWith('https://www.opentable.com/'),
      () => ({ kind: 'noop' }),
      'https://www.opentable.com/',
    );
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect((result.response as { ok: boolean }).ok).toBe(false);
    }
    expect(messagesSent).toHaveLength(1);
  });
});
