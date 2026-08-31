import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { sendToFirstResponsiveTab } from '../src/background.js';

// Mock chrome.tabs.{query,sendMessage} on globalThis for each test —
// the helper reaches the global directly (it's typed as `declare const
// chrome` in background.ts, so production builds and tests both hit
// `globalThis.chrome`). Each test scenario installs its own tabs array
// and sendMessage behavior, then verifies the helper's iteration logic.

interface FakeTab {
  id?: number;
  url?: string;
}

type SendMessageBehavior =
  | { kind: 'reply'; response: unknown }
  | { kind: 'throw'; error: string };

interface FakeChrome {
  tabs: {
    query: (q: { url?: string | string[] }) => Promise<FakeTab[]>;
    sendMessage: (tabId: number, message: unknown) => Promise<unknown>;
  };
}

function installFakeChrome(
  tabs: FakeTab[],
  perTabBehavior: Map<number, SendMessageBehavior>,
): { messagesSent: { tabId: number; message: unknown }[] } {
  const messagesSent: { tabId: number; message: unknown }[] = [];
  const fake: FakeChrome = {
    tabs: {
      query: async () => tabs,
      sendMessage: async (tabId, message) => {
        messagesSent.push({ tabId, message });
        const beh = perTabBehavior.get(tabId);
        if (!beh) throw new Error(`unexpected sendMessage to tabId=${tabId}`);
        if (beh.kind === 'throw') throw new Error(beh.error);
        return beh.response;
      },
    },
  };
  (globalThis as { chrome?: unknown }).chrome = fake;
  return { messagesSent };
}

describe('sendToFirstResponsiveTab', () => {
  beforeEach(() => {
    delete (globalThis as { chrome?: unknown }).chrome;
  });

  afterEach(() => {
    delete (globalThis as { chrome?: unknown }).chrome;
  });

  it('returns no-tab when zero tabs match the URL', async () => {
    installFakeChrome(
      [{ id: 1, url: 'https://other.example.com/' }],
      new Map(),
    );
    const result = await sendToFirstResponsiveTab(
      (url) => url.startsWith('https://target.example.com/'),
      () => ({ kind: 'noop' }),
      'https://target.example.com/',
    );
    expect(result.kind).toBe('no-tab');
    if (result.kind === 'no-tab') {
      // Plain "no tab matching X" message — distinct from the "all
      // matched tabs lacked content script" template the caller hits
      // when matches exist but every one throws Receiving-end.
      expect(result.error).toBe('no tab matching https://target.example.com/');
    }
  });

  it('returns response from the FIRST matched tab when it replies', async () => {
    const { messagesSent } = installFakeChrome(
      [
        { id: 10, url: 'https://target.example.com/' },
        { id: 11, url: 'https://target.example.com/other' },
      ],
      new Map<number, SendMessageBehavior>([
        [10, { kind: 'reply', response: { ok: true, body: 'from-10' } }],
        [11, { kind: 'reply', response: { ok: true, body: 'from-11' } }],
      ]),
    );
    const result = await sendToFirstResponsiveTab(
      (url) => url.startsWith('https://target.example.com/'),
      () => ({ kind: 'noop' }),
      'https://target.example.com/',
    );
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect(result.response).toEqual({ ok: true, body: 'from-10' });
      expect(result.tabUrl).toBe('https://target.example.com/');
    }
    // Only the first matched tab should have been messaged — the
    // second never tried because the first responded.
    expect(messagesSent).toHaveLength(1);
    expect(messagesSent[0]?.tabId).toBe(10);
  });

  it('skips a "Receiving end does not exist" tab and falls through to the next', async () => {
    const { messagesSent } = installFakeChrome(
      [
        { id: 20, url: 'https://target.example.com/old' },
        { id: 21, url: 'https://target.example.com/fresh' },
      ],
      new Map<number, SendMessageBehavior>([
        // First tab is the post-reload one with no content script.
        [
          20,
          {
            kind: 'throw',
            error: 'Could not establish connection. Receiving end does not exist.',
          },
        ],
        // Second is the freshly-loaded one that DOES have the content
        // script — should be the one we return.
        [21, { kind: 'reply', response: { ok: true, body: 'fresh' } }],
      ]),
    );
    const result = await sendToFirstResponsiveTab(
      (url) => url.startsWith('https://target.example.com/'),
      (tabUrl) => ({ kind: 'verb', tabUrl }),
      'https://target.example.com/',
    );
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect(result.response).toEqual({ ok: true, body: 'fresh' });
      expect(result.tabUrl).toBe('https://target.example.com/fresh');
    }
    // Both tabs were attempted, in order.
    expect(messagesSent.map((m) => m.tabId)).toEqual([20, 21]);
    // buildMessage gets the matched tab's actual URL (so verbs that
    // need to canonicalise tabUrl can do it per attempt).
    expect(messagesSent[1]?.message).toEqual({
      kind: 'verb',
      tabUrl: 'https://target.example.com/fresh',
    });
  });

  it('returns no-tab with embedded lastNoListener when ALL matched tabs are stale', async () => {
    installFakeChrome(
      [
        { id: 30, url: 'https://target.example.com/a' },
        { id: 31, url: 'https://target.example.com/b' },
      ],
      new Map<number, SendMessageBehavior>([
        [
          30,
          {
            kind: 'throw',
            error: 'Could not establish connection. Receiving end does not exist.',
          },
        ],
        [
          31,
          {
            kind: 'throw',
            error: 'Receiving end does not exist.',
          },
        ],
      ]),
    );
    const result = await sendToFirstResponsiveTab(
      (url) => url.startsWith('https://target.example.com/'),
      () => ({ kind: 'noop' }),
      'https://target.example.com/',
    );
    expect(result.kind).toBe('no-tab');
    if (result.kind === 'no-tab') {
      // Tells the user how many tabs matched (2), why we gave up
      // (none responded), how to fix it (refresh), and shows the
      // last underlying chrome error so they can pattern-match it
      // against what they see in DevTools.
      expect(result.error).toContain('2 URL matches');
      expect(result.error).toContain('none responded');
      expect(result.error).toContain('Reload that tab');
      // The remedy is useless without the cause: this is what every tab looks
      // like right after an extension update, and "reload" reads as a shrug
      // unless the message says why. Transporter 2.2.1 -> 2.3.0 sent two
      // debugging sessions after key derivation for want of this sentence.
      expect(result.error).toContain('right after the extension updates');
      expect(result.error).toContain('Receiving end does not exist');
    }
  });

  it('returns throw immediately when sendMessage throws a non-receiving-end error', async () => {
    const { messagesSent } = installFakeChrome(
      [
        { id: 40, url: 'https://target.example.com/a' },
        { id: 41, url: 'https://target.example.com/b' },
      ],
      new Map<number, SendMessageBehavior>([
        // First tab throws an unrelated error — should bubble out
        // without trying the second tab.
        [40, { kind: 'throw', error: 'permission denied' }],
        [41, { kind: 'reply', response: { ok: true } }],
      ]),
    );
    const result = await sendToFirstResponsiveTab(
      (url) => url.startsWith('https://target.example.com/'),
      () => ({ kind: 'noop' }),
      'https://target.example.com/',
    );
    expect(result.kind).toBe('throw');
    if (result.kind === 'throw') {
      expect(result.error).toContain('permission denied');
    }
    // Second tab must NOT have been attempted — a real fault stops
    // iteration so we don't try to fall over a permission issue.
    expect(messagesSent).toHaveLength(1);
    expect(messagesSent[0]?.tabId).toBe(40);
  });

  it('skips tabs whose id is not a number (filter excludes them; count stays accurate)', async () => {
    const { messagesSent } = installFakeChrome(
      [
        // Tab with no id (e.g. a tab Chrome hasn't fully created yet).
        // Without folding the id check into the filter, this would
        // inflate matches.length and skew the error message's count.
        { url: 'https://target.example.com/no-id' },
        { id: 50, url: 'https://target.example.com/has-id' },
      ],
      new Map<number, SendMessageBehavior>([
        [50, { kind: 'reply', response: { ok: true } }],
      ]),
    );
    const result = await sendToFirstResponsiveTab(
      (url) => url.startsWith('https://target.example.com/'),
      () => ({ kind: 'noop' }),
      'https://target.example.com/',
    );
    expect(result.kind).toBe('response');
    // Only the id'd tab was attempted; the no-id tab silently dropped.
    expect(messagesSent.map((m) => m.tabId)).toEqual([50]);
  });
});
