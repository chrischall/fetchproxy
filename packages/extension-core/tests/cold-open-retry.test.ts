/**
 * The cold-open race (#291): `ensureDomainTab` opens a relay tab
 * fire-and-forget at server-hello, and the MCP's first request routinely
 * arrives before that tab exists. The request path used to answer "no tab
 * matching <url> — open a tab on that host", which instructs the person to do
 * the thing the extension is already doing, and which a caller who simply
 * retried would have got right on the next attempt.
 *
 * These cases pin the retry and, when the retry cannot save it, the wording.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';

import { sendToFirstResponsiveTab } from '../src/background.js';
import { ensureDomainTab, __resetRelayGroupForTests } from '../src/ensure-domain-tab.js';
import {
  coldOpenInFlight,
  __resetColdOpenForTests,
  __setColdOpenTimingForTests,
} from '../src/lib/cold-open.js';

interface FakeTab {
  id?: number;
  url?: string;
  status?: string;
}

/**
 * One fake `chrome` for both halves of the race: `ensureDomainTab` creates
 * tabs through it, `sendToFirstResponsiveTab` queries and messages through it,
 * and `tabs.get` is what tells the retry whether the cold-opened tab has
 * finished loading. Tests mutate the returned `tabs` array mid-flight to model
 * a page that arrives while the caller is waiting.
 */
function installFakeChrome(tabs: FakeTab[]): {
  tabs: FakeTab[];
  responsive: Set<number>;
  sends: number[];
} {
  const responsive = new Set<number>();
  const sends: number[] = [];
  let nextId = 900;
  (globalThis as { chrome?: unknown }).chrome = {
    tabs: {
      query: async (q: { url?: string | string[] }) => {
        if (!q.url) return [...tabs];
        const patterns = Array.isArray(q.url) ? q.url : [q.url];
        return tabs.filter((t) =>
          patterns.some((p) => {
            const host = p.replace(/^\*:\/\//, '').replace(/\/\*$/, '').toLowerCase();
            try {
              const h = new URL(t.url ?? '').hostname.toLowerCase();
              const bare = host.startsWith('*.') ? host.slice(2) : host;
              return h === bare || h.endsWith('.' + bare);
            } catch {
              return false;
            }
          }),
        );
      },
      create: async (props: { url: string }) => {
        const tab: FakeTab = { id: nextId++, url: props.url, status: 'loading' };
        tabs.push(tab);
        return tab;
      },
      get: async (id: number) => {
        const t = tabs.find((x) => x.id === id);
        if (!t) throw new Error('No tab with id');
        return t;
      },
      sendMessage: async (tabId: number) => {
        sends.push(tabId);
        if (!responsive.has(tabId)) throw new Error('Receiving end does not exist.');
        return { ok: true };
      },
    },
  };
  return { tabs, responsive, sends };
}

const matchZillow = (tabUrl: string) => tabUrl.startsWith('https://www.zillow.com');

beforeEach(() => {
  __resetColdOpenForTests();
  __resetRelayGroupForTests();
  // Milliseconds, not seconds: these cases exercise the retry loop itself, so
  // the production budget would make the suite sleep for its whole length.
  __setColdOpenTimingForTests({ budgetMs: 300, pollMs: 10 });
});

afterEach(() => {
  __resetColdOpenForTests();
  delete (globalThis as { chrome?: unknown }).chrome;
});

describe('cold-open registry', () => {
  it('records the tab ensureDomainTab opened, and nothing when one already existed', async () => {
    installFakeChrome([]);
    expect(await coldOpenInFlight()).toBe(false);

    const opened = await ensureDomainTab('zillow.com');
    expect(opened.opened).toBe(true);
    expect(await coldOpenInFlight()).toBe(true);
  });

  it('reports nothing in flight once the opened tab finishes loading', async () => {
    const fake = installFakeChrome([]);
    await ensureDomainTab('zillow.com');
    expect(await coldOpenInFlight()).toBe(true);

    for (const t of fake.tabs) t.status = 'complete';
    expect(await coldOpenInFlight()).toBe(false);
  });

  it('does not register a tab when a matching one was already open', async () => {
    installFakeChrome([{ id: 1, url: 'https://www.zillow.com/homes' }]);
    const result = await ensureDomainTab('zillow.com');
    expect(result.opened).toBe(false);
    expect(await coldOpenInFlight()).toBe(false);
  });
});

describe('sendToFirstResponsiveTab through a cold open', () => {
  it('answers immediately, and without retrying, when no tab is being opened', async () => {
    const fake = installFakeChrome([{ id: 1, url: 'https://example.com/' }]);
    const started = Date.now();
    const result = await sendToFirstResponsiveTab(
      matchZillow,
      () => ({}),
      'https://www.zillow.com/',
    );
    expect(result.kind).toBe('no-tab');
    expect(result.kind === 'no-tab' && result.error).toContain('no tab matching');
    expect(result.kind === 'no-tab' && result.error).not.toContain('still opening');
    expect(fake.sends).toEqual([]);
    // The whole point of gating the retry on an in-flight open: a request for a
    // host nobody is opening must not pay the budget.
    expect(Date.now() - started).toBeLessThan(200);
  });

  it('succeeds when the cold-opened tab becomes responsive inside the budget', async () => {
    const fake = installFakeChrome([]);
    await ensureDomainTab('zillow.com');
    const cold = fake.tabs.find((t) => t.id !== undefined)!;
    // The tab exists but has not navigated anywhere the matcher accepts yet,
    // which is exactly the state the first attempt sees.
    cold.url = 'about:blank';

    setTimeout(() => {
      cold.url = 'https://www.zillow.com/';
      fake.responsive.add(cold.id!);
    }, 50);

    const result = await sendToFirstResponsiveTab(
      matchZillow,
      () => ({}),
      'https://www.zillow.com/',
    );
    expect(result.kind).toBe('response');
  });

  it('says the tab is still opening rather than telling the person to open one', async () => {
    const fake = installFakeChrome([]);
    await ensureDomainTab('zillow.com');
    // Never navigates, never loads: the budget runs out with the open still
    // in flight, which is the only state that earns the reworded error.
    for (const t of fake.tabs) t.url = 'about:blank';

    const result = await sendToFirstResponsiveTab(
      matchZillow,
      () => ({}),
      'https://www.zillow.com/',
    );
    expect(result.kind).toBe('no-tab');
    const error = result.kind === 'no-tab' ? result.error : '';
    // Keeps the `no tab matching ` prefix so an older @fetchproxy/server still
    // classifies it in the no-tab family rather than as a version mismatch.
    expect(error.startsWith('no tab matching https://www.zillow.com/')).toBe(true);
    expect(error).toContain('one is still opening');
    expect(error).not.toContain('content script loaded');
  });

  it('stops waiting as soon as the cold open settles, and keeps the ordinary wording', async () => {
    const fake = installFakeChrome([]);
    await ensureDomainTab('zillow.com');
    const cold = fake.tabs.find((t) => t.id !== undefined)!;
    cold.url = 'https://example.com/';

    setTimeout(() => {
      cold.status = 'complete';
    }, 30);

    const started = Date.now();
    const result = await sendToFirstResponsiveTab(
      matchZillow,
      () => ({}),
      'https://www.zillow.com/',
    );
    const elapsed = Date.now() - started;
    expect(result.kind).toBe('no-tab');
    // The tab loaded and it is not on this host, so "open a tab" is once again
    // the correct advice — the cold-open wording would now be a lie.
    expect(result.kind === 'no-tab' && result.error).not.toContain('still opening');
    expect(elapsed).toBeLessThan(280);
  });
});
