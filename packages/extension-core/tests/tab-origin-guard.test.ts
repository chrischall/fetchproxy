// @vitest-environment jsdom
import { describe, it, expect, beforeAll } from 'vitest';

/**
 * Tab-navigation TOCTOU. The background picks a relay tab by the URL
 * `chrome.tabs.query` reported, then messages it. If the tab navigated to
 * another site in between, the content script that answers is on a site the
 * MCP was never approved for. The background now stamps every tab message
 * with the ORIGIN it matched (`expectedOrigin`); the content script refuses
 * to serve when `location.origin` differs, and the walker moves on to the
 * next matching tab.
 */

type Listener = (msg: unknown, sender: unknown, sendResponse: (r: unknown) => void) => unknown;
let listener: Listener;
let sendToFirstResponsiveTab: typeof import('../src/lib/send-to-responsive-tab.js').sendToFirstResponsiveTab;

beforeAll(async () => {
  (globalThis as { chrome?: unknown }).chrome = {
    runtime: { onMessage: { addListener: (l: Listener) => void (listener = l) } },
  };
  await import('../src/content.js');
  ({ sendToFirstResponsiveTab } = await import('../src/lib/send-to-responsive-tab.js'));
});

function ask(msg: Record<string, unknown>): unknown {
  let out: unknown;
  listener(msg, {}, (r) => void (out = r));
  return out;
}

describe('content script refuses a message stamped for another origin', () => {
  it('serves a message whose expectedOrigin is this page', () => {
    document.body.innerHTML = `<h1>hi</h1>`;
    const r = ask({
      kind: 'fetchproxy-read-dom',
      selectors: [{ name: 't', selector: 'h1' }],
      expectedOrigin: location.origin,
    });
    expect(r).toEqual({ ok: true, values: { t: 'hi' } });
  });

  it('refuses when the tab has navigated to another origin', () => {
    document.body.innerHTML = `<h1>secret</h1>`;
    const r = ask({
      kind: 'fetchproxy-read-dom',
      selectors: [{ name: 't', selector: 'h1' }],
      expectedOrigin: 'https://approved.example',
    }) as { ok: boolean; wrongOrigin?: boolean; error?: string };
    expect(r.ok).toBe(false);
    expect(r.wrongOrigin).toBe(true);
    expect(r.error).toMatch(/navigated/);
  });
});

describe('the tab walker stamps the origin and skips a navigated tab', () => {
  it('sends expectedOrigin and falls through to the next tab on a wrongOrigin answer', async () => {
    const sent: { tabId: number; message: Record<string, unknown> }[] = [];
    (globalThis as { chrome?: unknown }).chrome = {
      tabs: {
        query: async () => [
          { id: 1, url: 'https://www.shop.com/a' },
          { id: 2, url: 'https://shop.com/b' },
        ],
        sendMessage: async (tabId: number, message: Record<string, unknown>) => {
          sent.push({ tabId, message });
          return tabId === 1
            ? { ok: false, error: 'tab navigated away', wrongOrigin: true }
            : { ok: true };
        },
      },
    };
    const r = await sendToFirstResponsiveTab(
      () => true,
      () => ({ kind: 'fetchproxy-read-dom' }),
      'https://shop.com/',
    );
    expect(sent.map((s) => s.message.expectedOrigin)).toEqual([
      'https://www.shop.com',
      'https://shop.com',
    ]);
    expect(r).toMatchObject({
      kind: 'response',
      response: { ok: true },
      tabUrl: 'https://shop.com/b',
    });
  });
});
