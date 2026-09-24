import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { syncMainWorldBridge, MAIN_BRIDGE_FILE } from '../src/main-world-bridge.js';
import { installMainWorldBridges } from '../src/capture-logger.js';

// PR #401 review: a tab left open across a revoke and a re-approve keeps the
// bridge from the first approval (a revoke cannot pull listeners out of a live
// page), and the re-approve injects `capture-logger.js` into it again. Without
// a page-side guard that installed a second set of listeners, so one
// `fetch-req` ran `win.fetch` twice — an in-page POST sent twice.

type Listener = (e: unknown) => void;

function makeTabWindow() {
  const listeners: Record<string, Listener[]> = {};
  const fetch = vi.fn(async () => ({ status: 200, url: 'https://www.opentable.com/x', text: async () => 'ok' }));
  const posted: unknown[] = [];
  const win: Record<string, unknown> = {
    fetch,
    addEventListener(type: string, fn: Listener): void {
      (listeners[type] ||= []).push(fn);
    },
    removeEventListener(type: string, fn: Listener): void {
      listeners[type] = (listeners[type] || []).filter((f) => f !== fn);
    },
    postMessage(m: unknown): void {
      posted.push(m);
    },
    setInterval: (): number => 0,
    clearInterval: (): void => {},
    location: { origin: 'https://www.opentable.com' },
  };
  const dispatch = (data: unknown): void => {
    for (const fn of listeners.message || []) fn({ source: win, data, origin: 'https://www.opentable.com' });
  };
  return { win, fetch, posted, listeners, dispatch };
}

const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

describe('MAIN-world bridge injection is idempotent per page', () => {
  const saved = (globalThis as { chrome?: unknown }).chrome;
  afterEach(() => {
    (globalThis as { chrome?: unknown }).chrome = saved;
  });

  let tab: ReturnType<typeof makeTabWindow>;
  let executed: number;
  beforeEach(() => {
    tab = makeTabWindow();
    executed = 0;
    let registered: { id: string; matches?: string[] }[] = [];
    (globalThis as { chrome?: unknown }).chrome = {
      scripting: {
        getRegisteredContentScripts: async (f?: { ids?: string[] }) =>
          registered.filter((r) => !f?.ids || f.ids.includes(r.id)).map((r) => ({ ...r })),
        registerContentScripts: async (s: { id: string; matches?: string[] }[]) => {
          registered.push(...s.map((x) => ({ ...x })));
        },
        updateContentScripts: async (s: { id: string; matches?: string[] }[]) => {
          for (const x of s) Object.assign(registered.find((r) => r.id === x.id)!, x);
        },
        unregisterContentScripts: async () => {
          registered = [];
        },
        // Running the bridge file in the tab == evaluating capture-logger's
        // module-load block against that tab's window.
        executeScript: async (i: { target: { tabId: number }; files: string[] }) => {
          expect(i.files).toEqual([MAIN_BRIDGE_FILE]);
          executed++;
          installMainWorldBridges(tab.win);
          return [];
        },
      },
      tabs: { query: async () => [{ id: 7, url: 'https://www.opentable.com/r/x' }] },
    };
  });

  it('a revoke then re-approve with the tab still open leaves one listener set and one fetch per request', async () => {
    await syncMainWorldBridge(['opentable.com'], { injectIntoOpenTabs: true });
    const listenersAfterFirst = tab.listeners.message?.length ?? 0;
    expect(listenersAfterFirst).toBeGreaterThan(0);

    await syncMainWorldBridge([], { injectIntoOpenTabs: true }); // revoke
    await syncMainWorldBridge(['opentable.com'], { injectIntoOpenTabs: true }); // re-approve
    expect(executed).toBe(2); // the file really did run twice in the tab

    expect(tab.listeners.message?.length).toBe(listenersAfterFirst);

    tab.dispatch({ __fetchproxy: 'fetch-req', reqId: 1, url: 'https://www.opentable.com/api', method: 'POST', body: '{}' });
    await flush();
    await flush();
    expect(tab.fetch).toHaveBeenCalledTimes(1);
    expect(tab.posted.filter((m) => (m as { __fetchproxy?: string }).__fetchproxy === 'fetch-res')).toHaveLength(1);
  });

  it('reports whether it installed, and keeps its guard out of enumeration and unwritable', () => {
    const before = Object.keys(tab.win);
    expect(installMainWorldBridges(tab.win)).toBe(true);
    expect(installMainWorldBridges(tab.win)).toBe(false);
    // The Apollo assignment interceptor defines __APOLLO_CLIENT__ by design;
    // the guard itself adds nothing enumerable.
    expect(Object.keys(tab.win).filter((k) => k !== '__APOLLO_CLIENT__')).toEqual(before);
    const [sym] = Object.getOwnPropertySymbols(tab.win);
    expect(Object.getOwnPropertyDescriptor(tab.win, sym!)).toMatchObject({
      enumerable: false,
      writable: false,
      configurable: false,
    });
  });
});
