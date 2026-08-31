import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  reinjectContentScripts,
  maybeReinjectOnInstalled,
  matchesAnyPattern,
} from '../src/reinject-content-scripts.js';

// Chrome tears down content scripts in ALREADY-OPEN tabs when an extension
// updates, and does NOT inject the new ones — the manifest's `content_scripts`
// only cover navigations from then on. Every pre-update tab is therefore left
// with no listener, and `chrome.tabs.sendMessage` to it fails with "Receiving
// end does not exist" until a human reloads it.
//
// That is not hypothetical: Transporter 2.2.1 -> 2.3.0 did it, and every MCP
// that reads from a long-lived tab broke at once for anyone who had one open.
// Two different servers looked independently broken on the same night, which
// sent the debugging into key derivation and a revoke/re-pair that discarded a
// working pairing. Re-injecting on update is what stops that recurring.

interface FakeTab { id?: number; url?: string }
interface Injection { tabId: number; files: string[]; world?: string }

function installFakeChrome(opts: {
  tabs: FakeTab[];
  contentScripts?: unknown;
  failFor?: Set<number>;
  noScripting?: boolean;
}): { injections: Injection[] } {
  const injections: Injection[] = [];
  const chrome: Record<string, unknown> = {
    runtime: {
      getManifest: () => ({
        version: '2.3.0',
        content_scripts: opts.contentScripts ?? [
          { matches: ['<all_urls>'], js: ['content.js'], world: 'ISOLATED', run_at: 'document_idle' },
          { matches: ['<all_urls>'], js: ['capture-logger.js'], world: 'MAIN', run_at: 'document_start' },
        ],
      }),
    },
    tabs: { query: async () => opts.tabs },
  };
  if (!opts.noScripting) {
    chrome.scripting = {
      executeScript: async (i: { target: { tabId: number }; files: string[]; world?: string }) => {
        if (opts.failFor?.has(i.target.tabId)) throw new Error('Cannot access contents of the page');
        injections.push({ tabId: i.target.tabId, files: i.files, world: i.world });
        return [];
      },
    };
  }
  (globalThis as { chrome?: unknown }).chrome = chrome;
  return { injections };
}

describe('reinjectContentScripts', () => {
  const saved = (globalThis as { chrome?: unknown }).chrome;
  beforeEach(() => { delete (globalThis as { chrome?: unknown }).chrome; });
  afterEach(() => { (globalThis as { chrome?: unknown }).chrome = saved; });

  it('re-injects every declared content script into an open http(s) tab', async () => {
    const { injections } = installFakeChrome({ tabs: [{ id: 7, url: 'https://zoomws.hbportal.co/flow/x' }] });
    const r = await reinjectContentScripts();
    expect(injections).toEqual([
      { tabId: 7, files: ['content.js'], world: 'ISOLATED' },
      { tabId: 7, files: ['capture-logger.js'], world: 'MAIN' },
    ]);
    expect(r.tabs).toBe(1);
  });

  // The MAIN-world capture-logger reads page globals the ISOLATED world cannot.
  // Injecting it into the wrong world yields a script that runs and silently
  // sees nothing, which is worse than not injecting it at all.
  it('preserves each script\'s world', async () => {
    const { injections } = installFakeChrome({ tabs: [{ id: 1, url: 'https://a.test/' }] });
    await reinjectContentScripts();
    expect(injections.find((i) => i.files[0] === 'capture-logger.js')?.world).toBe('MAIN');
  });

  // chrome://, about:, devtools:, the Web Store — injection throws on all of
  // them. Attempting it turns a clean pass into a log full of failures.
  it('skips tabs that cannot be injected into', async () => {
    const { injections } = installFakeChrome({
      tabs: [
        { id: 1, url: 'chrome://extensions' },
        { id: 2, url: 'about:blank' },
        { id: 3, url: 'https://chromewebstore.google.com/detail/x' },
        { id: 4, url: 'file:///tmp/x.html' },
        { id: 5, url: 'https://ok.test/' },
        { url: 'https://no-id.test/' },
      ],
    });
    await reinjectContentScripts();
    expect([...new Set(injections.map((i) => i.tabId))]).toEqual([5]);
  });

  // Best-effort per tab: one page that refuses injection must not cost every
  // other tab its content script.
  it('keeps going when one tab fails', async () => {
    const { injections } = installFakeChrome({
      tabs: [{ id: 1, url: 'https://a.test/' }, { id: 2, url: 'https://b.test/' }],
      failFor: new Set([1]),
    });
    const r = await reinjectContentScripts();
    expect([...new Set(injections.map((i) => i.tabId))]).toEqual([2]);
    expect(r.failed).toBe(1);
    expect(r.tabs).toBe(1);
  });

  it('no-ops without chrome.scripting rather than throwing', async () => {
    installFakeChrome({ tabs: [{ id: 1, url: 'https://a.test/' }], noScripting: true });
    await expect(reinjectContentScripts()).resolves.toEqual({ tabs: 0, failed: 0 });
  });

  // The whole point of reading the manifest: restore what it declares, where it
  // declares it — not "everything, everywhere".
  it('injects a narrowed script only into tabs its matches cover', async () => {
    const { injections } = installFakeChrome({
      tabs: [
        { id: 1, url: 'https://hbportal.co/flow/x' },
        { id: 2, url: 'https://elsewhere.test/' },
      ],
      contentScripts: [
        { matches: ['<all_urls>'], js: ['content.js'], world: 'ISOLATED' },
        { matches: ['*://*.hbportal.co/*'], js: ['narrow.js'], world: 'ISOLATED' },
      ],
    });
    await reinjectContentScripts();
    const byTab = (id: number) => injections.filter((i) => i.tabId === id).map((i) => i.files[0]).sort();
    expect(byTab(1)).toEqual(['content.js', 'narrow.js']);
    expect(byTab(2)).toEqual(['content.js']);
  });

  // A tab no declared script claims is not a failure — nothing was owed to it.
  it('does not count an unmatched tab as failed', async () => {
    const { injections } = installFakeChrome({
      tabs: [{ id: 1, url: 'https://elsewhere.test/' }],
      contentScripts: [{ matches: ['*://*.hbportal.co/*'], js: ['narrow.js'] }],
    });
    const r = await reinjectContentScripts();
    expect(injections).toEqual([]);
    expect(r).toEqual({ tabs: 0, failed: 0 });
  });

  it('no-ops when the manifest declares no content scripts', async () => {
    const { injections } = installFakeChrome({ tabs: [{ id: 1, url: 'https://a.test/' }], contentScripts: [] });
    await reinjectContentScripts();
    expect(injections).toEqual([]);
  });
});

describe('maybeReinjectOnInstalled', () => {
  const saved = (globalThis as { chrome?: unknown }).chrome;
  beforeEach(() => { delete (globalThis as { chrome?: unknown }).chrome; });
  afterEach(() => { (globalThis as { chrome?: unknown }).chrome = saved; });

  // `update` is the reason that orphans tabs. `install` has no pre-existing
  // tabs worth touching, and `chrome_update` does not tear content scripts down.
  it('re-injects on update', async () => {
    const { injections } = installFakeChrome({ tabs: [{ id: 1, url: 'https://a.test/' }] });
    await maybeReinjectOnInstalled({ reason: 'update' });
    expect(injections.length).toBeGreaterThan(0);
  });

  it.each(['install', 'chrome_update', 'shared_module_update'])('ignores %s', async (reason) => {
    const { injections } = installFakeChrome({ tabs: [{ id: 1, url: 'https://a.test/' }] });
    await maybeReinjectOnInstalled({ reason });
    expect(injections).toEqual([]);
  });
});

// A content script declares WHERE it belongs. Ignoring `matches` and injecting
// everything everywhere happens to be harmless for the shipped manifest, whose
// two entries are both `<all_urls>` — but it makes the re-injection path mean
// something different from the manifest it is supposed to restore, so the day a
// script is narrowed to one origin this would quietly put it on every tab.
describe('matchesAnyPattern', () => {
  it('matches <all_urls> for http(s)', () => {
    expect(matchesAnyPattern('https://a.test/x', ['<all_urls>'])).toBe(true);
    expect(matchesAnyPattern('http://a.test/', ['<all_urls>'])).toBe(true);
  });

  it('honours scheme', () => {
    expect(matchesAnyPattern('http://a.test/', ['https://*/*'])).toBe(false);
    expect(matchesAnyPattern('https://a.test/', ['https://*/*'])).toBe(true);
    // `*` as a scheme means http|https only, never file:.
    expect(matchesAnyPattern('https://a.test/', ['*://*/*'])).toBe(true);
  });

  it('honours host, including the *. subdomain form', () => {
    expect(matchesAnyPattern('https://zoomws.hbportal.co/f', ['*://*.hbportal.co/*'])).toBe(true);
    // `*.domain` matches the apex too, as Chrome does.
    expect(matchesAnyPattern('https://hbportal.co/f', ['*://*.hbportal.co/*'])).toBe(true);
    expect(matchesAnyPattern('https://evil-hbportal.co/f', ['*://*.hbportal.co/*'])).toBe(false);
    expect(matchesAnyPattern('https://b.test/', ['*://a.test/*'])).toBe(false);
  });

  it('honours the path glob', () => {
    expect(matchesAnyPattern('https://a.test/app/x', ['https://a.test/app/*'])).toBe(true);
    expect(matchesAnyPattern('https://a.test/other', ['https://a.test/app/*'])).toBe(false);
  });

  it('is false for an empty pattern list, not true', () => {
    expect(matchesAnyPattern('https://a.test/', [])).toBe(false);
  });
});
