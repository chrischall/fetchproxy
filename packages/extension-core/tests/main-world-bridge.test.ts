import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  MAIN_BRIDGE_SCRIPT_ID,
  MAIN_BRIDGE_FILE,
  bridgeMatchPatterns,
  syncMainWorldBridge,
} from '../src/main-world-bridge.js';

// Audit #1003: the MAIN-world bridges (CSRF, Apollo, in-page fetch) used to be
// a manifest content script on <all_urls>. Each answers a same-window
// postMessage carrying the private marker, so ANY site could post
// {__fetchproxy:'csrf-req'} and learn the extension is installed — a
// fingerprint anti-bot vendors use to flag automation. The bridge now lives
// only on hosts some approved MCP may reach, registered dynamically.

interface Registered {
  id: string;
  js?: string[];
  matches?: string[];
  runAt?: string;
  world?: string;
  persistAcrossSessions?: boolean;
  allFrames?: boolean;
}
interface Injection { tabId: number; files: string[]; world?: string; injectImmediately?: boolean }

function installFakeChrome(opts: { registered?: Registered[]; tabs?: { id?: number; url?: string }[] } = {}) {
  let registered: Registered[] = (opts.registered ?? []).map((r) => ({ ...r }));
  const injections: Injection[] = [];
  const calls: string[] = [];
  (globalThis as { chrome?: unknown }).chrome = {
    scripting: {
      getRegisteredContentScripts: async (filter?: { ids?: string[] }) =>
        registered.filter((r) => !filter?.ids || filter.ids.includes(r.id)).map((r) => ({ ...r })),
      registerContentScripts: async (scripts: Registered[]) => {
        calls.push('register');
        for (const s of scripts) {
          if (registered.some((r) => r.id === s.id)) throw new Error(`Duplicate script ID '${s.id}'`);
          registered.push({ ...s });
        }
      },
      updateContentScripts: async (scripts: Registered[]) => {
        calls.push('update');
        for (const s of scripts) {
          const r = registered.find((x) => x.id === s.id);
          if (!r) throw new Error('not registered');
          Object.assign(r, s);
        }
      },
      unregisterContentScripts: async (filter?: { ids?: string[] }) => {
        calls.push('unregister');
        registered = registered.filter((r) => filter?.ids && !filter.ids.includes(r.id));
      },
      executeScript: async (i: { target: { tabId: number }; files: string[]; world?: string; injectImmediately?: boolean }) => {
        injections.push({ tabId: i.target.tabId, files: i.files, world: i.world, injectImmediately: i.injectImmediately });
        return [];
      },
    },
    tabs: { query: async () => opts.tabs ?? [] },
  };
  return { registered: () => registered, injections, calls };
}

describe('bridgeMatchPatterns', () => {
  it('covers each approved domain and its subdomains, nothing else', () => {
    expect(bridgeMatchPatterns(['opentable.com', 'b.example.org'])).toEqual([
      '*://*.b.example.org/*',
      '*://*.opentable.com/*',
    ]);
  });

  it('dedupes, lowercases, and drops anything that is not a plain hostname', () => {
    expect(
      bridgeMatchPatterns(['A.com', 'a.com', '', '*.x.com', 'x.com/path', 'x.com:8080', ' y.com', '<all_urls>']),
    ).toEqual(['*://*.a.com/*']);
  });

  it('uses an exact host for an IP address or a dotless host, where *. is not a valid pattern', () => {
    expect(bridgeMatchPatterns(['127.0.0.1', 'localhost'])).toEqual([
      '*://127.0.0.1/*',
      '*://localhost/*',
    ]);
  });
});

describe('syncMainWorldBridge', () => {
  const saved = (globalThis as { chrome?: unknown }).chrome;
  beforeEach(() => { delete (globalThis as { chrome?: unknown }).chrome; });
  afterEach(() => { (globalThis as { chrome?: unknown }).chrome = saved; });

  it('registers the bridge MAIN-world at document_start on approved hosts only', async () => {
    const fake = installFakeChrome();
    await syncMainWorldBridge(['opentable.com']);
    expect(fake.registered()).toEqual([
      {
        id: MAIN_BRIDGE_SCRIPT_ID,
        js: [MAIN_BRIDGE_FILE],
        matches: ['*://*.opentable.com/*'],
        runAt: 'document_start',
        world: 'MAIN',
        allFrames: false,
        persistAcrossSessions: true,
      },
    ]);
    expect(MAIN_BRIDGE_FILE).toBe('capture-logger.js');
  });

  it('registers nothing while no MCP is approved', async () => {
    const fake = installFakeChrome();
    await syncMainWorldBridge([]);
    expect(fake.registered()).toEqual([]);
    expect(fake.calls).not.toContain('register');
  });

  it('narrows or widens an existing registration in place', async () => {
    const fake = installFakeChrome({
      registered: [{ id: MAIN_BRIDGE_SCRIPT_ID, js: [MAIN_BRIDGE_FILE], matches: ['*://*.a.com/*'], runAt: 'document_start', world: 'MAIN' }],
    });
    await syncMainWorldBridge(['b.com']);
    expect(fake.registered()[0]!.matches).toEqual(['*://*.b.com/*']);
    expect(fake.calls).toEqual(['update']);
  });

  it('does not touch a registration that already matches', async () => {
    const fake = installFakeChrome({
      registered: [{ id: MAIN_BRIDGE_SCRIPT_ID, js: [MAIN_BRIDGE_FILE], matches: ['*://*.a.com/*'], runAt: 'document_start', world: 'MAIN' }],
    });
    await syncMainWorldBridge(['a.com']);
    expect(fake.calls).toEqual([]);
  });

  it('unregisters when the last approval is revoked', async () => {
    const fake = installFakeChrome({
      registered: [{ id: MAIN_BRIDGE_SCRIPT_ID, js: [MAIN_BRIDGE_FILE], matches: ['*://*.a.com/*'], runAt: 'document_start', world: 'MAIN' }],
    });
    await syncMainWorldBridge([]);
    expect(fake.registered()).toEqual([]);
  });

  it('injects into already-open tabs only on hosts newly covered, and only when asked', async () => {
    const tabs = [
      { id: 1, url: 'https://www.a.com/x' }, // already covered before this sync
      { id: 2, url: 'https://b.com/' }, // newly covered
      { id: 3, url: 'https://unrelated.test/' }, // never covered
      { id: 4, url: 'chrome://extensions' },
    ];
    const reg = [{ id: MAIN_BRIDGE_SCRIPT_ID, js: [MAIN_BRIDGE_FILE], matches: ['*://*.a.com/*'], runAt: 'document_start', world: 'MAIN' }];

    const quiet = installFakeChrome({ registered: reg, tabs });
    await syncMainWorldBridge(['a.com', 'b.com']);
    expect(quiet.injections).toEqual([]);

    const fake = installFakeChrome({ registered: reg, tabs });
    await syncMainWorldBridge(['a.com', 'b.com'], { injectIntoOpenTabs: true });
    expect(fake.injections).toEqual([
      { tabId: 2, files: [MAIN_BRIDGE_FILE], world: 'MAIN', injectImmediately: true },
    ]);
  });

  it('no-ops without the dynamic scripting API rather than throwing', async () => {
    (globalThis as { chrome?: unknown }).chrome = { scripting: {} };
    await expect(syncMainWorldBridge(['a.com'])).resolves.toBeUndefined();
  });
});
