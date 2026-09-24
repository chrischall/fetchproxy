/**
 * Where the MAIN-world bridge (`capture-logger.js`) runs.
 *
 * The bridge answers the isolated world's CSRF-token, Apollo GraphQL and
 * in-page fetch requests over the window's `postMessage` bus. That bus is
 * shared with the page, so a script on ANY page it runs on can post the
 * private `__fetchproxy` marker and get a reply — the extension is detectable.
 * Nothing about the bus can hide that (a page sees every message the isolated
 * world sends), so the fix is where the script runs, not how it answers.
 *
 * It used to be a manifest content script on `<all_urls>`, which made every
 * site the user visited able to fingerprint the extension — and a bridge
 * extension is exactly what anti-bot vendors flag as automation (audit
 * #1003). It is now registered at runtime, via `chrome.scripting`, only on
 * the hosts some approved MCP may reach: the same "exact host or any
 * subdomain" rule the per-request allowlist applies. Still `document_start`
 * in the MAIN world, so the Apollo bridge keeps its head start on the page's
 * `window.__APOLLO_CLIENT__` assignment.
 *
 * Residual exposure, stated rather than hidden: a site an MCP is approved for
 * can still detect the bridge, and a tab that loaded while its host was
 * approved keeps the bridge until it reloads after a revoke.
 */

import { isInjectableUrl, matchesAnyPattern } from './reinject-content-scripts.js';

export const MAIN_BRIDGE_SCRIPT_ID = 'fetchproxy-main-bridge';
export const MAIN_BRIDGE_FILE = 'capture-logger.js';

interface RegisteredScript {
  id: string;
  js?: string[];
  matches?: string[];
  runAt?: 'document_start' | 'document_end' | 'document_idle';
  world?: 'MAIN' | 'ISOLATED';
  allFrames?: boolean;
  persistAcrossSessions?: boolean;
}

interface ScriptingApi {
  getRegisteredContentScripts?: (filter?: { ids?: string[] }) => Promise<RegisteredScript[]>;
  registerContentScripts?: (scripts: RegisteredScript[]) => Promise<void>;
  updateContentScripts?: (scripts: RegisteredScript[]) => Promise<void>;
  unregisterContentScripts?: (filter?: { ids?: string[] }) => Promise<void>;
  executeScript?: (injection: {
    target: { tabId: number };
    files: string[];
    world?: 'MAIN' | 'ISOLATED';
    injectImmediately?: boolean;
  }) => Promise<unknown>;
}

function api(): {
  scripting?: ScriptingApi;
  tabs?: { query?: (q: Record<string, never>) => Promise<{ id?: number; url?: string }[]> };
} {
  return ((globalThis as { chrome?: unknown }).chrome ?? {}) as ReturnType<typeof api>;
}

const HOST_LABELS = /^[a-z0-9-]+(\.[a-z0-9-]+)*$/;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Chrome match patterns for a set of approved domains. `*://*.d/*` covers the
 * apex and every subdomain, as the trust check does. An IP address or a
 * dotless host gets an exact pattern (`*.` is only meaningful before a
 * domain). Anything that is not a plain hostname is dropped rather than
 * passed through — one invalid pattern makes Chrome reject the whole
 * registration, and a wildcard must never widen it.
 */
export function bridgeMatchPatterns(domains: Iterable<string>): string[] {
  const out = new Set<string>();
  for (const raw of domains) {
    if (typeof raw !== 'string') continue;
    const d = raw.toLowerCase();
    if (!HOST_LABELS.test(d)) continue;
    out.add(IPV4.test(d) || !d.includes('.') ? `*://${d}/*` : `*://*.${d}/*`);
  }
  return [...out].sort();
}

/** The registration `syncMainWorldBridge` maintains, for `reinjectContentScripts`. */
export function mainBridgeScriptFor(domains: Iterable<string>): {
  matches: string[];
  js: string[];
  world: 'MAIN';
  run_at: 'document_start';
} {
  return {
    matches: bridgeMatchPatterns(domains),
    js: [MAIN_BRIDGE_FILE],
    world: 'MAIN',
    run_at: 'document_start',
  };
}

const sameSet = (a: readonly string[], b: readonly string[]): boolean =>
  a.length === b.length && [...a].sort().every((x, i) => x === [...b].sort()[i]);

let queue: Promise<void> = Promise.resolve();

/**
 * Make the registered bridge cover exactly `domains`. Serialised, so an
 * approval and a revoke racing in one context apply in order.
 *
 * `injectIntoOpenTabs` also injects the bridge into tabs already open on a
 * host this call newly covers — a site approved while its tab is open would
 * otherwise have no bridge until reloaded. Tabs covered before this call are
 * skipped, but that is only a shortcut: a tab left open across a revoke and a
 * re-approve already has the bridge yet looks newly covered here. The bridge
 * itself refuses a second install (`installMainWorldBridges`), so a repeat
 * injection is a no-op rather than a second listener answering — and, for an
 * in-page POST, re-sending — the same request. Best-effort throughout; a
 * failure is logged, never thrown.
 */
export function syncMainWorldBridge(
  domains: Iterable<string>,
  opts: { injectIntoOpenTabs?: boolean } = {},
): Promise<void> {
  const list = [...domains];
  const run = queue.then(() => doSync(list, opts));
  queue = run.catch(() => {});
  return run;
}

async function doSync(domains: string[], opts: { injectIntoOpenTabs?: boolean }): Promise<void> {
  const s = api().scripting;
  if (
    typeof s?.getRegisteredContentScripts !== 'function' ||
    typeof s.registerContentScripts !== 'function' ||
    typeof s.updateContentScripts !== 'function' ||
    typeof s.unregisterContentScripts !== 'function'
  ) {
    return;
  }
  try {
    const matches = bridgeMatchPatterns(domains);
    const [existing] = await s.getRegisteredContentScripts({ ids: [MAIN_BRIDGE_SCRIPT_ID] });
    const before = existing?.matches ?? [];
    if (matches.length === 0) {
      if (existing) await s.unregisterContentScripts({ ids: [MAIN_BRIDGE_SCRIPT_ID] });
      return;
    }
    if (!existing) {
      await s.registerContentScripts([
        {
          id: MAIN_BRIDGE_SCRIPT_ID,
          js: [MAIN_BRIDGE_FILE],
          matches,
          runAt: 'document_start',
          world: 'MAIN',
          allFrames: false,
          persistAcrossSessions: true,
        },
      ]);
    } else if (!sameSet(before, matches)) {
      await s.updateContentScripts([{ id: MAIN_BRIDGE_SCRIPT_ID, matches }]);
    }
    if (opts.injectIntoOpenTabs) await injectNewlyCovered(s, before, matches);
  } catch (e) {
    console.error('[fetchproxy] could not update the page bridge registration:', e);
  }
}

async function injectNewlyCovered(
  s: ScriptingApi,
  before: string[],
  after: string[],
): Promise<void> {
  const added = after.filter((p) => !before.includes(p));
  const query = api().tabs?.query;
  if (added.length === 0 || typeof s.executeScript !== 'function' || typeof query !== 'function') {
    return;
  }
  const tabs = await query({});
  for (const tab of tabs) {
    if (typeof tab.id !== 'number' || !isInjectableUrl(tab.url)) continue;
    const url = tab.url ?? '';
    if (!matchesAnyPattern(url, added) || matchesAnyPattern(url, before)) continue;
    try {
      await s.executeScript({
        target: { tabId: tab.id },
        files: [MAIN_BRIDGE_FILE],
        world: 'MAIN',
        injectImmediately: true,
      });
    } catch {
      // Restricted page or a tab mid-navigation — its next load picks the
      // registration up.
    }
  }
}

/** {@link syncMainWorldBridge} onto whatever the trust store approves now. Never throws. */
export async function syncMainWorldBridgeFromTrust(
  trust: { approvedDomains(): Promise<string[]> },
  opts: { injectIntoOpenTabs?: boolean } = {},
): Promise<void> {
  try {
    await syncMainWorldBridge(await trust.approvedDomains(), opts);
  } catch (e) {
    console.error('[fetchproxy] could not read approved domains for the page bridge:', e);
  }
}
