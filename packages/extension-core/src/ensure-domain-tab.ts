/**
 * After a successful pair (or auto-trust), make sure a tab matching the MCP's
 * declared domain is open. If none exists, open https://<domain>/ in a new tab.
 *
 * "None exists" is asked of the WHOLE browser, never of the fetchproxy group:
 * every window, every tab group, the person's own tabs included. A tab that is
 * already on the domain is reused wherever it lives and is deliberately NOT
 * moved into the relay group — it is theirs, and relocating a tab out from
 * under someone is worse than an ungrouped relay. Only a tab this helper had
 * to open itself is filed under the group.
 *
 * The extension's fetch RPC needs a matching tab to issue same-origin
 * window.fetch calls from. Without this helper, the first fetch can fail
 * because no opentable.com tab is open at the moment the MCP starts.
 *
 * The tab is opened IN THE BACKGROUND and collected into one "fetchproxy" tab
 * group. A relay tab is machinery, not somewhere the person asked to go:
 * stealing focus interrupts whatever they were doing, and an MCP fleet opening
 * one tab per domain otherwise scatters them through the tab strip with no
 * indication of what created them or which are safe to close.
 *
 * Fire-and-forget from the caller's perspective — the returned promise
 * resolves once chrome.tabs.create returns, but the tab's actual page-load
 * is not awaited (it would race the ready frame anyway).
 *
 * What the caller does NOT have to do is tell the request path about that
 * gap: a tab opened here is recorded in the cold-open registry
 * (`lib/cold-open.ts`), and `sendToFirstResponsiveTab` waits on it rather than
 * reporting that no tab is open on a host it is at that moment opening (#291).
 */

import { HOSTNAME_RE } from '@fetchproxy/protocol';
import { noteColdOpen } from './lib/cold-open.js';
import { isUrlAllowedForDomain } from './lib/url-match.js';

/** Title of the tab group relay tabs are collected into. */
export const RELAY_TAB_GROUP_TITLE = 'fetchproxy';

declare const chrome: {
  tabs: {
    query: (q: {
      url?: string | string[];
    }) => Promise<{ id?: number; url?: string; pendingUrl?: string }[]>;
    create: (props: { url: string; active?: boolean }) => Promise<{ id?: number; url?: string }>;
    group?: (opts: { tabIds: number | number[]; groupId?: number }) => Promise<number>;
  };
  tabGroups?: {
    query: (q: { title?: string }) => Promise<{ id: number; title?: string }[]>;
    update: (groupId: number, props: { title?: string; color?: string }) => Promise<unknown>;
  };
};

export interface EnsureDomainTabResult {
  opened: boolean;
  /** The tab group the new tab was filed under, when grouping succeeded. */
  groupId?: number;
}

/**
 * In-flight resolution of the shared group id, so CONCURRENT callers share one
 * group instead of each creating their own.
 *
 * A multi-domain MCP fires `ensureDomainTab` once per domain without awaiting
 * (`background/approval.ts`, `background/server-hello.ts`), so without this
 * latch every one of them would `tabGroups.query`, all see nothing, and all
 * create a separate "fetchproxy" group — the exact scattering this feature
 * exists to prevent. Reset whenever the group turns out to be unusable (the
 * person closed it), so a later call rebuilds one rather than failing forever.
 */
let relayGroupPromise: Promise<number | undefined> | null = null;

/** Resolve the group id once: adopt an existing group, else create one. */
async function resolveRelayGroup(firstTabId: number): Promise<number | undefined> {
  const existing = (await chrome.tabGroups?.query({ title: RELAY_TAB_GROUP_TITLE })) ?? [];
  const groupId = existing.length > 0
    ? await chrome.tabs.group!({ tabIds: firstTabId, groupId: existing[0]!.id })
    : await chrome.tabs.group!({ tabIds: firstTabId });
  // Naming only matters on creation, but it is idempotent and cheap, and it
  // repairs a group the person renamed by hand.
  await chrome.tabGroups?.update(groupId, { title: RELAY_TAB_GROUP_TITLE, color: 'blue' });
  return groupId;
}

/**
 * Put `tabId` in the shared fetchproxy group, creating it on first use.
 *
 * Deliberately best-effort: every failure here is cosmetic, while the tab it
 * is filing is load-bearing. `chrome.tabs.group` needs a recent Chrome and
 * `chrome.tabGroups` needs the `tabGroups` permission, so a browser or build
 * without either must still get its relay tab.
 */
async function fileInRelayGroup(tabId: number): Promise<number | undefined> {
  if (typeof chrome.tabs.group !== 'function') return undefined;
  try {
    if (relayGroupPromise === null) {
      relayGroupPromise = resolveRelayGroup(tabId);
      return await relayGroupPromise;
    }
    const groupId = await relayGroupPromise;
    if (groupId === undefined) return undefined;
    await chrome.tabs.group({ tabIds: tabId, groupId });
    return groupId;
  } catch {
    // Either the creation failed or the remembered group is gone. Drop the
    // latch so the next call re-resolves instead of inheriting the failure.
    relayGroupPromise = null;
    return undefined;
  }
}

/**
 * In-flight opens, keyed by lowercased domain.
 *
 * Both callers loop over the MCP's declared domains firing this WITHOUT
 * awaiting (`background/approval.ts`, `background/server-hello.ts`), and a
 * pair approval is routinely followed by the server hello that repeats the
 * same list. Without a latch each of those calls queries, all of them see
 * nothing open yet, and each opens its own tab — which is how one domain ends
 * up with several relay tabs. Concurrent callers now share one resolution;
 * the entry is dropped as soon as it settles, so a later call opens a
 * replacement rather than reusing a stale answer.
 */
const inFlight = new Map<string, Promise<EnsureDomainTabResult>>();

/**
 * Is a tab already NAVIGATING to this domain, in any group or window?
 *
 * `chrome.tabs.query({url})` filters on `url`, which Chrome sets only once a
 * navigation commits; until then the destination lives in `pendingUrl` and the
 * tab matches nothing. So a tab opened a moment ago — by the person, by
 * another profile's MCP, or by a sibling call whose latch has already
 * settled — is invisible to the pattern query, and opening a second one is
 * exactly the duplicate this check exists to prevent.
 *
 * Read only when the pattern query came back empty, so the common case still
 * costs one native query.
 */
async function loadingTabOnDomain(domain: string): Promise<boolean> {
  const all = await chrome.tabs.query({});
  return all.some(
    (t) => typeof t.pendingUrl === 'string' && isUrlAllowedForDomain(t.pendingUrl, domain),
  );
}

/** Test seam: forget the remembered group and any in-flight opens. */
export function __resetRelayGroupForTests(): void {
  relayGroupPromise = null;
  inFlight.clear();
}

export function ensureDomainTab(domain: string): Promise<EnsureDomainTabResult> {
  // Validated before the latch: an invalid domain is the caller's bug and must
  // reject every time, never be cached or shared with an unrelated call.
  if (!domain || !HOSTNAME_RE.test(domain)) {
    return Promise.reject(
      new Error(`ensureDomainTab: invalid domain ${JSON.stringify(domain)}`),
    );
  }
  const key = domain.toLowerCase();
  const running = inFlight.get(key);
  if (running) return running;
  const settled = openDomainTab(domain).finally(() => {
    inFlight.delete(key);
  });
  inFlight.set(key, settled);
  return settled;
}

async function openDomainTab(domain: string): Promise<EnsureDomainTabResult> {
  const patterns = [
    `*://${domain}/*`,
    `*://*.${domain}/*`,
  ];
  const tabs = await chrome.tabs.query({ url: patterns });
  if (tabs.length > 0) return { opened: false };
  if (await loadingTabOnDomain(domain)) return { opened: false };
  const tab = await chrome.tabs.create({ url: `https://${domain}/`, active: false });
  // Registered BEFORE the grouping, which is cosmetic and may fail: the race
  // this closes is against the page load, and it starts the moment the tab
  // exists.
  if (typeof tab.id === 'number') noteColdOpen(tab.id, domain);
  const groupId = typeof tab.id === 'number' ? await fileInRelayGroup(tab.id) : undefined;
  return { opened: true, ...(groupId !== undefined ? { groupId } : {}) };
}
