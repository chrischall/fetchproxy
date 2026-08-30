/**
 * After a successful pair (or auto-trust), make sure a tab matching the MCP's
 * declared domain is open. If none exists, open https://<domain>/ in a new tab.
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
 */

import { HOSTNAME_RE } from '@fetchproxy/protocol';

/** Title of the tab group relay tabs are collected into. */
export const RELAY_TAB_GROUP_TITLE = 'fetchproxy';

declare const chrome: {
  tabs: {
    query: (q: { url?: string | string[] }) => Promise<{ id?: number; url?: string }[]>;
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
 * Put `tabId` in the shared fetchproxy group, creating it on first use.
 *
 * Deliberately best-effort: every failure here is cosmetic, while the tab it
 * is filing is load-bearing. `chrome.tabs.group` needs a recent Chrome and
 * `chrome.tabGroups` needs the `tabGroups` permission, so a browser or build
 * without either must still get its relay tab.
 */
async function fileInRelayGroup(tabId: number): Promise<number | undefined> {
  try {
    if (typeof chrome.tabs.group !== 'function') return undefined;
    const existing = (await chrome.tabGroups?.query({ title: RELAY_TAB_GROUP_TITLE })) ?? [];
    const groupId = existing.length > 0
      ? await chrome.tabs.group({ tabIds: tabId, groupId: existing[0]!.id })
      : await chrome.tabs.group({ tabIds: tabId });
    // Naming only matters on creation, but it is idempotent and cheap, and it
    // repairs a group the person renamed by hand.
    await chrome.tabGroups?.update(groupId, { title: RELAY_TAB_GROUP_TITLE, color: 'blue' });
    return groupId;
  } catch {
    return undefined;
  }
}

export async function ensureDomainTab(domain: string): Promise<EnsureDomainTabResult> {
  if (!domain || !HOSTNAME_RE.test(domain)) {
    throw new Error(`ensureDomainTab: invalid domain ${JSON.stringify(domain)}`);
  }
  const patterns = [
    `*://${domain}/*`,
    `*://*.${domain}/*`,
  ];
  const tabs = await chrome.tabs.query({ url: patterns });
  if (tabs.length > 0) return { opened: false };
  const tab = await chrome.tabs.create({ url: `https://${domain}/`, active: false });
  const groupId = typeof tab.id === 'number' ? await fileInRelayGroup(tab.id) : undefined;
  return { opened: true, ...(groupId !== undefined ? { groupId } : {}) };
}
