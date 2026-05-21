/**
 * After a successful pair (or auto-trust), make sure a tab matching the MCP's
 * declared domain is open. If none exists, open https://<domain>/ in a new tab.
 *
 * The extension's fetch RPC needs a matching tab to issue same-origin
 * window.fetch calls from. Without this helper, the first fetch can fail
 * because no opentable.com tab is open at the moment the MCP starts.
 *
 * Fire-and-forget from the caller's perspective — the returned promise
 * resolves once chrome.tabs.create returns, but the tab's actual page-load
 * is not awaited (it would race the ready frame anyway).
 */

declare const chrome: {
  tabs: {
    query: (q: { url?: string | string[] }) => Promise<{ id?: number; url?: string }[]>;
    create: (props: { url: string }) => Promise<{ id?: number; url?: string }>;
  };
};

// Strict hostname pattern: at least two labels (no bare TLDs), each label
// alphanumeric + hyphen (no underscores, no leading/trailing hyphen).
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

export interface EnsureDomainTabResult {
  opened: boolean;
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
  await chrome.tabs.create({ url: `https://${domain}/` });
  return { opened: true };
}
