/**
 * Domain allowlist + tab-URL prefix matching. Pure helpers, unit
 * tested. Defenses T3 (per-MCP scope) and the tab routing logic
 * for fetch requests.
 */

/**
 * Returns true iff `url` is on a domain the MCP is allowed to reach.
 * Allowed = exact hostname match OR a subdomain (`.foo.com` matches
 * `foo.com`). Rejects non-http(s) schemes outright (no javascript:,
 * data:, file:, etc.).
 */
export function isUrlAllowedForDomain(url: string, allowedDomain: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return false;
  }
  const host = parsed.hostname.toLowerCase();
  const allowed = allowedDomain.toLowerCase();
  return host === allowed || host.endsWith('.' + allowed);
}

/**
 * Returns true iff a tab's URL begins with the prefix the MCP server
 * supplied in `init.tabUrl`. The MCP picks a coarse prefix
 * ("https://www.opentable.com/") and the extension finds the first
 * matching open tab.
 */
export function isTabUrlMatch(tabUrl: string, prefix: string): boolean {
  return tabUrl.startsWith(prefix);
}
