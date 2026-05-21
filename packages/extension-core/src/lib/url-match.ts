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
 * Returns true iff `url` is on ANY of the allowed domains (or a subdomain
 * of one). Used by the extension's per-request allowlist check for
 * multi-domain MCPs.
 */
export function isUrlAllowedForAnyDomain(
  url: string,
  allowedDomains: readonly string[],
): boolean {
  for (const d of allowedDomains) {
    if (isUrlAllowedForDomain(url, d)) return true;
  }
  return false;
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

/**
 * 0.4.1+: find an open tab on a target origin, treating the origin's
 * host as a domain allowlist (exact match OR any subdomain).
 *
 * The strict-prefix `isTabUrlMatch` works for single-domain MCPs
 * whose tabUrl matches the user's actual tab URL byte-for-byte
 * (OpenTable: `https://www.opentable.com/`). It does NOT work for
 * multi-vendor MCPs whose declared `storageDomain` is an apex
 * (HoneyBook: `hbportal.co`) but whose actual tab lives on a vendor
 * subdomain (`thesilkveileventsbyivy.hbportal.co`).
 *
 * Semantics: parse `targetOrigin` to extract its host; return true
 * iff `tabUrl`'s host equals the target host or is a subdomain of it.
 * This mirrors the per-MCP domain-allowlist check
 * (`isUrlAllowedForDomain`) used elsewhere — a tab on any subdomain
 * of a declared domain is reachable by that MCP, so it's also a
 * valid storage-read target.
 */
export function isTabUrlOnOrigin(tabUrl: string, targetOrigin: string): boolean {
  let targetHost: string;
  try {
    targetHost = new URL(targetOrigin).hostname.toLowerCase();
  } catch {
    return false;
  }
  if (!targetHost) return false;
  return isUrlAllowedForDomain(tabUrl, targetHost);
}
