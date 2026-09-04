/**
 * The cold-open registry: relay tabs `ensureDomainTab` opened moments ago
 * that have not finished loading yet (#291).
 *
 * It exists to break a race between two halves of the extension that must not
 * import each other. `ensureDomainTab` opens a tab per declared domain at
 * server-hello and deliberately does NOT await the page load (awaiting it
 * would race the content script's ready frame anyway); the request path,
 * meanwhile, asks `chrome.tabs.query` what is open and answers "no tab
 * matching <url> — open a tab on that host" when nothing is. Between those two
 * facts sat a request that failed by telling the person to do the thing the
 * extension was already doing — and which succeeded verbatim a few seconds
 * later.
 *
 * So this module is a leaf both sides depend on rather than an edge between
 * them: `ensure-domain-tab.ts` writes to it, `lib/send-to-responsive-tab.ts`
 * reads from it, and neither imports the other. Module state IS the mechanism
 * here (the service worker is the only thing that knows a tab is mid-open), so
 * it carries a test seam to clear it.
 *
 * Ageing matters as much as recording: an MV3 service worker can be evicted
 * between the open and the request, and a tab the person closes while it loads
 * is never reported complete. An entry older than the window is therefore
 * dropped unasked, so a leak costs one stale retry budget rather than
 * a permanently confused request path.
 */

import type { ChromeApi } from '../chrome-api.js';
import { isUrlAllowedForDomain } from './url-match.js';

declare const chrome: ChromeApi;

/** How long an unsettled entry is believed, in ms. */
const DEFAULT_WINDOW_MS = 15_000;
/** How long a request will wait on an in-flight open before giving up, in ms. */
const DEFAULT_BUDGET_MS = 3_000;
/** Gap between retry attempts while waiting, in ms. */
const DEFAULT_POLL_MS = 250;

export interface ColdOpenTiming {
  windowMs: number;
  budgetMs: number;
  pollMs: number;
}

const DEFAULT_TIMING: ColdOpenTiming = {
  windowMs: DEFAULT_WINDOW_MS,
  budgetMs: DEFAULT_BUDGET_MS,
  pollMs: DEFAULT_POLL_MS,
};

let timing: ColdOpenTiming = { ...DEFAULT_TIMING };

/** tabId → the domain it was opened for, and when. */
const pending = new Map<number, { domain: string; at: number }>();

/**
 * Could a tab opened for `domain` end up serving a request aimed at `url`?
 *
 * Deliberately looser than the caller's own tab matcher, and in both
 * directions. A profile that declares the apex `zillow.com` opens its relay
 * tab there while the request is for `www.zillow.com`; asked through
 * `isTabUrlOnOrigin`, the apex is NOT on that origin, so matching that way
 * would refuse the wait and put the original race straight back (#291). The
 * reverse — a declared `www.` host and a request on the apex — is rarer but
 * the same shape.
 *
 * The asymmetry of the two errors is what settles it: waiting slightly too
 * often costs one bounded delay, while waiting too rarely brings back a
 * failure that tells the person to open a tab the extension is opening.
 */
function couldServe(domain: string, url: string): boolean {
  if (isUrlAllowedForDomain(url, domain)) return true;
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase();
  } catch {
    return false;
  }
  const d = domain.toLowerCase();
  return d.endsWith('.' + host);
}

/** The waits a request should use. Read per call so a test seam can move them. */
export function coldOpenTiming(): ColdOpenTiming {
  return timing;
}

/** Record a tab this extension just opened. Called only on the create path. */
export function noteColdOpen(tabId: number, domain: string): void {
  pending.set(tabId, { domain, at: Date.now() });
}

/**
 * Is a tab that could serve `url` still loading?
 *
 * Scoped to the host on purpose (#293). `ensureDomainTab` runs once per
 * DECLARED domain, so a multi-domain MCP routinely has one host opening while
 * a request goes to another; answering "yes" to every caller made that request
 * wait the whole budget and then be told a tab was arriving for a host nothing
 * was opening — a false statement rather than a slow true one, and one that
 * also suppressed `fpx health`'s `--subdomain` hint.
 *
 * Cheap when the answer is no: an empty registry returns without touching
 * `chrome`, which is the common case on every request that is not racing an
 * open. Settled and vanished tabs are forgotten as they are observed — for
 * EVERY pending entry, not only the relevant ones, since the ageing is what
 * bounds the map — so a caller polling this converges rather than burning its
 * whole budget.
 */
export async function coldOpenInFlight(url: string): Promise<boolean> {
  if (pending.size === 0) return false;
  const now = Date.now();
  for (const [id, entry] of [...pending]) {
    if (now - entry.at > timing.windowMs) pending.delete(id);
  }
  if (pending.size === 0) return false;
  const get = chrome?.tabs?.get;
  if (typeof get !== 'function') return relevant(url);
  for (const [id] of [...pending]) {
    try {
      const tab = await get.call(chrome.tabs, id);
      if (tab?.status === 'complete') pending.delete(id);
    } catch {
      // The tab is gone — closed while loading, or never really created.
      // Nothing will ever report it complete, so stop waiting on it.
      pending.delete(id);
    }
  }
  return relevant(url);
}

function relevant(url: string): boolean {
  for (const { domain } of pending.values()) {
    if (couldServe(domain, url)) return true;
  }
  return false;
}

/** Test seam: forget every recorded open and restore the production waits. */
export function __resetColdOpenForTests(): void {
  pending.clear();
  timing = { ...DEFAULT_TIMING };
}

/** Test seam: shrink the waits so a retry case need not sleep for seconds. */
export function __setColdOpenTimingForTests(next: Partial<ColdOpenTiming>): void {
  timing = { ...timing, ...next };
}
