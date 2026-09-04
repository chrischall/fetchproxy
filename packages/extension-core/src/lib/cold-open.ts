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

declare const chrome: {
  tabs: {
    /**
     * Optional on purpose: it is a core API, but the fakes in tests and the
     * narrow `chrome` shapes elsewhere in this package do not all provide it.
     * Absent, the registry falls back to ageing alone — the retry still
     * happens, it is just bounded by the window rather than by the tab.
     */
    get?: (tabId: number) => Promise<{ status?: string } | undefined>;
  };
};

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

/** tabId → the ms timestamp `chrome.tabs.create` returned it. */
const pending = new Map<number, number>();

/** The waits a request should use. Read per call so a test seam can move them. */
export function coldOpenTiming(): ColdOpenTiming {
  return timing;
}

/** Record a tab this extension just opened. Called only on the create path. */
export function noteColdOpen(tabId: number): void {
  pending.set(tabId, Date.now());
}

/**
 * Is at least one recently opened tab still loading?
 *
 * Cheap when the answer is no: an empty registry returns without touching
 * `chrome`, which is the common case on every request that is not racing an
 * open. Settled and vanished tabs are forgotten as they are observed, so a
 * caller polling this converges rather than burning its whole budget.
 */
export async function coldOpenInFlight(): Promise<boolean> {
  if (pending.size === 0) return false;
  const now = Date.now();
  for (const [id, at] of [...pending]) {
    if (now - at > timing.windowMs) pending.delete(id);
  }
  if (pending.size === 0) return false;
  const get = chrome?.tabs?.get;
  if (typeof get !== 'function') return true;
  for (const id of [...pending.keys()]) {
    try {
      const tab = await get.call(chrome.tabs, id);
      if (tab?.status === 'complete') pending.delete(id);
    } catch {
      // The tab is gone — closed while loading, or never really created.
      // Nothing will ever report it complete, so stop waiting on it.
      pending.delete(id);
    }
  }
  return pending.size > 0;
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
