/**
 * Bot-wall / CAPTCHA classification (#86).
 *
 * Promoted from the cohort's per-MCP duplicates: zillow-mcp's
 * PerimeterX detection (#91) and compass's confirmed AWS-WAF block.
 * Every portal MCP sees responses that may be a bot-wall interstitial
 * rather than real content, and misclassifying one as "not found" is
 * the silent-data-corruption failure class rounds 2-3 stamped out. A
 * shared classifier keeps detection in one place so no MCP reinvents it.
 *
 * Detection keys on the response BODY primarily — a PerimeterX
 * interstitial can be served as HTTP 200 (zillow #91), so requiring a
 * 4xx would miss it — with status and headers as additional signal for
 * vendors (AWS WAF) that only block with a 403.
 *
 * Pure: no I/O, no logging. The caller decides what to do with a
 * positive result (typically: back off via {@link backoffDelayMs} and
 * retry, surfacing the {@link FetchErrorKind} `'bot_challenge'`).
 */

/** Bot-wall vendor a positive classification attributes the block to. */
export type BotWallVendor =
  | 'perimeterx'
  | 'aws_waf'
  | 'cloudflare'
  | 'datadome'
  | 'unknown';

/**
 * Discriminated result of {@link classifyBotWall}. `blocked: false`
 * carries no vendor; a positive result always names a vendor (falling
 * back to `'unknown'` only if a future arm detects a wall it can't
 * attribute).
 */
export type BotWallResult =
  | { blocked: true; vendor: BotWallVendor }
  | { blocked: false };

/**
 * PerimeterX px-captcha *block-page* body markers. Any one is
 * sufficient — the interstitial reliably carries at least one, and these
 * appear only on the block page, never on legitimate listing HTML.
 *
 * zillow #92: the original list (zillow #90/#91) also carried
 * `window._pxAppId`. That string is the PerimeterX *sensor* bootstrap,
 * which real portals inline into EVERY SSR page — blocked or not — so it
 * false-flagged every legitimate listing as a bot-wall. It is NOT a
 * block-page marker and must never appear here.
 */
const PX_MARKERS = [
  'meta name="px-captcha"',
  'Access to this page has been denied',
] as const;

/**
 * AWS-WAF challenge body markers. Only consulted alongside a 403 — AWS
 * WAF blocks with a 4xx, so a 200 page that merely references awswaf
 * (e.g. an SSR page embedding an awswaf script for its own forms) must
 * not trip the wall.
 */
const AWS_WAF_BODY_MARKERS = ['AWSWAFCAPTCHA', 'awswaf.com'] as const;

/** Cloudflare block-page title marker. */
const CLOUDFLARE_BODY_MARKER = 'Attention Required! | Cloudflare';

/**
 * Cloudflare JS-challenge interstitial ("Just a moment…") markers — a
 * different page from the block page above, served as 403/503 and
 * sometimes 200 (fleet-audit #1182). The same two definitive markers as
 * mcp-utils `isCloudflareChallenge`: the `_cf_chl_opt` challenge-options
 * bootstrap, or a `<title>` that opens with "Just a moment"
 * (case-insensitive). The title is anchored to the `<title>` element so
 * body copy that merely says "just a moment" never trips the wall.
 *
 * The title rule is the one regex here that can backtrack, so it is both
 * bounded and run over a head of the body only (fleet-audit #1189). The
 * unbounded `<title[^>]*>` this replaced was quadratic over a body of
 * repeated `<title` — one hostile response (bodies can be 5 MiB) pinned the
 * MCP's event loop for tens of minutes. The attribute run is capped at 256
 * chars and the scan at {@link CLOUDFLARE_TITLE_SCAN_MAX}, mirroring
 * mcp-utils `detectEdgeBlock`'s head slice: a challenge page is a few KB with
 * its `<title>` at the top. The `_cf_chl_opt` marker is a plain substring
 * test, linear on any input, so it still reads the whole body.
 *
 * This is a deliberate second copy of mcp-utils' markers, not the shared
 * implementation (fleet-audit #1246): @fetchproxy/server cannot import
 * mcp-utils (the dependency runs the other way). If a marker changes here,
 * change mcp-utils `isCloudflareChallenge` / `detectEdgeBlock` with it — and
 * keep the bound, which is the part that matters.
 */
const CLOUDFLARE_CHL_OPT_MARKER = '_cf_chl_opt';
const CLOUDFLARE_TITLE_RE = /<title(?:\s[^>]{0,256})?>\s*Just a moment/i;
const CLOUDFLARE_TITLE_SCAN_MAX = 64 * 1024;

/** The Cloudflare "Just a moment…" JS-challenge interstitial — linear in `body`. */
function isCloudflareJsChallenge(body: string): boolean {
  return (
    body.includes(CLOUDFLARE_CHL_OPT_MARKER) ||
    CLOUDFLARE_TITLE_RE.test(body.slice(0, CLOUDFLARE_TITLE_SCAN_MAX))
  );
}

/**
 * DataDome challenge marker — the captcha-delivery script host the
 * DataDome interstitial loads. Matched with a size guard so it can't
 * false-positive inside a gargantuan legitimate SSR page that mentions
 * it in passing (mirrors zillow's sign-in heuristic).
 */
const DATADOME_MARKER = 'captcha-delivery';
const DATADOME_MAX_BODY = 80_000;

/** Lower-case a header bag's keys so lookups are case-insensitive. */
function lowerKeys(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

/**
 * Classify a response as a bot-wall interstitial or genuine content.
 *
 * Detection is body-first (so a 200-status PerimeterX wall is caught),
 * with status/headers as additional signal for vendors that only block
 * with a 403. Arms are ordered most-specific first: PerimeterX (the
 * strongest, body-keyed signal) wins over a generic header.
 *
 * A plain 403 with no bot-wall markers stays `blocked: false` — it's a
 * hard auth error, not a transient wall, and callers must not back off
 * on it.
 *
 * @param body     Response body text.
 * @param status   HTTP status code.
 * @param headers  Optional response headers (case-insensitive lookup).
 */
export function classifyBotWall(
  body: string,
  status: number,
  headers?: Record<string, string>,
): BotWallResult {
  const h = headers ? lowerKeys(headers) : {};

  // 1. PerimeterX — body-keyed, the most specific signal. Served as
  //    either 403 or 200, so we never gate it on status.
  if (PX_MARKERS.some((m) => body.includes(m))) {
    return { blocked: true, vendor: 'perimeterx' };
  }

  // 2. AWS WAF — gated on a 403. Either the action header or the
  //    challenge HTML / token host in the body.
  if (status === 403) {
    if (
      'x-amzn-waf-action' in h ||
      AWS_WAF_BODY_MARKERS.some((m) => body.includes(m))
    ) {
      return { blocked: true, vendor: 'aws_waf' };
    }
  }

  // 3. Cloudflare — the `cf-mitigated` header (any status), the
  //    block-page title, or the JS-challenge interstitial markers in the
  //    body (any status — bridge callers often pass no headers).
  if (
    'cf-mitigated' in h ||
    body.includes(CLOUDFLARE_BODY_MARKER) ||
    isCloudflareJsChallenge(body)
  ) {
    return { blocked: true, vendor: 'cloudflare' };
  }

  // 4. DataDome — the captcha-delivery marker, size-guarded.
  if (body.includes(DATADOME_MARKER) && body.length < DATADOME_MAX_BODY) {
    return { blocked: true, vendor: 'datadome' };
  }

  return { blocked: false };
}
