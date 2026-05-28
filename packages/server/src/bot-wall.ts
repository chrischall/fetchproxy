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
 * The three PerimeterX px-captcha body markers (zillow #90/#91). Any
 * one is sufficient — the interstitial reliably carries at least one,
 * and they don't appear in legitimate listing HTML.
 */
const PX_MARKERS = [
  'window._pxAppId',
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

  // 3. Cloudflare — the `cf-mitigated` header (any status) or the
  //    block-page title in the body.
  if ('cf-mitigated' in h || body.includes(CLOUDFLARE_BODY_MARKER)) {
    return { blocked: true, vendor: 'cloudflare' };
  }

  // 4. DataDome — the captcha-delivery marker, size-guarded.
  if (body.includes(DATADOME_MARKER) && body.length < DATADOME_MAX_BODY) {
    return { blocked: true, vendor: 'datadome' };
  }

  return { blocked: false };
}
