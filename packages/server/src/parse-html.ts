/**
 * SSR-HTML / URL parsing helpers for the scraping portal-MCP cohort.
 *
 * Every SSR-scraping MCP (the realty cohort — zillow, redfin, compass,
 * homes_com, onehome — and friends) re-implements the same handful of
 * pure string utilities to pull state out of server-rendered pages:
 *
 *   * {@link extractGlobalAssign} / {@link extractBalancedObject} —
 *     lift a `window.<X> = {…}` (or `var X = {…}`) JSON object out of an
 *     inline bootstrap script via string-aware balanced-brace walking.
 *   * {@link extractImgTags} — regex-scrape `<img>` `src`/`alt` pairs.
 *   * {@link lastPathSegment} — reduce a URL or path to its final
 *     non-empty path segment (the canonical opaque-id extractor).
 *
 * All pure: no state, no I/O, no logging, no dependencies. Anything
 * portal-specific — the `window.X` variable *names*, CDN-host filters,
 * GraphQL bodies — stays in the consumer.
 *
 * Generalized from compass-mcp's `src/page-state.ts`, homes-mcp's
 * `src/tools/photos.ts`, and the last-path-segment id-extractor that
 * every portal MCP hand-rolls.
 */

/**
 * Walk a balanced `{}` object starting at `start` (which must point at a
 * `{`). Returns the parsed value, or `null` on imbalance / parse error.
 *
 * String-aware: braces inside double-quoted string literals don't move
 * the depth counter, and `\"` / `\\` escapes are handled so a quote (or
 * brace) hidden behind a backslash can't throw off the walk. Stops at
 * the first balanced close brace, so a trailing `;` (or any other
 * inline-script tail) after the object is ignored.
 *
 * @param text  The text to scan (typically the SSR HTML body).
 * @param start Index of the opening `{`.
 * @returns     The parsed object, or `null`.
 */
export function extractBalancedObject(text: string, start: number): unknown | null {
  if (text[start] !== '{') return null;
  let depth = 0;
  let inString = false;
  for (let i = start; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (ch === '\\') {
        i++; // skip the escaped char (covers \" and \\)
        continue;
      }
      if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) {
        const blob = text.slice(start, i + 1);
        try {
          return JSON.parse(blob);
        } catch {
          return null;
        }
      }
    }
  }
  return null;
}

/**
 * Find the first global assignment of the named variable in `html` and
 * return its parsed object. Matches `window.<name> = {…}`,
 * `global.<name> = {…}`, and `var <name> = {…}` (also `let`/`const`).
 *
 * Skips an assignment whose object can't be parsed and keeps scanning,
 * so a same-named-but-unparseable earlier occurrence doesn't shadow a
 * later valid one. The variable name is matched as a literal (regex
 * metacharacters escaped) with a leading/trailing identifier-boundary
 * guard, so a search for `uc` won't match `myuc` or `ucx`.
 *
 * Returns `null` when the variable is absent or no occurrence parses.
 *
 * Note: the *name* of the variable is portal-specific and stays in the
 * caller — this helper just does the lift-and-parse.
 *
 * @param html The SSR HTML (or any text) to scan.
 * @param name The variable identifier, e.g. `__INITIAL_DATA__`, `uc`.
 */
export function extractGlobalAssign(html: string, name: string): Record<string, unknown> | null {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // Accept `window.X = `, `global.X = `, or a `var|let|const X = `
  // declaration. `(?<![\w$])` / `(?![\w$])` keep `X` from matching a
  // longer identifier it's merely a substring of.
  const re = new RegExp(
    `(?:(?:window|global)\\.|(?:var|let|const)\\s+)(?<![\\w$])${escaped}(?![\\w$])\\s*=\\s*`,
    'g',
  );
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    const after = match.index + match[0].length;
    if (html[after] !== '{') continue;
    const obj = extractBalancedObject(html, after);
    if (obj && typeof obj === 'object') {
      return obj as Record<string, unknown>;
    }
  }
  return null;
}

/**
 * Parse `<img>` tags out of an HTML body into `{ src, alt }` records.
 *
 * Regex-based rather than a full HTML parser: we only want `src` (and
 * `alt` for filtering hints), the dependency surface stays empty, and
 * the input is predictable server-rendered output. Attribute order is
 * irrelevant (`src`/`alt` are captured independently), single and
 * double quotes are both accepted, and matching is case-insensitive.
 *
 * Tags with no `src` are skipped. `alt` is omitted when the attribute
 * is absent, but a present-but-empty `alt=""` is preserved as `''`
 * (a decorative image is distinct from one with no alt at all).
 *
 * Host/CDN filtering and dedup are portal-specific and stay in the
 * caller.
 *
 * @param html The HTML body to scrape.
 */
export function extractImgTags(html: string): Array<{ src: string; alt?: string }> {
  const out: Array<{ src: string; alt?: string }> = [];
  const tagRe = /<img\b[^>]*>/gi;
  const srcRe = /\bsrc\s*=\s*["']([^"']+)["']/i;
  const altRe = /\balt\s*=\s*["']([^"']*)["']/i;
  for (const m of html.matchAll(tagRe)) {
    const tag = m[0];
    const src = srcRe.exec(tag)?.[1];
    if (!src) continue;
    const alt = altRe.exec(tag)?.[1];
    out.push(alt !== undefined ? { src, alt } : { src });
  }
  return out;
}

/**
 * Reduce a URL or bare path to its final non-empty path segment — the
 * canonical opaque-id extractor (e.g. a `<zpid>_zpid`, a base36 hash, a
 * `<id>_lid` token). Strips the scheme/host prefix, then any `?query`
 * and `#fragment`, then returns the last slash-delimited segment that
 * isn't empty (so trailing slashes and `//` runs are tolerated).
 *
 * Returns `''` when there is no path segment (host-only / root / empty
 * input). Callers that prefer one source field over another (e.g.
 * `url` over a `@id` that carries a fragment) should pick the field
 * before calling.
 *
 * @param urlOrPath A full URL or a bare path.
 */
export function lastPathSegment(urlOrPath: string): string {
  const path = urlOrPath.replace(/^[a-z][a-z0-9+.-]*:\/\/[^/]+/i, '').replace(/[?#].*$/, '');
  const segments = path.split('/').filter((s) => s.length > 0);
  return segments[segments.length - 1] ?? '';
}
