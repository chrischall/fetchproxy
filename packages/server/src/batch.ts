/**
 * Batch-paging primitives for bulk fan-out.
 *
 * `chunk` and `sleep` pair with the fan-out kit
 * ({@link mapWithConcurrency} / `TokenBucket` / `backoffDelayMs`): a
 * large id list gets split into safe-sized pages with `chunk`,
 * dispatched one page at a time, with `sleep` spacing the pages so a
 * single tool call doesn't stampede the upstream.
 *
 * Both are pure — no shared state, no I/O beyond `sleep`'s timer.
 * Hoisted from zillow-mcp's bulk-get (`src/throttle.ts` /
 * `src/backoff.ts`).
 */

/**
 * Split `items` into pages of at most `size`, in order. A non-positive
 * `size` collapses to a single page (defensive — never loops forever).
 * Returns a fresh outer array of fresh slices; the input is never
 * mutated.
 *
 * @param items The list to page.
 * @param size  Max items per page. `<= 0` → one page with everything.
 * @returns     Pages, in input order; `[]` for an empty input.
 */
export function chunk<T>(items: T[], size: number): T[][] {
  if (items.length === 0) return [];
  if (size <= 0) return [items.slice()];
  const pages: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    pages.push(items.slice(i, i + size));
  }
  return pages;
}

/**
 * Promise-based sleep. Resolves (to `undefined`) after `ms`
 * milliseconds. Used to space out paged dispatches in a bulk fan-out.
 *
 * @param ms Delay in milliseconds.
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
