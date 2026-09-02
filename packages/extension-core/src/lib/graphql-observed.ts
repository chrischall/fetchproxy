/**
 * The "operation not yet observed on this tab" error, in one place.
 *
 * Two modules need to agree on this string and they live in different
 * bundles: `capture-logger.ts` (MAIN world) *builds* it when the page's
 * Apollo client has no DocumentNode for the requested operation, and the
 * background's `graphql_query` handler *recognises* it to decide whether
 * to keep fanning out across the remaining matching tabs.
 *
 * Recognition matters because the miss is per-tab, not per-site: one
 * stale opentable.com tab (a dashboard, a confirmation page) that never
 * fired the operation would otherwise shadow the restaurant tab that did,
 * on every call, forever — `sendToFirstResponsiveTab` stops at the first
 * tab that answers *at all*. Sharing the constant keeps that detection
 * from being a string match on a message someone reworded.
 */

/** Build the typed miss the MAIN-world Apollo bridge posts back. */
export function notYetObservedError(operationName: string): string {
  return (
    `operation ${operationName} not yet observed on this tab — ` +
    `open a page on the site that triggers this GraphQL operation, then retry`
  );
}

/**
 * True when `error` is the miss above, for any operation name. Matches on
 * the invariant middle of the sentence so the operation name (which varies)
 * and any future trailing hint don't affect it.
 */
export function isNotYetObservedError(error: unknown): boolean {
  return typeof error === 'string' && error.includes('not yet observed on this tab');
}
