/**
 * Shared text codecs.
 *
 * `enc` was a module-level singleton in `background.ts`, read by both the
 * hello path and the approval path. It lives here so those two modules
 * share one instance rather than each constructing their own.
 */

export const enc = new TextEncoder();
