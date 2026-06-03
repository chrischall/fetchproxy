/**
 * Scope canonicalisation, hashing, intersection, and equality helpers.
 *
 * These were originally private functions in background.ts. Extracted here
 * so they can be unit-tested in isolation and reused by other modules.
 */

import { sha256, toHex } from '@fetchproxy/protocol';
import type { CaptureHeaderDecl, IndexedDbScopeDecl, StoragePointerDecl } from '@fetchproxy/protocol';

// ---------------------------------------------------------------------------
// Scope interface
// ---------------------------------------------------------------------------

export interface Scope {
  capabilities: string[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: CaptureHeaderDecl[];
  indexedDbScopes: IndexedDbScopeDecl[];
  localStoragePointers: StoragePointerDecl[];
  sessionStoragePointers: StoragePointerDecl[];
}

// ---------------------------------------------------------------------------
// Equality helpers (moved from background.ts, exported for reuse)
// ---------------------------------------------------------------------------

/**
 * Order-insensitive equality for two capability lists. A capability
 * upgrade (e.g. fetch → fetch+read_cookies) is conservative: we want
 * the user to re-approve when the MCP asks for more access.
 */
export function sameCapabilitySet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const sa = [...a].sort();
  const sb = [...b].sort();
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
}

export function sameScopeArrays(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const sa = [...a].sort();
  const sb = [...b].sort();
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
}

export function sameCaptureHeaders(
  a: readonly { urlPattern: string; headerName: string }[],
  b: readonly { urlPattern: string; headerName: string }[],
): boolean {
  if (a.length !== b.length) return false;
  const norm = (
    arr: readonly { urlPattern: string; headerName: string }[],
  ): string[] => arr.map((d) => `${d.urlPattern}\x00${d.headerName}`).sort();
  const sa = norm(a);
  const sb = norm(b);
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
}

export function sameIndexedDbScopes(
  a: readonly IndexedDbScopeDecl[],
  b: readonly IndexedDbScopeDecl[],
): boolean {
  if (a.length !== b.length) return false;
  const norm = (arr: readonly IndexedDbScopeDecl[]): string[] =>
    arr
      .map(
        (d) =>
          `${d.origin}\x00${d.database}\x00${d.store}\x00${[...d.keys].sort().join(',')}`,
      )
      .sort();
  const sa = norm(a);
  const sb = norm(b);
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
}

export function sameStoragePointers(
  a: readonly StoragePointerDecl[],
  b: readonly StoragePointerDecl[],
): boolean {
  if (a.length !== b.length) return false;
  const norm = (arr: readonly StoragePointerDecl[]): string[] =>
    arr.map((d) => `${d.key}\x00${d.jsonPointer}`).sort();
  const sa = norm(a);
  const sb = norm(b);
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Scope hashing
// ---------------------------------------------------------------------------

/** Canonical string key for a captureHeaders entry. */
function normCaptureHeader(d: CaptureHeaderDecl): string {
  return `${d.urlPattern}\x00${d.headerName}`;
}

/** Canonical string key for an IndexedDbScopeDecl entry. */
function normIndexedDbScope(d: IndexedDbScopeDecl): string {
  return `${d.origin}\x00${d.database}\x00${d.store}\x00${[...d.keys].sort().join(',')}`;
}

/** Canonical string key for a StoragePointerDecl entry. */
function normStoragePointer(d: StoragePointerDecl): string {
  return `${d.key}\x00${d.jsonPointer}`;
}

/**
 * Deterministic, order-independent hash of a Scope. Returns a hex string.
 *
 * All arrays are sorted before serialisation so that the hash is stable
 * regardless of the order in which the MCP declared items.
 */
export async function scopeHash(s: Scope): Promise<string> {
  const canonical = {
    capabilities: [...s.capabilities].sort(),
    cookieKeys: [...s.cookieKeys].sort(),
    localStorageKeys: [...s.localStorageKeys].sort(),
    sessionStorageKeys: [...s.sessionStorageKeys].sort(),
    captureHeaders: [...s.captureHeaders].map(normCaptureHeader).sort(),
    indexedDbScopes: [...s.indexedDbScopes].map(normIndexedDbScope).sort(),
    localStoragePointers: [...s.localStoragePointers].map(normStoragePointer).sort(),
    sessionStoragePointers: [...s.sessionStoragePointers].map(normStoragePointer).sort(),
  };
  const json = JSON.stringify(canonical);
  const bytes = new TextEncoder().encode(json);
  const hash = await sha256(bytes);
  return toHex(hash);
}

// ---------------------------------------------------------------------------
// Scope intersection and subset check
// ---------------------------------------------------------------------------

/**
 * Per-field set intersection: returns a new Scope containing only the
 * members that are present in both `approved` and `declared`.
 *
 * For object-array fields (captureHeaders, indexedDbScopes, pointers) an
 * entry from `declared` is kept only when a deep-equal entry exists in
 * `approved` (using the same normalisation as the equality helpers).
 */
export function intersectScope(approved: Scope, declared: Scope): Scope {
  // String-array fields — order-insensitive set intersection.
  const intersectStrings = (ap: readonly string[], dc: readonly string[]): string[] => {
    const apSet = new Set(ap);
    return dc.filter((v) => apSet.has(v));
  };

  // captureHeaders — match on canonical key.
  const apCaptureSet = new Set(approved.captureHeaders.map(normCaptureHeader));
  const captureHeaders = declared.captureHeaders.filter((d) =>
    apCaptureSet.has(normCaptureHeader(d)),
  );

  // indexedDbScopes — match on canonical key.
  const apIndexedSet = new Set(approved.indexedDbScopes.map(normIndexedDbScope));
  const indexedDbScopes = declared.indexedDbScopes.filter((d) =>
    apIndexedSet.has(normIndexedDbScope(d)),
  );

  // Storage pointers — match on canonical key.
  const apLocalPtrSet = new Set(approved.localStoragePointers.map(normStoragePointer));
  const localStoragePointers = declared.localStoragePointers.filter((d) =>
    apLocalPtrSet.has(normStoragePointer(d)),
  );

  const apSessionPtrSet = new Set(approved.sessionStoragePointers.map(normStoragePointer));
  const sessionStoragePointers = declared.sessionStoragePointers.filter((d) =>
    apSessionPtrSet.has(normStoragePointer(d)),
  );

  return {
    capabilities: intersectStrings(approved.capabilities, declared.capabilities),
    cookieKeys: intersectStrings(approved.cookieKeys, declared.cookieKeys),
    localStorageKeys: intersectStrings(approved.localStorageKeys, declared.localStorageKeys),
    sessionStorageKeys: intersectStrings(approved.sessionStorageKeys, declared.sessionStorageKeys),
    captureHeaders,
    indexedDbScopes,
    localStoragePointers,
    sessionStoragePointers,
  };
}

/**
 * Returns true iff every member of `declared` is present in `approved`.
 *
 * Implemented as: `intersectScope(approved, declared)` deep-equals
 * `declared` (order-insensitively), i.e. nothing was dropped.
 */
export function isScopeSubset(declared: Scope, approved: Scope): boolean {
  const intersection = intersectScope(approved, declared);
  return (
    sameCapabilitySet(intersection.capabilities, declared.capabilities) &&
    sameScopeArrays(intersection.cookieKeys, declared.cookieKeys) &&
    sameScopeArrays(intersection.localStorageKeys, declared.localStorageKeys) &&
    sameScopeArrays(intersection.sessionStorageKeys, declared.sessionStorageKeys) &&
    sameCaptureHeaders(intersection.captureHeaders, declared.captureHeaders) &&
    sameIndexedDbScopes(intersection.indexedDbScopes, declared.indexedDbScopes) &&
    sameStoragePointers(intersection.localStoragePointers, declared.localStoragePointers) &&
    sameStoragePointers(intersection.sessionStoragePointers, declared.sessionStoragePointers)
  );
}
