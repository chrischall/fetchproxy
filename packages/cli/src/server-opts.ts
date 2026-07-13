import type { Capability } from '@fetchproxy/server';
import type { CaptureHeaderDecl, IndexedDbScopeDecl, StoragePointerDecl } from '@fetchproxy/protocol';
import type { Profile } from './profiles.js';

export interface DerivedServerOpts {
  serverName: string;
  version: string;
  domains: string[];
  capabilities: Capability[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: CaptureHeaderDecl[];
  indexedDbScopes: IndexedDbScopeDecl[];
  localStoragePointers: StoragePointerDecl[];
  sessionStoragePointers: StoragePointerDecl[];
}

/**
 * Derive the FetchproxyServer opts for a profile.
 *
 * MUST stay in lockstep with `bootstrap()`'s derivation
 * (packages/bootstrap/src/index.ts, "capabilities" block): extension
 * trust is keyed to (identity, domains, capabilities), so every fpx
 * verb — and the `session` verb, which goes through bootstrap() itself
 * — has to send an identical hello or the user gets re-pair prompts
 * when alternating verbs. Same push order, same pointer auto-add, and
 * the same `localStoragePointers`/`sessionStoragePointers` mapping
 * (outputKey is dropped, storageKey → `key`) so the hello — not just
 * the capability list and raw key sets — is byte-for-byte identical.
 */
export function serverOptsFor(profileName: string, p: Profile, version: string): DerivedServerOpts {
  const capabilities: Capability[] = ['fetch'];
  if (p.cookies.length > 0) capabilities.push('read_cookies');
  if (p.localStorage.length > 0 || p.localStoragePointers.length > 0) {
    capabilities.push('read_local_storage');
  }
  if (p.sessionStorage.length > 0 || p.sessionStoragePointers.length > 0) {
    capabilities.push('read_session_storage');
  }
  if (p.captureHeaders.length > 0) capabilities.push('capture_request_header');
  if (p.indexedDb.length > 0) capabilities.push('read_indexed_db');

  const localStorageKeys = new Set(p.localStorage);
  for (const ptr of p.localStoragePointers) localStorageKeys.add(ptr.storageKey);
  const sessionStorageKeys = new Set(p.sessionStorage);
  for (const ptr of p.sessionStoragePointers) sessionStorageKeys.add(ptr.storageKey);

  return {
    serverName: `fpx-${profileName}`,
    version,
    domains: [...p.domains],
    capabilities,
    cookieKeys: [...p.cookies],
    localStorageKeys: [...localStorageKeys],
    sessionStorageKeys: [...sessionStorageKeys],
    captureHeaders: p.captureHeaders.map((d) => ({ ...d })),
    indexedDbScopes: p.indexedDb.map((d) => ({ ...d, keys: [...d.keys] })),
    // Mirror bootstrap's mapping exactly: outputKey is bootstrap-local
    // (it only keys the per-call `pointers` map bootstrap passes to
    // readLocalStorage/readSessionStorage), so it's dropped here too —
    // the hello only ever carries `key` + `jsonPointer`.
    localStoragePointers: p.localStoragePointers.map((ptr) => ({
      key: ptr.storageKey,
      jsonPointer: ptr.jsonPointer,
    })),
    sessionStoragePointers: p.sessionStoragePointers.map((ptr) => ({
      key: ptr.storageKey,
      jsonPointer: ptr.jsonPointer,
    })),
  };
}
