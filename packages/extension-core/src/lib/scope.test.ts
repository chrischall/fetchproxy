import { describe, it, expect } from 'vitest';
import { scopeHash, intersectScope, isScopeSubset, type Scope } from './scope.js';

const base = (): Scope => ({
  capabilities: ['fetch', 'read_cookies'], cookieKeys: ['sid', 'cf'],
  localStorageKeys: [], sessionStorageKeys: [], captureHeaders: [],
  indexedDbScopes: [], localStoragePointers: [], sessionStoragePointers: [],
});

describe('scopeHash', () => {
  it('is order-independent', async () => {
    const a = base();
    const b: Scope = { ...base(), capabilities: ['read_cookies', 'fetch'], cookieKeys: ['cf', 'sid'] };
    expect(await scopeHash(a)).toBe(await scopeHash(b));
  });
  it('differs when a capability is added', async () => {
    expect(await scopeHash(base())).not.toBe(
      await scopeHash({ ...base(), capabilities: ['fetch', 'read_cookies', 'capture_request_header'] })
    );
  });
});

describe('intersectScope / isScopeSubset', () => {
  it('intersect drops capabilities not in approved', () => {
    const declared: Scope = { ...base(), capabilities: ['fetch', 'read_cookies', 'capture_request_header'] };
    expect(intersectScope(base(), declared).capabilities.sort()).toEqual(['fetch', 'read_cookies']);
  });
  it('isScopeSubset false when declared adds a capability', () => {
    expect(isScopeSubset({ ...base(), capabilities: ['fetch', 'read_cookies', 'capture_request_header'] }, base())).toBe(false);
  });
  it('isScopeSubset true when declared ⊆ approved', () => {
    expect(isScopeSubset({ ...base(), capabilities: ['fetch'] }, base())).toBe(true);
  });
});
