import { describe, it, expect } from 'vitest';
import { scopeHash, intersectScope, isScopeSubset, type Scope } from './scope.js';

const base = (): Scope => ({
  capabilities: ['fetch', 'read_cookies'], cookieKeys: ['sid', 'cf'],
  localStorageKeys: [], sessionStorageKeys: [], captureHeaders: [],
  indexedDbScopes: [], domSelectors: [], localStoragePointers: [], sessionStoragePointers: [],
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

describe('captureHeaders scope (host/path/headerName)', () => {
  it('scopeHash treats omitted path as /*', async () => {
    const omitted: Scope = {
      ...base(),
      captureHeaders: [{ host: 'musescore.com', headerName: 'cookie' }],
    };
    const explicit: Scope = {
      ...base(),
      captureHeaders: [{ host: 'musescore.com', path: '/*', headerName: 'cookie' }],
    };
    expect(await scopeHash(omitted)).toBe(await scopeHash(explicit));
  });

  it('scopeHash differs when host differs', async () => {
    const a: Scope = {
      ...base(),
      captureHeaders: [{ host: 'musescore.com', headerName: 'cookie' }],
    };
    const b: Scope = {
      ...base(),
      captureHeaders: [{ host: 'api.musescore.com', headerName: 'cookie' }],
    };
    expect(await scopeHash(a)).not.toBe(await scopeHash(b));
  });

  it('isScopeSubset true when declared captureHeaders ⊆ approved (omitted ≡ /*)', () => {
    const approved: Scope = {
      ...base(),
      captureHeaders: [{ host: 'musescore.com', path: '/*', headerName: 'cookie' }],
    };
    const declared: Scope = {
      ...base(),
      captureHeaders: [{ host: 'musescore.com', headerName: 'cookie' }],
    };
    expect(isScopeSubset(declared, approved)).toBe(true);
  });

  it('isScopeSubset false when declared captureHeaders host escapes approved', () => {
    const approved: Scope = {
      ...base(),
      captureHeaders: [{ host: 'musescore.com', headerName: 'cookie' }],
    };
    const declared: Scope = {
      ...base(),
      captureHeaders: [{ host: 'evil.com', headerName: 'cookie' }],
    };
    expect(isScopeSubset(declared, approved)).toBe(false);
  });

  it('intersect drops captureHeaders not in approved', () => {
    const approved: Scope = {
      ...base(),
      captureHeaders: [{ host: 'musescore.com', headerName: 'cookie' }],
    };
    const declared: Scope = {
      ...base(),
      captureHeaders: [
        { host: 'musescore.com', headerName: 'cookie' },
        { host: 'musescore.com', headerName: 'user-agent' },
      ],
    };
    const kept = intersectScope(approved, declared).captureHeaders;
    expect(kept).toEqual([{ host: 'musescore.com', headerName: 'cookie' }]);
  });
});

describe('domSelectors scope (name/selector/attribute)', () => {
  it('scopeHash treats omitted attribute as empty', async () => {
    const omitted: Scope = {
      ...base(),
      domSelectors: [{ name: 'title', selector: 'h1.title' }],
    };
    const explicit: Scope = {
      ...base(),
      domSelectors: [{ name: 'title', selector: 'h1.title', attribute: '' }],
    };
    expect(await scopeHash(omitted)).toBe(await scopeHash(explicit));
  });

  it('scopeHash is order-independent for domSelectors', async () => {
    const a: Scope = {
      ...base(),
      domSelectors: [
        { name: 'title', selector: 'h1' },
        { name: 'csrf', selector: 'meta[name=csrf]', attribute: 'content' },
      ],
    };
    const b: Scope = {
      ...base(),
      domSelectors: [
        { name: 'csrf', selector: 'meta[name=csrf]', attribute: 'content' },
        { name: 'title', selector: 'h1' },
      ],
    };
    expect(await scopeHash(a)).toBe(await scopeHash(b));
  });

  it('scopeHash differs when a selector differs', async () => {
    const a: Scope = { ...base(), domSelectors: [{ name: 'title', selector: 'h1' }] };
    const b: Scope = { ...base(), domSelectors: [{ name: 'title', selector: 'h2' }] };
    expect(await scopeHash(a)).not.toBe(await scopeHash(b));
  });

  it('scopeHash differs when the attribute differs', async () => {
    const a: Scope = { ...base(), domSelectors: [{ name: 'x', selector: 'a', attribute: 'href' }] };
    const b: Scope = { ...base(), domSelectors: [{ name: 'x', selector: 'a', attribute: 'title' }] };
    expect(await scopeHash(a)).not.toBe(await scopeHash(b));
  });

  it('isScopeSubset true when declared domSelectors ⊆ approved (omitted ≡ empty attr)', () => {
    const approved: Scope = {
      ...base(),
      domSelectors: [{ name: 'title', selector: 'h1', attribute: '' }],
    };
    const declared: Scope = {
      ...base(),
      domSelectors: [{ name: 'title', selector: 'h1' }],
    };
    expect(isScopeSubset(declared, approved)).toBe(true);
  });

  it('isScopeSubset false when declared domSelectors escape approved', () => {
    const approved: Scope = {
      ...base(),
      domSelectors: [{ name: 'title', selector: 'h1' }],
    };
    const declared: Scope = {
      ...base(),
      domSelectors: [{ name: 'title', selector: 'h1' }, { name: 'evil', selector: 'input#pw', attribute: 'value' }],
    };
    expect(isScopeSubset(declared, approved)).toBe(false);
  });

  it('intersect drops domSelectors not in approved', () => {
    const approved: Scope = {
      ...base(),
      domSelectors: [{ name: 'title', selector: 'h1' }],
    };
    const declared: Scope = {
      ...base(),
      domSelectors: [
        { name: 'title', selector: 'h1' },
        { name: 'csrf', selector: 'meta', attribute: 'content' },
      ],
    };
    const kept = intersectScope(approved, declared).domSelectors;
    expect(kept).toEqual([{ name: 'title', selector: 'h1' }]);
  });
});
