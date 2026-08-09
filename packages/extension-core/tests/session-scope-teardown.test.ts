import { describe, it, expect } from 'vitest';
import {
  mcpDomains,
  mcpCapabilities,
  mcpCookieKeys,
  mcpLocalStorageKeys,
  mcpSessionStorageKeys,
  mcpCaptureHeaders,
  mcpIndexedDbScopes,
  mcpDomSelectors,
  mcpGraphqlOps,
  mcpLocalStoragePointers,
  mcpSessionStoragePointers,
  mcpIdentityHash,
  clearAllSessionScopes,
} from '../src/background/session-scope.js';

// Every per-mcpId scope table. A map that survives a WS teardown is a
// privilege leak (the next connection inherits the previous session's
// grant), so this list is deliberately exhaustive — adding a thirteenth
// map without adding it to `clearAllSessionScopes` must fail here.
const ALL_SCOPE_MAPS: [string, Map<string, unknown>][] = [
  ['mcpDomains', mcpDomains],
  ['mcpCapabilities', mcpCapabilities],
  ['mcpCookieKeys', mcpCookieKeys],
  ['mcpLocalStorageKeys', mcpLocalStorageKeys],
  ['mcpSessionStorageKeys', mcpSessionStorageKeys],
  ['mcpCaptureHeaders', mcpCaptureHeaders],
  ['mcpIndexedDbScopes', mcpIndexedDbScopes],
  ['mcpDomSelectors', mcpDomSelectors],
  ['mcpGraphqlOps', mcpGraphqlOps],
  ['mcpLocalStoragePointers', mcpLocalStoragePointers],
  ['mcpSessionStoragePointers', mcpSessionStoragePointers],
  ['mcpIdentityHash', mcpIdentityHash],
];

describe('clearAllSessionScopes', () => {
  it('empties every per-mcpId scope table', () => {
    for (const [, map] of ALL_SCOPE_MAPS) {
      map.set('musescore-mcp:0.5.0:aabb0001', [] as unknown);
    }
    for (const [name, map] of ALL_SCOPE_MAPS) {
      expect(map.size, `${name} was not seeded`).toBe(1);
    }

    clearAllSessionScopes();

    for (const [name, map] of ALL_SCOPE_MAPS) {
      expect(map.size, `${name} survived teardown`).toBe(0);
    }
  });

  it('covers all twelve declared scope tables', () => {
    expect(ALL_SCOPE_MAPS).toHaveLength(12);
  });
});
