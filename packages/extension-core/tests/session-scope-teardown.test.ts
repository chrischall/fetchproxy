import { describe, it, expect } from 'vitest';
import * as sessionScope from '../src/background/session-scope.js';
import { clearAllSessionScopes } from '../src/background/session-scope.js';

// Every per-mcpId scope table, DERIVED from the module's own exports rather
// than listed by hand. A map that survives a WS teardown is a privilege leak —
// the next connection inherits the previous session's grant — so the guarantee
// this file exists for is "no scope map is ever missed".
//
// A hand-maintained literal cannot make that guarantee, and this file used to
// carry one under a comment claiming it could. It could not: a thirteenth map
// added to session-scope.ts and forgotten in `clearAllSessionScopes` would also
// be forgotten HERE, so the test passed and the leak shipped. Verified before
// changing it — adding an uncleaned `mcpThirteenth` left this suite green at
// 2/2 (fetchproxy#227).
//
// Deriving from the namespace closes that: a new exported Map is picked up with
// no edit to this file, so forgetting `clearAllSessionScopes` is the only way to
// fail, which is exactly the mistake worth catching.
const ALL_SCOPE_MAPS: [string, Map<string, unknown>][] = Object.entries(sessionScope)
  .filter((entry): entry is [string, Map<string, unknown>] => entry[1] instanceof Map)
  .sort(([a], [b]) => a.localeCompare(b));

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

  // A deliberate tripwire, and the reason it survives the switch to a derived
  // list. The test above catches a new scope map that teardown FORGETS; this one
  // fires on any new scope map at all, cleaned or not, so adding one cannot be
  // an incidental edit. Bumping this number is the moment to ask whether the new
  // table also needs seeding, redaction or a popup surface — not just clearing.
  it('has exactly the scope tables it was last reviewed with', () => {
    expect(ALL_SCOPE_MAPS).toHaveLength(12);
  });
});
