import { describe, it, expect } from 'vitest';
import { validateInnerFrame, ProtocolError } from '../src/validate.js';
import { KNOWN_CAPABILITIES } from '../src/frames.js';

/**
 * `fetch_in_page` — the capability that lets a declared fetch run in the
 * page's MAIN world instead of the content script's isolated world.
 *
 * Motivation (opentable.com, verified live): an edge bot-manager accepts a
 * GraphQL *mutation* POST issued by the page and rejects the byte-identical
 * request issued from the isolated world with 403, while GraphQL queries and
 * REST writes pass from either. That blocks every booking write. The escape
 * hatch is per-REQUEST, not per-MCP, so an MCP flags only the handful of
 * operations that need it and everything else keeps the isolated world's
 * tamper isolation.
 */

const base = {
  type: 'request' as const,
  id: 1,
  op: 'fetch' as const,
  init: {
    url: 'https://www.opentable.com/dapi/fe/gql',
    method: 'POST',
    tabUrl: 'https://www.opentable.com/',
  },
};

describe('fetch_in_page capability', () => {
  it('is a known wire capability', () => {
    expect(KNOWN_CAPABILITIES.has('fetch_in_page')).toBe(true);
  });
});

describe('FetchInit.inPage validation', () => {
  it('accepts a fetch with no inPage (the default, isolated world)', () => {
    const f = validateInnerFrame(base) as typeof base;
    expect(f.init).not.toHaveProperty('inPage');
  });

  it('accepts inPage: true', () => {
    const f = validateInnerFrame({
      ...base,
      init: { ...base.init, inPage: true },
    }) as { init: { inPage?: boolean } };
    expect(f.init.inPage).toBe(true);
  });

  it('accepts inPage: false', () => {
    const f = validateInnerFrame({
      ...base,
      init: { ...base.init, inPage: false },
    }) as { init: { inPage?: boolean } };
    expect(f.init.inPage).toBe(false);
  });

  it('rejects a non-boolean inPage rather than coercing it', () => {
    // A truthy string must NOT silently become "run this in the page".
    for (const bad of ['true', 1, {}, null]) {
      expect(() => validateInnerFrame({ ...base, init: { ...base.init, inPage: bad } })).toThrow(
        ProtocolError,
      );
    }
  });
});
