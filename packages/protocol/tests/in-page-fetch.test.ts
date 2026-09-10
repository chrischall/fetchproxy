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

/**
 * `FetchInit.credentials` (#324) — a closed set, not merely "a string".
 *
 * The value is handed to `fetch`, and the isolated world passes it through as
 * given. `same-origin` would silently drop the page's cookies on a
 * cross-origin call and present as an unexplained failure; anything else is a
 * TypeError inside the content script. Both are worse than a refused frame.
 */
describe('FetchInit.credentials validation', () => {
  const withCreds = (credentials: unknown) => ({
    ...base,
    init: { ...base.init, credentials },
  });

  it('accepts a fetch with no credentials — the default, unchanged senders', () => {
    const f = validateInnerFrame(base) as typeof base;
    expect(f.init).not.toHaveProperty('credentials');
  });

  it("accepts 'include' and 'omit'", () => {
    for (const v of ['include', 'omit']) {
      const f = validateInnerFrame(withCreds(v)) as { init: { credentials: string } };
      expect(f.init.credentials).toBe(v);
    }
  });

  // The dangerous one: a real fetch value that quietly changes behaviour.
  it("refuses 'same-origin'", () => {
    expect(() => validateInnerFrame(withCreds('same-origin'))).toThrow(ProtocolError);
  });

  it('refuses other types and junk', () => {
    for (const v of [true, 1, null, {}, [], 'INCLUDE', '']) {
      expect(() => validateInnerFrame(withCreds(v)), `accepted ${JSON.stringify(v)}`).toThrow(
        ProtocolError,
      );
    }
  });
});
