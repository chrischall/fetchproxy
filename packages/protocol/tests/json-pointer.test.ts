import { describe, it, expect } from 'vitest';
import {
  evalJsonPointer,
  isValidJsonPointer,
  matchesDeclaredKey,
  undeclaredKeys,
} from '../src/json-pointer.js';

describe('evalJsonPointer', () => {
  const root = {
    HB_AUTH_TOKEN: 'ey...',
    HB_CURR_USER: { company: { company_name: 'Acme Co.' } },
    list: [10, 20, 30],
    'has/slash': 'escaped',
    'has~tilde': 'tilde-escaped',
    nested: { 'with/slash': 'inner' },
    nullish: null,
  };

  it('empty pointer returns root', () => {
    expect(evalJsonPointer(root, '')).toBe(root);
  });

  it('top-level property', () => {
    expect(evalJsonPointer(root, '/HB_AUTH_TOKEN')).toBe('ey...');
  });

  it('nested property', () => {
    expect(evalJsonPointer(root, '/HB_CURR_USER/company/company_name')).toBe('Acme Co.');
  });

  it('array index', () => {
    expect(evalJsonPointer(root, '/list/1')).toBe(20);
  });

  it('out-of-bounds array index returns undefined', () => {
    expect(evalJsonPointer(root, '/list/99')).toBeUndefined();
  });

  it('escape /', () => {
    expect(evalJsonPointer(root, '/has~1slash')).toBe('escaped');
  });

  it('escape ~', () => {
    expect(evalJsonPointer(root, '/has~0tilde')).toBe('tilde-escaped');
  });

  it('nested with / escape', () => {
    expect(evalJsonPointer(root, '/nested/with~1slash')).toBe('inner');
  });

  it('missing top-level path returns undefined', () => {
    expect(evalJsonPointer(root, '/no_such_key')).toBeUndefined();
  });

  it('missing nested path returns undefined', () => {
    expect(evalJsonPointer(root, '/HB_CURR_USER/no_such')).toBeUndefined();
  });

  it('crossing through null returns undefined', () => {
    expect(evalJsonPointer(root, '/nullish/anything')).toBeUndefined();
  });

  it('crossing through primitive returns undefined', () => {
    expect(evalJsonPointer(root, '/HB_AUTH_TOKEN/extra')).toBeUndefined();
  });

  it('invalid pointer (no leading slash) throws', () => {
    expect(() => evalJsonPointer(root, 'no-slash')).toThrow(/JSON pointer/);
  });

  it('non-integer array index returns undefined', () => {
    expect(evalJsonPointer(root, '/list/abc')).toBeUndefined();
  });

  it('leading-zero array index rejected', () => {
    // RFC 6901 requires `0` or `[1-9][0-9]*`. `01` is invalid.
    expect(evalJsonPointer(root, '/list/01')).toBeUndefined();
  });

  it('does not access inherited prototype properties', () => {
    // Object.prototype.toString is inherited, so evaluating `/toString`
    // must not pull it. (hasOwnProperty guard.)
    expect(evalJsonPointer({}, '/toString')).toBeUndefined();
  });
});

describe('isValidJsonPointer', () => {
  it('accepts empty', () => expect(isValidJsonPointer('')).toBe(true));
  it('accepts /foo', () => expect(isValidJsonPointer('/foo')).toBe(true));
  it('accepts nested', () => expect(isValidJsonPointer('/a/b/c')).toBe(true));
  it('accepts ~0 and ~1', () => {
    expect(isValidJsonPointer('/a~0b')).toBe(true);
    expect(isValidJsonPointer('/a~1b')).toBe(true);
  });
  it('rejects no leading slash', () => expect(isValidJsonPointer('foo')).toBe(false));
  it('rejects lone ~', () => expect(isValidJsonPointer('/a~b')).toBe(false));
  it('rejects ~ followed by EOL', () => expect(isValidJsonPointer('/a~')).toBe(false));
});

describe('matchesDeclaredKey (glob)', () => {
  it('exact literal match', () => {
    expect(matchesDeclaredKey('foo', ['foo'])).toBe(true);
  });

  it("doesn't match if literal differs", () => {
    expect(matchesDeclaredKey('foo', ['bar'])).toBe(false);
  });

  it('glob match: trailing * matches the suffix', () => {
    expect(matchesDeclaredKey('feh--12ab', ['feh--*'])).toBe(true);
    expect(matchesDeclaredKey('auth_xyz', ['auth_*'])).toBe(true);
  });

  it("glob doesn't match without any suffix character", () => {
    // `*` requires at least one character after the literal prefix —
    // otherwise the declared literal would have been written without `*`.
    expect(matchesDeclaredKey('feh--', ['feh--*'])).toBe(false);
  });

  it("glob doesn't match unrelated keys", () => {
    expect(matchesDeclaredKey('weirdo', ['auth_*'])).toBe(false);
  });

  it('mixed literal + glob: either kind matches', () => {
    expect(matchesDeclaredKey('hb_user_token', ['hb_user_token', 'feh--*'])).toBe(true);
    expect(matchesDeclaredKey('feh--xxx', ['hb_user_token', 'feh--*'])).toBe(true);
    expect(matchesDeclaredKey('nope', ['hb_user_token', 'feh--*'])).toBe(false);
  });

  it('empty declared list never matches', () => {
    expect(matchesDeclaredKey('anything', [])).toBe(false);
  });
});

describe('undeclaredKeys', () => {
  it('returns keys that match nothing', () => {
    expect(undeclaredKeys(['a', 'b', 'c'], ['a', 'c'])).toEqual(['b']);
  });

  it('respects glob declarations', () => {
    expect(undeclaredKeys(['hb_user_token', 'feh--xxx', 'orphan'], ['hb_user_token', 'feh--*'])).toEqual([
      'orphan',
    ]);
  });

  it('returns [] when all requested are declared', () => {
    expect(undeclaredKeys(['a', 'b'], ['a', 'b', 'c'])).toEqual([]);
  });
});
