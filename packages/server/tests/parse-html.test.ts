// Tests for the SSR-HTML / URL parsing helpers in `@fetchproxy/server`.
//
// These are pure, dependency-free string utilities hoisted from the
// SSR-scraping portal-MCP cohort, where each consumer re-implemented
// the same primitives:
//
//   * `extractBalancedObject` / `extractGlobalAssign` — pull a
//     `window.<X> = {…}` (or `var X = {…}`) JSON object out of an inline
//     bootstrap script via string-aware balanced-brace walking.
//     (Generalized from compass-mcp's `src/page-state.ts`.)
//   * `extractImgTags` — regex-scrape `<img>` src/alt pairs.
//     (From homes-mcp's `src/tools/photos.ts`.)
//   * `lastPathSegment` — strip scheme/host + `?#` and return the final
//     non-empty path segment (the canonical opaque-id extractor every
//     portal MCP hand-rolls).
//
// The brace walker is the one with real edge cases (braces inside
// quoted strings, escaped quotes, nesting, a trailing `;`), so it gets
// the most coverage.
import { describe, it, expect } from 'vitest';
import {
  extractBalancedObject,
  extractGlobalAssign,
  extractImgTags,
  lastPathSegment,
} from '../src/index.js';

describe('extractBalancedObject', () => {
  it('returns null when the start index is not a `{`', () => {
    expect(extractBalancedObject('  {"a":1}', 0)).toBeNull();
  });

  it('parses a flat object starting at the brace', () => {
    expect(extractBalancedObject('{"a":1,"b":2}', 0)).toEqual({ a: 1, b: 2 });
  });

  it('parses nested objects, stopping at the matching close brace', () => {
    const text = '{"a":{"b":{"c":3}},"d":4}';
    expect(extractBalancedObject(text, 0)).toEqual({ a: { b: { c: 3 } }, d: 4 });
  });

  it('ignores braces inside quoted strings', () => {
    // The `{` / `}` inside the string value must not move the depth counter.
    const text = '{"note":"a } b { c","n":1}';
    expect(extractBalancedObject(text, 0)).toEqual({ note: 'a } b { c', n: 1 });
  });

  it('handles escaped quotes inside strings', () => {
    // The `\"` must not end the string early, so the trailing `}` inside
    // the value stays inside the string and depth is unaffected.
    const text = '{"q":"she said \\"hi}\\" loudly"}';
    expect(extractBalancedObject(text, 0)).toEqual({ q: 'she said "hi}" loudly' });
  });

  it('handles an escaped backslash before a quote', () => {
    // `\\` is a literal backslash; the following `"` then DOES close the
    // string. (Regression guard: a naive `\\`-skip that swallows the
    // closing quote would over-run.)
    const text = '{"path":"C:\\\\dir\\\\","n":2}';
    expect(extractBalancedObject(text, 0)).toEqual({ path: 'C:\\dir\\', n: 2 });
  });

  it('stops at the first balanced close and ignores a trailing `;`', () => {
    // Inline-script assignments end in `…};` — the walker must return the
    // object at its matching `}` and not be confused by trailing chars.
    const text = '{"a":1};\nwindow.other = 2;';
    expect(extractBalancedObject(text, 0)).toEqual({ a: 1 });
  });

  it('starts from an arbitrary offset, not just 0', () => {
    const text = 'prefix junk {"a":1} suffix';
    const start = text.indexOf('{');
    expect(extractBalancedObject(text, start)).toEqual({ a: 1 });
  });

  it('returns null on an unbalanced (never-closed) object', () => {
    expect(extractBalancedObject('{"a":{"b":1}', 0)).toBeNull();
  });

  it('returns null when the balanced slice is not valid JSON', () => {
    // Balanced braces, but JS-literal (single-quoted / unquoted keys) the
    // way some inline scripts emit — not strict JSON, so JSON.parse fails.
    expect(extractBalancedObject("{a:1,'b':2}", 0)).toBeNull();
  });
});

describe('extractGlobalAssign', () => {
  it('pulls a `window.<X> = {…}` object out of inline-script HTML', () => {
    const html = '<script>window.__DATA__ = {"hello":"world","n":42};</script>';
    expect(extractGlobalAssign(html, '__DATA__')).toEqual({ hello: 'world', n: 42 });
  });

  it('pulls a `var X = {…}` declaration', () => {
    const html = '<script>var APP = {"ready":true};</script>';
    expect(extractGlobalAssign(html, 'APP')).toEqual({ ready: true });
  });

  it('pulls a `global.<X> = {…}` assignment', () => {
    const html = '<script>global.uc = {"a":1};</script>';
    expect(extractGlobalAssign(html, 'uc')).toEqual({ a: 1 });
  });

  it('tolerates arbitrary whitespace around the `=`', () => {
    const html = '<script>window.X   =\n   {"a":1};</script>';
    expect(extractGlobalAssign(html, 'X')).toEqual({ a: 1 });
  });

  it('returns null when the variable is absent', () => {
    expect(extractGlobalAssign('<script>window.other = {};</script>', 'missing')).toBeNull();
  });

  it('skips a same-named assignment whose object is unparseable and finds the next valid one', () => {
    // First `window.X` is JS-literal garbage (single quotes) → unparseable;
    // the walker must keep scanning and return the second, valid one.
    const html =
      "<script>window.X = {bad:'json'};</script>" + '<script>window.X = {"good":true};</script>';
    expect(extractGlobalAssign(html, 'X')).toEqual({ good: true });
  });

  it('does not match a variable whose name is a suffix of the target', () => {
    // Looking for `uc` must NOT match `myuc`. The boundary guard prevents
    // `window.myuc = {…}` from satisfying a search for `uc`.
    const html = '<script>window.myuc = {"a":1};</script>';
    expect(extractGlobalAssign(html, 'uc')).toBeNull();
  });

  it('escapes regex metacharacters in the variable name', () => {
    // `$` is a regex metachar AND a legal JS identifier char — the name
    // must be treated literally, not as a regex.
    const html = '<script>window.__INITIAL_DATA__ = {"k":1};</script>';
    expect(extractGlobalAssign(html, '__INITIAL_DATA__')).toEqual({ k: 1 });
  });

  it('handles braces-in-strings within the assigned object', () => {
    const html = '<script>window.X = {"tpl":"a {b} c","n":1};</script>';
    expect(extractGlobalAssign(html, 'X')).toEqual({ tpl: 'a {b} c', n: 1 });
  });
});

describe('extractImgTags', () => {
  it('extracts src/alt pairs from `<img>` tags', () => {
    const html =
      '<img src="https://cdn/a.jpg" alt="Front">' + '<img src="https://cdn/b.jpg" alt="Kitchen">';
    expect(extractImgTags(html)).toEqual([
      { src: 'https://cdn/a.jpg', alt: 'Front' },
      { src: 'https://cdn/b.jpg', alt: 'Kitchen' },
    ]);
  });

  it('omits alt when the attribute is absent', () => {
    expect(extractImgTags('<img src="/x.png">')).toEqual([{ src: '/x.png' }]);
  });

  it('keeps an empty-string alt (present but blank)', () => {
    // `alt=""` is a real value (decorative image) — distinct from absent.
    expect(extractImgTags('<img alt="" src="/x.png">')).toEqual([{ src: '/x.png', alt: '' }]);
  });

  it('is attribute-order agnostic (alt before src)', () => {
    expect(extractImgTags('<img alt="Yard" src="/y.png">')).toEqual([
      { src: '/y.png', alt: 'Yard' },
    ]);
  });

  it('handles single-quoted attribute values', () => {
    expect(extractImgTags("<img src='/q.png' alt='Quote'>")).toEqual([
      { src: '/q.png', alt: 'Quote' },
    ]);
  });

  it('skips `<img>` tags with no src', () => {
    expect(extractImgTags('<img alt="no source"><img src="/ok.png">')).toEqual([
      { src: '/ok.png' },
    ]);
  });

  it('is case-insensitive on the tag and attribute names', () => {
    expect(extractImgTags('<IMG SRC="/c.png" ALT="Cap">')).toEqual([{ src: '/c.png', alt: 'Cap' }]);
  });

  it('returns an empty array when there are no images', () => {
    expect(extractImgTags('<div>no images here</div>')).toEqual([]);
  });

  it('handles self-closing and multiline img tags', () => {
    const html = '<img\n  src="/m.png"\n  alt="Multi"\n/>';
    expect(extractImgTags(html)).toEqual([{ src: '/m.png', alt: 'Multi' }]);
  });
});

describe('lastPathSegment', () => {
  it('returns the final path segment of a full URL', () => {
    expect(lastPathSegment('https://www.example.com/property/some-slug/abc123')).toBe('abc123');
  });

  it('strips a trailing slash and returns the preceding segment', () => {
    expect(lastPathSegment('https://www.example.com/homedetails/123_zpid/')).toBe('123_zpid');
  });

  it('strips a query string before taking the segment', () => {
    expect(lastPathSegment('https://x.com/a/b/c?foo=bar&baz=1')).toBe('c');
  });

  it('strips a hash fragment before taking the segment', () => {
    // The canonical id-extractor must drop `#realestatelisting`-style
    // fragments that some portals append to @id values.
    expect(lastPathSegment('https://x.com/a/b/c/#realestatelisting')).toBe('c');
  });

  it('strips both query and fragment', () => {
    expect(lastPathSegment('https://x.com/a/b/c?q=1#frag')).toBe('c');
  });

  it('works on a bare path with no scheme/host', () => {
    expect(lastPathSegment('/property/slug/xyz789/')).toBe('xyz789');
  });

  it('works on a single bare segment', () => {
    expect(lastPathSegment('justanid')).toBe('justanid');
  });

  it('returns an empty string for a host-only URL with no path', () => {
    expect(lastPathSegment('https://www.example.com')).toBe('');
  });

  it('returns an empty string for a root-only URL', () => {
    expect(lastPathSegment('https://www.example.com/')).toBe('');
  });

  it('returns an empty string for an empty input', () => {
    expect(lastPathSegment('')).toBe('');
  });

  it('collapses repeated slashes (empty segments are skipped)', () => {
    expect(lastPathSegment('https://x.com/a//b//')).toBe('b');
  });
});
