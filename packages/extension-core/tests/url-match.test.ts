import { describe, it, expect } from 'vitest';
import {
  isUrlAllowedForDomain,
  isUrlAllowedForAnyDomain,
  isTabUrlMatch,
} from '../src/lib/url-match.js';

describe('isUrlAllowedForDomain', () => {
  it('allows exact domain', () => {
    expect(isUrlAllowedForDomain('https://opentable.com/x', 'opentable.com')).toBe(true);
  });

  it('allows subdomain', () => {
    expect(isUrlAllowedForDomain('https://www.opentable.com/x', 'opentable.com')).toBe(true);
    expect(isUrlAllowedForDomain('https://api.opentable.com/x', 'opentable.com')).toBe(true);
  });

  it('rejects different domain', () => {
    expect(isUrlAllowedForDomain('https://yourbank.com/x', 'opentable.com')).toBe(false);
  });

  it('rejects suffix-attack domain', () => {
    // evilopentable.com should NOT match opentable.com
    expect(isUrlAllowedForDomain('https://evilopentable.com/x', 'opentable.com')).toBe(false);
  });

  it('rejects non-http(s) schemes', () => {
    expect(isUrlAllowedForDomain('javascript:alert(1)', 'opentable.com')).toBe(false);
    expect(isUrlAllowedForDomain('file:///etc/passwd', 'opentable.com')).toBe(false);
    expect(isUrlAllowedForDomain('data:text/html,<script>1</script>', 'opentable.com')).toBe(false);
  });

  it('rejects malformed URLs', () => {
    expect(isUrlAllowedForDomain('not a url', 'opentable.com')).toBe(false);
  });
});

describe('isUrlAllowedForAnyDomain', () => {
  it('allows a URL on any of the declared domains', () => {
    expect(
      isUrlAllowedForAnyDomain('https://opentable.com/x', ['opentable.com', 'resy.com']),
    ).toBe(true);
    expect(
      isUrlAllowedForAnyDomain('https://resy.com/x', ['opentable.com', 'resy.com']),
    ).toBe(true);
  });

  it('allows a subdomain of any declared domain', () => {
    expect(
      isUrlAllowedForAnyDomain('https://api.resy.com/x', ['opentable.com', 'resy.com']),
    ).toBe(true);
  });

  it('rejects a URL outside the declared domain set', () => {
    expect(
      isUrlAllowedForAnyDomain('https://evil.com/x', ['opentable.com', 'resy.com']),
    ).toBe(false);
  });

  it('rejects suffix-attack against any declared domain', () => {
    expect(
      isUrlAllowedForAnyDomain('https://evilopentable.com/x', ['opentable.com', 'resy.com']),
    ).toBe(false);
  });

  it('returns false for empty domain set', () => {
    expect(isUrlAllowedForAnyDomain('https://opentable.com/x', [])).toBe(false);
  });

  it('rejects non-http(s) schemes for every domain in the set', () => {
    expect(
      isUrlAllowedForAnyDomain('javascript:alert(1)', ['opentable.com', 'resy.com']),
    ).toBe(false);
  });
});

describe('isTabUrlMatch', () => {
  it('prefix-matches against the tab URL', () => {
    expect(isTabUrlMatch('https://www.opentable.com/r/x?a=1', 'https://www.opentable.com/')).toBe(true);
  });

  it('does not match a different domain', () => {
    expect(isTabUrlMatch('https://evil.com/', 'https://www.opentable.com/')).toBe(false);
  });

  it('handles edge: exact equality', () => {
    expect(isTabUrlMatch('https://www.opentable.com/', 'https://www.opentable.com/')).toBe(true);
  });
});

// 0.3.0 regression: Canvas serves arbitrarily-deep subdomains
// (a.b.c.instructure.com); confirm the existing match logic handles them.
describe('arbitrary subdomain depth (0.3.0 regression)', () => {
  it('matches arbitrary-depth subdomains against the declared root', () => {
    expect(isUrlAllowedForDomain('https://a.b.c.instructure.com/x', 'instructure.com')).toBe(true);
    expect(
      isUrlAllowedForAnyDomain('https://a.b.c.instructure.com/x', ['instructure.com']),
    ).toBe(true);
  });

  it('still matches the bare root domain', () => {
    expect(isUrlAllowedForDomain('https://instructure.com/x', 'instructure.com')).toBe(true);
  });

  it('does not match an unrelated host', () => {
    expect(isUrlAllowedForDomain('https://a.b.c.othersite.com/x', 'instructure.com')).toBe(false);
  });

  it('does not match a suffix collision', () => {
    expect(isUrlAllowedForDomain('https://x.evilinstructure.com/x', 'instructure.com')).toBe(false);
  });
});
