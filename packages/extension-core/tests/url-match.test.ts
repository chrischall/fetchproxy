import { describe, it, expect } from 'vitest';
import { isUrlAllowedForDomain, isTabUrlMatch } from '../src/lib/url-match.js';

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
