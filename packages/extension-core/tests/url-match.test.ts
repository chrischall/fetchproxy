import { describe, it, expect } from 'vitest';
import {
  isUrlAllowedForDomain,
  isUrlAllowedForAnyDomain,
  isTabUrlMatch,
  isTabUrlOnOrigin,
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

// 2.2.1: `www.` is optional on BOTH sides.
//
// Measured against the live fleet (2026-08-30): etix-mcp declares
// `defaultSubdomain: 'www'`, so its relay tab defaults to
// `https://www.etix.com/` — but `etix.com` does NOT redirect to `www`
// (302 -> https://etix.com/ticket), so a user browsing normally sits on the
// apex and the strict prefix never matched. The healthcheck reported
// `no_tab: no tab matching https://www.etix.com/` while the extension itself
// was healthy (it answered in 330ms).
//
// Host-or-subdomain matching does NOT fix this: an apex is a PARENT of `www`,
// not a subdomain of it, so `isUrlAllowedForDomain('https://etix.com/',
// 'www.etix.com')` is correctly false. Only `www` equivalence closes it.
describe('www is optional on both sides (2.2.1)', () => {
  it('matches an apex tab against a www prefix', () => {
    expect(isTabUrlMatch('https://etix.com/ticket', 'https://www.etix.com/')).toBe(true);
  });

  it('matches a www tab against an apex prefix', () => {
    expect(isTabUrlMatch('https://www.etix.com/ticket', 'https://etix.com/')).toBe(true);
  });

  it('still pins a deeper path', () => {
    expect(isTabUrlMatch('https://etix.com/other', 'https://www.etix.com/ticket')).toBe(false);
    expect(isTabUrlMatch('https://etix.com/ticket/v/1', 'https://www.etix.com/ticket')).toBe(true);
  });

  it('does not treat www as a wildcard for other subdomains', () => {
    expect(isTabUrlMatch('https://api.etix.com/x', 'https://www.etix.com/')).toBe(false);
    expect(isTabUrlMatch('https://wwwevil.com/', 'https://www.etix.com/')).toBe(false);
  });

  it('does not match an unrelated host that merely starts with the same letters', () => {
    expect(isTabUrlMatch('https://www.etix.com.evil.com/', 'https://www.etix.com/')).toBe(false);
  });

  it('keeps scheme significant', () => {
    expect(isTabUrlMatch('http://etix.com/ticket', 'https://www.etix.com/')).toBe(false);
  });

  it('leaves a malformed prefix falling back to plain prefix semantics', () => {
    expect(isTabUrlMatch('not a url', 'not a url')).toBe(true);
    expect(isTabUrlMatch('https://etix.com/', 'not a url')).toBe(false);
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

// 0.4.1: multi-vendor MCPs declare an apex `storageDomain` and the
// extension must accept tabs on any subdomain of that apex. This is
// the host-or-subdomain variant of `isTabUrlMatch` — used for tab
// lookup when the MCP can't predict the exact subdomain at build
// time (HoneyBook vendor portals, Canvas school subdomains, etc.).
describe('isTabUrlOnOrigin', () => {
  it('matches a tab on the exact origin host', () => {
    expect(isTabUrlOnOrigin('https://hbportal.co/', 'https://hbportal.co')).toBe(true);
    expect(isTabUrlOnOrigin('https://hbportal.co/app/x', 'https://hbportal.co')).toBe(true);
  });

  it('matches a tab on any subdomain of the origin host', () => {
    expect(
      isTabUrlOnOrigin(
        'https://thesilkveileventsbyivy.hbportal.co/app/event/x',
        'https://hbportal.co',
      ),
    ).toBe(true);
    expect(
      isTabUrlOnOrigin('https://a.b.c.instructure.com/x', 'https://instructure.com'),
    ).toBe(true);
  });

  it('honors an explicit-subdomain target — still matches that subdomain', () => {
    expect(isTabUrlOnOrigin('https://app.example.com/x', 'https://app.example.com')).toBe(true);
    // … and sub-subdomains of it (rare, but consistent semantics).
    expect(isTabUrlOnOrigin('https://eu.app.example.com/x', 'https://app.example.com')).toBe(true);
  });

  it('rejects suffix collisions', () => {
    expect(isTabUrlOnOrigin('https://evilhbportal.co/', 'https://hbportal.co')).toBe(false);
    expect(isTabUrlOnOrigin('https://x.evilhbportal.co/', 'https://hbportal.co')).toBe(false);
  });

  it('rejects unrelated hosts', () => {
    expect(isTabUrlOnOrigin('https://example.com/x', 'https://hbportal.co')).toBe(false);
  });

  it('rejects non-http(s) and malformed origins', () => {
    expect(isTabUrlOnOrigin('https://hbportal.co/', 'not-a-url')).toBe(false);
    expect(isTabUrlOnOrigin('javascript:alert(1)', 'https://hbportal.co')).toBe(false);
    expect(isTabUrlOnOrigin('file:///etc/passwd', 'https://hbportal.co')).toBe(false);
  });
});
