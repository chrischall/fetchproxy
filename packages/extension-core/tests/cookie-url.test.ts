import { describe, it, expect } from 'vitest';
import { cookieUrlFor } from '../src/index.js';

/**
 * The URL handed to `chrome.cookies.get` decides whether a path-scoped cookie
 * is visible at all: Chrome matches the cookie's `Path` attribute against this
 * URL's path, so `Path=/campus` is invisible at the bare origin. That miss is
 * silent — the read just returns nothing, which is indistinguishable from the
 * user being signed out, and cost real time to diagnose. (#198)
 */
describe('cookieUrlFor', () => {
  it('appends the path so Path-scoped cookies match', () => {
    expect(cookieUrlFor('https://600.ncsis.gov', '/campus')).toBe(
      'https://600.ncsis.gov/campus',
    );
  });

  it('returns the bare origin when no path is given', () => {
    expect(cookieUrlFor('https://www.signupgenius.com')).toBe('https://www.signupgenius.com');
  });

  it('treats an empty path as no path', () => {
    expect(cookieUrlFor('https://x.com', '')).toBe('https://x.com');
  });

  it('preserves a multi-segment path', () => {
    expect(cookieUrlFor('https://x.com', '/a/b')).toBe('https://x.com/a/b');
  });
});
