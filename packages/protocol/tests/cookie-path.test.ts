import { describe, it, expect } from 'vitest';
import { validateInnerFrame, ProtocolError } from '../src/index.js';

/**
 * `read_cookies` carries an optional cookie `path` (#198). It is a separate
 * field rather than part of `origin` because `assertHttpsOriginOnly` refuses a
 * path there on purpose — the origin decides WHICH HOST may be read, and
 * nothing in a path should be able to influence that.
 *
 * Which means this field needs its own guard: it feeds the URL handed to
 * `chrome.cookies.get`, so anything that could re-point that URL at another
 * host has to be refused here rather than trusted from the MCP side.
 */
const frame = (init: Record<string, unknown>) => ({
  type: 'request',
  id: 1,
  op: 'read_cookies',
  init,
});

describe('read_cookies init.path', () => {
  it('accepts an absolute path', () => {
    expect(() =>
      validateInnerFrame(frame({ origin: 'https://600.ncsis.gov', keys: ['JSESSIONID'], path: '/campus' })),
    ).not.toThrow();
  });

  it('accepts init with no path at all (unchanged shape)', () => {
    expect(() =>
      validateInnerFrame(frame({ origin: 'https://x.com', keys: ['a'] })),
    ).not.toThrow();
  });

  it.each([
    ['relative', 'campus'],
    ['protocol-relative', '//evil.example.com/'],
    ['absolute URL', 'https://evil.example.com/'],
    ['with query', '/campus?x=1'],
    ['with fragment', '/campus#f'],
    ['backslash', '/campus\\..\\x'],
  ])('rejects a %s path', (_label, path) => {
    expect(() =>
      validateInnerFrame(frame({ origin: 'https://x.com', keys: ['a'], path })),
    ).toThrow(ProtocolError);
  });

  it('still rejects a path smuggled into origin', () => {
    expect(() =>
      validateInnerFrame(frame({ origin: 'https://x.com/campus', keys: ['a'] })),
    ).toThrow(/bare origin/);
  });
});
