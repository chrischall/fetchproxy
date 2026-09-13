import { describe, it, expect } from 'vitest';
import { isPublicSuffix } from '@fetchproxy/protocol';
import { FetchproxyServer } from '../src/index.js';

/**
 * #365 — the public-suffix refusal used to live only in `validateHello`, which
 * runs at the FAR end: `background/socket.ts` wraps `validateFrame` in a
 * try/catch and answers a `ProtocolError` with `console.warn('dropped
 * malformed frame')` into the service worker's own console. So a profile
 * declaring `co.uk` constructed happily, listened happily, and then failed as
 * a bridge that never answers — with the diagnosis in a console nobody
 * running the MCP can read, at the moment somebody was trying to use it.
 *
 * The declaration is made in the constructor, so that is where it is judged.
 */

const base = {
  serverName: 'test-mcp',
  version: '0.0.1',
};

describe('FetchproxyServer constructor — opts.domains public-suffix refusal', () => {
  it('refuses a multi-label public suffix and names it', () => {
    expect(() => new FetchproxyServer({ ...base, domains: ['co.uk'] })).toThrow(
      /"co\.uk"/,
    );
  });

  it('refuses a bare TLD', () => {
    expect(() => new FetchproxyServer({ ...base, domains: ['com'] })).toThrow(
      /"com"/,
    );
  });

  it('refuses a listed hosting suffix that is not at the head of the list', () => {
    // The offender is the SECOND entry: a loop that only judged domains[0]
    // would let this through, and one plausible entry beside a suffix is the
    // shape a real profile has.
    expect(
      () =>
        new FetchproxyServer({
          ...base,
          domains: ['example.com', 'github.io'],
        }),
    ).toThrow(/"github\.io"/);
  });

  it('names the option and says what to declare instead', () => {
    let message = '';
    try {
      new FetchproxyServer({ ...base, domains: ['co.uk'] });
    } catch (e) {
      message = e instanceof Error ? e.message : String(e);
    }
    expect(message).toContain('FetchproxyServer');
    expect(message).toContain('domains');
    expect(message).toContain('example.co.uk');
  });

  it('still constructs for a registrable domain under a public suffix', () => {
    expect(
      () =>
        new FetchproxyServer({
          ...base,
          domains: ['example.co.uk', 'example.com', 'chrischall.github.io'],
        }),
    ).not.toThrow();
  });

  it('agrees with the protocol predicate rather than carrying a second copy', () => {
    // Not a proof of the import, but it fails the moment the two disagree —
    // which is the failure a second implementation of "is this a public
    // suffix" produces.
    const samples = [
      'com',
      'co.uk',
      'github.io',
      'pages.dev',
      'CO.UK',
      'co.uk.',
      'example.com',
      'bbc.co.uk',
      'sub.example.github.io',
    ];
    for (const d of samples) {
      const refused = (() => {
        try {
          new FetchproxyServer({ ...base, domains: [d] });
          return false;
        } catch {
          return true;
        }
      })();
      expect(refused, d).toBe(isPublicSuffix(d));
    }
  });
});
