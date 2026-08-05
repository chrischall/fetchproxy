import { describe, it, expect } from 'vitest';
import {
  resolveWriteCookiesRequest,
  cookieSetDetailsFor,
  type ChromeCookie,
} from '../src/background.js';
import type { InnerRequestWriteCookies } from '@fetchproxy/protocol';

/**
 * `write_cookies` is the bridge's first and only write verb. It exists because
 * sites that ROTATE a credential cookie otherwise sign the user out of their
 * own browser — the MCP refreshes, the site issues a new value, and the copy in
 * the cookie jar is dead (chrischall/creditkarma-mcp#119).
 *
 * Being a write, the interesting cases are the refusals and the attribute
 * copying, not the happy path.
 */
const req = (
  cookies: { name: string; value: string }[],
  origin = 'https://www.example.com',
): InnerRequestWriteCookies => ({
  type: 'request',
  id: 1,
  op: 'write_cookies',
  init: { origin, cookies },
});

const DOMAINS = ['example.com'];

describe('resolveWriteCookiesRequest', () => {
  it('allows a declared cookie on a declared domain', () => {
    expect(resolveWriteCookiesRequest(req([{ name: 'SESSION', value: 'v' }]), DOMAINS, ['SESSION']))
      .toEqual({ ok: true });
  });

  it('refuses an origin outside the declared domains', () => {
    const r = resolveWriteCookiesRequest(req([{ name: 'SESSION', value: 'v' }], 'https://evil.test'), DOMAINS, ['SESSION']);
    expect(r).toMatchObject({ ok: false });
    expect((r as { error: string }).error).toMatch(/not in domains/);
  });

  it('refuses a cookie the MCP was never trusted to read', () => {
    // The whole containment argument for this verb: a write cannot reach
    // outside the read scope the user already approved.
    const r = resolveWriteCookiesRequest(req([{ name: 'ADMIN', value: 'v' }]), DOMAINS, ['SESSION']);
    expect(r).toMatchObject({ ok: false });
    expect((r as { error: string }).error).toMatch(/not in declared set/);
  });

  it('refuses the whole batch when any one name is undeclared', () => {
    // A rotation applied to some of its cookies is worse than one refused.
    const r = resolveWriteCookiesRequest(
      req([{ name: 'SESSION', value: 'a' }, { name: 'ADMIN', value: 'b' }]),
      DOMAINS,
      ['SESSION'],
    );
    expect(r).toMatchObject({ ok: false });
    expect((r as { error: string }).error).toMatch(/ADMIN/);
  });

  it('refuses everything when nothing is declared', () => {
    expect(resolveWriteCookiesRequest(req([{ name: 'SESSION', value: 'v' }]), DOMAINS, []))
      .toMatchObject({ ok: false });
  });
});

describe('cookieSetDetailsFor', () => {
  const base: ChromeCookie = {
    name: 'SESSION',
    value: 'old',
    domain: '.example.com',
    hostOnly: false,
    path: '/',
    secure: true,
    httpOnly: true,
    sameSite: 'lax',
    expirationDate: 1893456000,
    storeId: '0',
  };
  const decl = { name: 'SESSION', value: 'new' };
  const URL = 'https://www.example.com/';

  it('carries the new value with the original attributes', () => {
    // Anything less and the write creates a second cookie instead of
    // replacing the first — the site keeps reading the stale one.
    expect(cookieSetDetailsFor(URL, decl, base)).toEqual({
      url: URL,
      name: 'SESSION',
      value: 'new',
      domain: '.example.com',
      path: '/',
      secure: true,
      httpOnly: true,
      sameSite: 'lax',
      expirationDate: 1893456000,
      storeId: '0',
    });
  });

  it('omits domain entirely for a host-only cookie', () => {
    // Chrome reads the PRESENCE of `domain` as "make this a domain cookie",
    // so passing it would silently widen a host-only cookie's scope.
    const details = cookieSetDetailsFor(URL, decl, { ...base, hostOnly: true });
    expect(details).not.toHaveProperty('domain');
  });

  it('omits expirationDate for a session cookie', () => {
    // Passing undefined would turn a persistent cookie into a session one;
    // omitting keeps a session cookie a session cookie.
    const { expirationDate, ...sessionCookie } = base;
    void expirationDate;
    const details = cookieSetDetailsFor(URL, decl, sessionCookie as ChromeCookie);
    expect(details).not.toHaveProperty('expirationDate');
  });

  it('never carries the old value through', () => {
    expect(cookieSetDetailsFor(URL, decl, base).value).toBe('new');
  });
});

describe('pair popup — write_cookies is presented as a write', () => {
  // The popup is where the user actually grants this. A label reading like a
  // sibling of the reads above it would understate what is being approved.
  it('labels it as changing state, and warns', async () => {
    const mod = await import('../src/popup/popup.js');
    const display = (mod as unknown as {
      __testCapabilityDisplay?: Record<string, { label: string; warn: boolean }>;
    }).__testCapabilityDisplay;
    // Falls back to reading the source when the map isn't exported for tests.
    const { readFileSync } = await import('node:fs');
    const src = display
      ? JSON.stringify(display)
      : readFileSync(new URL('../src/popup/popup.ts', import.meta.url), 'utf8');
    expect(src).toMatch(/write_cookies/);
    expect(src).toMatch(/Overwrite cookies/);
    expect(src).toMatch(/signed-in session/);
  });
});
