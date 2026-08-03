import { describe, it, expect } from 'vitest';
import { FetchproxyServer } from '../src/index.js';

/**
 * Path-scoped cookies (#198).
 *
 * `read_cookies` built an origin with no path and the extension called
 * `chrome.cookies.get({ url: origin, name })`. Chrome's cookie matching is
 * path-sensitive, so any cookie narrower than `Path=/` was invisible and the
 * read reported the user signed out.
 *
 * Verified live against Infinite Campus, which sets
 * `JSESSIONID=...; Path=/campus` (Tomcat's default for an app deployed at
 * /campus): the cookie read returned {} while a fetch through the same tab
 * returned authenticated data.
 *
 * The origin is already a URL and the extension's allow-check is host-only
 * (`isUrlAllowedForDomain` parses and compares `hostname`), so the path rides
 * along without a protocol or extension change.
 */
function captureInit(): { server: FetchproxyServer; sent: unknown[] } {
  const sent: unknown[] = [];
  const server = new FetchproxyServer({
    serverName: 'probe',
    version: '1',
    domains: ['ncsis.gov'],
    capabilities: ['read_cookies'],
    cookieKeys: ['JSESSIONID'],
    localStorageKeys: [],
    sessionStorageKeys: [],
    captureHeaders: [],
  } as never);
  // Intercept the frame instead of standing up a bridge.
  (server as unknown as { sendInnerFrame: (f: unknown) => Promise<void> }).sendInnerFrame = async (
    f: unknown,
  ) => {
    sent.push(f);
  };
  (server as unknown as { ensureConnected: () => Promise<void> }).ensureConnected = async () => {};
  (server as unknown as { throwIfPendingPair: () => void }).throwIfPendingPair = () => {};
  return { server, sent };
}

const initOf = (frame: unknown) =>
  (frame as { init: { origin: string; path?: string } }).init;

describe('readCookies — storage path', () => {
  it('includes the path in the origin so path-scoped cookies match', async () => {
    const { server, sent } = captureInit();
    void server.readCookies({ keys: ['JSESSIONID'], subdomain: '600', path: '/campus' });
    await new Promise((r) => setTimeout(r, 0));
    // Origin stays BARE — assertHttpsOriginOnly refuses a path there, so
    // smuggling one in would make the frame invalid and the extension would
    // silently drop it (observed live as a 30s timeout).
    expect(initOf(sent[0]).origin).toBe('https://600.ncsis.gov');
    expect(initOf(sent[0]).path).toBe('/campus');
  });

  it('omits the path when none is given (unchanged behavior)', async () => {
    const { server, sent } = captureInit();
    void server.readCookies({ keys: ['JSESSIONID'], subdomain: '600' });
    await new Promise((r) => setTimeout(r, 0));
    expect(initOf(sent[0]).origin).toBe('https://600.ncsis.gov');
    expect(initOf(sent[0]).path).toBeUndefined();
  });

  it('normalizes a path given without a leading slash', async () => {
    const { server, sent } = captureInit();
    void server.readCookies({ keys: ['JSESSIONID'], path: 'campus' });
    await new Promise((r) => setTimeout(r, 0));
    expect(initOf(sent[0]).origin).toBe('https://ncsis.gov');
    expect(initOf(sent[0]).path).toBe('/campus');
  });

  it('rejects a path that is not a path', async () => {
    const { server } = captureInit();
    await expect(
      server.readCookies({ keys: ['JSESSIONID'], path: 'https://evil.example.com/' }),
    ).rejects.toThrow(/path/i);
  });
});
