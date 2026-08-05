import { describe, it, expect, vi } from 'vitest';
import { FetchproxyServer } from '../src/index.js';

/**
 * The bridge's only write verb, added for one failure class: sites that ROTATE
 * a credential cookie. The MCP refreshes, the site issues a new value, and the
 * copy in the browser's cookie jar is dead — so the user is signed out of a tab
 * they never touched, and told it was "inactivity". Reading cannot repair that
 * (chrischall/creditkarma-mcp#119); writing the rotated value back can.
 *
 * Because it is the first write capability, the gates matter more than the
 * happy path. Two independent ones on this side: the capability must be
 * declared, and every name must already be in declared `cookieKeys` — so
 * granting writes can never widen WHICH cookies are in play, only what may be
 * done to the ones the user already saw and approved.
 */
function server(opts: { capabilities?: string[]; cookieKeys?: string[] } = {}) {
  return new FetchproxyServer({
    serverName: 'test',
    version: '0.0.0',
    domains: ['example.com'],
    capabilities: (opts.capabilities ?? ['fetch', 'read_cookies', 'write_cookies']) as never,
    cookieKeys: opts.cookieKeys ?? ['SESSION', 'REFRESH'],
  });
}

/** Capture the inner frame instead of talking to a bridge. */
function captureFrame(s: FetchproxyServer) {
  const sent: unknown[] = [];
  vi.spyOn(s as never, 'ensureConnected').mockResolvedValue(undefined as never);
  vi.spyOn(s as never, 'throwIfPendingPair').mockReturnValue(undefined as never);
  vi.spyOn(s as never, 'sendInnerFrame').mockImplementation(async (f: unknown) => {
    sent.push(f);
  });
  return sent;
}

describe('writeCookies — gates', () => {
  it('refuses when the capability was not declared', async () => {
    // Declaring cookieKeys for reading must not imply permission to write them.
    const s = server({ capabilities: ['fetch', 'read_cookies'] });

    await expect(s.writeCookies({ cookies: { SESSION: 'new' } })).rejects.toThrow(
      /did not declare "write_cookies"/,
    );
  });

  it('refuses a cookie outside the declared keys', async () => {
    const s = server();
    captureFrame(s);

    await expect(s.writeCookies({ cookies: { OTHER: 'v' } })).rejects.toThrow(/cookieKeys/);
  });

  it('refuses when any one name is undeclared, not just the first', async () => {
    // Partial application of a rotation is worse than refusing it.
    const s = server();
    captureFrame(s);

    await expect(
      s.writeCookies({ cookies: { SESSION: 'ok', SNEAKY: 'v' } }),
    ).rejects.toThrow(/cookieKeys/);
  });

  it('refuses an empty write rather than sending a no-op frame', async () => {
    const s = server();
    captureFrame(s);

    await expect(s.writeCookies({ cookies: {} })).rejects.toThrow(/no cookies/i);
  });
});

describe('writeCookies — the frame it sends', () => {
  it('carries a bare origin and the name/value pairs', async () => {
    const s = server();
    const sent = captureFrame(s);

    void s.writeCookies({ cookies: { SESSION: 'a', REFRESH: 'b' } });
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    expect(sent[0]).toMatchObject({
      op: 'write_cookies',
      init: {
        origin: 'https://example.com',
        cookies: [
          { name: 'SESSION', value: 'a' },
          { name: 'REFRESH', value: 'b' },
        ],
      },
    });
  });

  it('keeps the path as its own field so it cannot re-point the origin', async () => {
    // Same invariant the read path holds: the domain gate is decided on the
    // bare origin, so a path must never be foldable into it.
    const s = server();
    const sent = captureFrame(s);

    void s.writeCookies({ cookies: { SESSION: 'a' }, path: '/campus' });
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    expect(sent[0]).toMatchObject({
      init: { origin: 'https://example.com', path: '/campus' },
    });
  });

  it('targets the requested subdomain', async () => {
    const s = server();
    const sent = captureFrame(s);

    void s.writeCookies({ cookies: { SESSION: 'a' }, subdomain: 'www' });
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    expect(sent[0]).toMatchObject({ init: { origin: 'https://www.example.com' } });
  });
});
