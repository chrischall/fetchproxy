import { describe, it, expect, vi } from 'vitest';
import { FetchproxyServer } from '../src/index.js';

/**
 * `request()` derives the relay tab from the request's own host. That is right
 * for app hosts — routing photos.x.com through a www.x.com tab would be wrong —
 * but it assumes every host CAN have a tab, and API hosts can't.
 *
 * api.creditkarma.com serves no HTML app. Opening a tab there yields a page
 * with no content script, so a bridged request to it is unroutable no matter
 * what the user opens — while the signed-in www.creditkarma.com tab could
 * perform that cross-origin fetch perfectly well, as CK's own web app does for
 * every GraphQL call (#203).
 *
 * `viaTab` names the relay explicitly. The default is untouched.
 */
function serverWithCapturedFetch(domains: string[]) {
  const server = new FetchproxyServer({ serverName: 'test', version: '0.0.0', domains });
  const fetchSpy = vi
    .spyOn(server, 'fetch')
    .mockResolvedValue({ ok: true, status: 200, headers: {}, body: '{}', url: 'https://x/' } as never);
  return { server, fetchSpy };
}

describe('request({ viaTab })', () => {
  it('defaults the relay tab to the request host', async () => {
    const { server, fetchSpy } = serverWithCapturedFetch(['creditkarma.com']);

    await server.request('POST', 'https://api.creditkarma.com/graphql');

    expect(fetchSpy.mock.calls[0][0]).toMatchObject({
      url: 'https://api.creditkarma.com/graphql',
      tabUrl: 'https://api.creditkarma.com/',
    });
  });

  it('routes through the named tab when one is given', async () => {
    const { server, fetchSpy } = serverWithCapturedFetch(['creditkarma.com']);

    await server.request('POST', 'https://api.creditkarma.com/graphql', {
      viaTab: 'https://www.creditkarma.com/',
    });

    // The request URL is untouched — only the tab performing it changes.
    expect(fetchSpy.mock.calls[0][0]).toMatchObject({
      url: 'https://api.creditkarma.com/graphql',
      tabUrl: 'https://www.creditkarma.com/',
    });
  });

  it('works for relative paths too', async () => {
    const { server, fetchSpy } = serverWithCapturedFetch(['creditkarma.com']);

    await server.request('GET', '/graphql', {
      subdomain: 'api',
      viaTab: 'https://www.creditkarma.com/',
    });

    expect(fetchSpy.mock.calls[0][0]).toMatchObject({
      url: 'https://api.creditkarma.com/graphql',
      tabUrl: 'https://www.creditkarma.com/',
    });
  });

  it('refuses a relay tab outside the declared domains', async () => {
    // Without this, `viaTab` would be a way to run fetches from the context of
    // any page the user happens to have open. The declared-domain set is the
    // boundary the user approved at pair time; widening which tab relays must
    // not be a way around it.
    const { server } = serverWithCapturedFetch(['creditkarma.com']);

    await expect(
      server.request('POST', 'https://api.creditkarma.com/graphql', {
        viaTab: 'https://evil.example/',
      }),
    ).rejects.toThrow(/not in domains|viaTab/i);
  });

  it('accepts a relay tab on a declared subdomain', async () => {
    const { server, fetchSpy } = serverWithCapturedFetch(['creditkarma.com']);

    await server.request('GET', 'https://api.creditkarma.com/x', {
      viaTab: 'https://www.creditkarma.com/networth/transactions',
    });

    // Kept verbatim: tab matching is prefix-based, so a deeper path lets the
    // caller pin one specific page rather than any page on the host.
    expect(fetchSpy.mock.calls[0][0]).toMatchObject({
      tabUrl: 'https://www.creditkarma.com/networth/transactions',
    });
  });

  it('rejects a malformed relay tab with a message naming the option', async () => {
    const { server } = serverWithCapturedFetch(['creditkarma.com']);

    await expect(
      server.request('GET', 'https://api.creditkarma.com/x', { viaTab: 'not a url' }),
    ).rejects.toThrow(/viaTab/);
  });
});
