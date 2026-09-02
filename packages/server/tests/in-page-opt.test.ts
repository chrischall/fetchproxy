import { describe, it, expect, vi } from 'vitest';
import { FetchproxyServer } from '../src/index.js';

/**
 * `inPage` reaches the wire through the ORDINARY verbs.
 *
 * The flag itself shipped in the protocol's `FetchInit`, but `RequestOpts` /
 * `BodylessRequestOpts` did not carry it — so the only way to set it was the
 * low-level `fetch(init)`, which bypasses everything `request()` is for:
 * `assertUrlInDomains` on the resolved URL, `expectStatus`, and the typed
 * `FetchproxyHttpError` / `FetchproxyProtocolError` conversion. A consumer
 * needing one in-page call had to give all of that up for every call in that
 * path. Threaded the way `viaTab` is.
 */
function serverWithCapturedFetch(domains: string[]) {
  const server = new FetchproxyServer({ serverName: 'test', version: '0.0.0', domains });
  const fetchSpy = vi
    .spyOn(server, 'fetch')
    .mockResolvedValue({ ok: true, status: 200, headers: {}, body: '{}', url: 'https://x/' } as never);
  return { server, fetchSpy };
}

describe('request({ inPage })', () => {
  it('omits inPage entirely by default — the flag is opt-in on the wire', async () => {
    const { server, fetchSpy } = serverWithCapturedFetch(['resy.com']);
    await server.request('POST', 'https://api.resy.com/3/book');
    expect(fetchSpy.mock.calls[0][0]).not.toHaveProperty('inPage');
  });

  it('passes inPage: true through to the fetch init', async () => {
    const { server, fetchSpy } = serverWithCapturedFetch(['resy.com']);
    await server.request('POST', 'https://api.resy.com/3/book', { inPage: true });
    expect(fetchSpy.mock.calls[0][0]).toMatchObject({
      url: 'https://api.resy.com/3/book',
      inPage: true,
    });
  });

  it('reaches the wire through the bodyless shortcuts too', async () => {
    const { server, fetchSpy } = serverWithCapturedFetch(['resy.com']);
    await server.postJson('https://api.resy.com/3/book', { a: 1 }, { inPage: true });
    await server.getJson('https://api.resy.com/3/me', { inPage: true });
    expect(fetchSpy.mock.calls[0][0]).toMatchObject({ inPage: true });
    expect(fetchSpy.mock.calls[1][0]).toMatchObject({ inPage: true });
  });

  it('still enforces the domain guard that the low-level fetch would have skipped', async () => {
    const { server } = serverWithCapturedFetch(['resy.com']);
    await expect(
      server.request('POST', 'https://evil.example/steal', { inPage: true }),
    ).rejects.toThrow(/domain/i);
  });
});
