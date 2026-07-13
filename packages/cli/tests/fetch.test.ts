import { describe, it, expect, vi } from 'vitest';
import { runFetch, type VerbServer } from '../src/verbs/fetch.js';
import { emptyProfile } from '../src/profiles.js';
import { EXIT, type Io } from '../src/output.js';
import { FetchproxySessionNotReadyError } from '@fetchproxy/server';

function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = []; const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}
const CMD = { kind: 'fetch', profile: 'trip', method: 'GET',
  url: 'https://www.tripadvisor.com/x', headers: {}, body: undefined, json: false } as const;
const PROFILE = emptyProfile(['tripadvisor.com']);

function stubServer(overrides: Partial<VerbServer> = {}): VerbServer & { closed: boolean } {
  const s = {
    closed: false,
    listen: vi.fn(async () => {}),
    close: vi.fn(async () => { s.closed = true; }),
    request: vi.fn(async () => ({ status: 200, body: 'BODY', url: CMD.url })),
    readCookies: vi.fn(async () => ''),
    readLocalStorage: vi.fn(async () => ({})),
    readSessionStorage: vi.fn(async () => ({})),
    readIndexedDb: vi.fn(async () => ({})),
    bridgeHealth: vi.fn(() => ({})),
    ...overrides,
  };
  return s as never;
}

describe('runFetch', () => {
  it('2xx: body to stdout, exit 0, server closed', async () => {
    const io = memIo(); const server = stubServer();
    const code = await runFetch(CMD, PROFILE, io, () => server);
    expect(code).toBe(EXIT.OK);
    expect(io.outs).toEqual(['BODY']);
    expect(server.closed).toBe(true);
  });

  it('--json wraps status/url/body', async () => {
    const io = memIo();
    await runFetch({ ...CMD, json: true }, PROFILE, io, () => stubServer());
    expect(JSON.parse(io.outs[0])).toEqual({ status: 200, url: CMD.url, body: 'BODY' });
  });

  it('non-2xx: exit 4 with status on stderr, body still on stdout', async () => {
    const io = memIo();
    const server = stubServer({ request: vi.fn(async () => ({ status: 404, body: 'nope', url: CMD.url })) });
    const code = await runFetch(CMD, PROFILE, io, () => server);
    expect(code).toBe(EXIT.HTTP);
    expect(io.outs).toEqual(['nope']);
    expect(io.errs.join('\n')).toMatch(/HTTP 404/);
  });

  it('bot wall body → exit 3 with vendor named', async () => {
    const io = memIo();
    const server = stubServer({ request: vi.fn(async () => ({
      status: 403, body: 'var dd={"rt":"c"}… captcha-delivery.com …', url: CMD.url })) });
    const code = await runFetch(CMD, PROFILE, io, () => server);
    expect(code).toBe(EXIT.BOTWALL);
    expect(io.errs.join('\n')).toMatch(/bot wall/i);
  });

  it('session-not-ready → exit 2 with pairing hint', async () => {
    const io = memIo();
    const server = stubServer({ request: vi.fn(async () => {
      throw new FetchproxySessionNotReadyError({ mcpId: 'fpx-trip', pairCode: '123-456' });
    }) });
    const code = await runFetch(CMD, PROFILE, io, () => server);
    expect(code).toBe(EXIT.BRIDGE);
    expect(io.errs.join('\n')).toMatch(/123-456|pair/i);
  });

  it('off-domain URL → UsageError before any connect', async () => {
    const io = memIo();
    const factory = vi.fn();
    await expect(runFetch({ ...CMD, url: 'https://evil.com/x' }, PROFILE, io, factory))
      .rejects.toThrow(/tripadvisor\.com/);
    expect(factory).not.toHaveBeenCalled();
  });
});
