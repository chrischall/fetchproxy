import { describe, it, expect, vi } from 'vitest';
import { runRead } from '../src/verbs/read.js';
import { emptyProfile } from '../src/profiles.js';
import { EXIT, type Io } from '../src/output.js';
import type { VerbServer } from '../src/verbs/fetch.js';

function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = []; const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}
function stubServer(overrides: Partial<VerbServer> = {}): VerbServer {
  return {
    listen: vi.fn(async () => {}), close: vi.fn(async () => {}),
    request: vi.fn(async () => ({ status: 200, body: '', url: '' })),
    readCookies: vi.fn(async () => 'a=1; b=2'),
    readLocalStorage: vi.fn(async () => ({ tok: 'T' })),
    readSessionStorage: vi.fn(async () => ({})),
    readIndexedDb: vi.fn(async () => ({ k: 'v' })),
    bridgeHealth: vi.fn(() => ({})),
    ...overrides,
  } as never;
}
const PROFILE = {
  ...emptyProfile(['resy.com']),
  cookies: ['a', 'b'],
  localStorage: ['tok'],
  indexedDb: [{ origin: 'https://resy.com', database: 'db', store: 's', keys: ['k'] }],
};

describe('runRead', () => {
  it('cookies: parses the joined string into a JSON record', async () => {
    const io = memIo();
    const code = await runRead(
      { kind: 'read', profile: 'r', bucket: 'cookies', keys: [] }, PROFILE, io, () => stubServer());
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs[0])).toEqual({ a: '1', b: '2' });
  });

  it('narrows to requested declared keys', async () => {
    const server = stubServer();
    await runRead({ kind: 'read', profile: 'r', bucket: 'cookies', keys: ['a'] },
      PROFILE, memIo(), () => server);
    expect(server.readCookies).toHaveBeenCalledWith({ keys: ['a'], domain: undefined, subdomain: undefined });
  });

  it('undeclared key → UsageError naming profile declare', async () => {
    await expect(runRead({ kind: 'read', profile: 'r', bucket: 'cookies', keys: ['zzz'] },
      PROFILE, memIo(), () => stubServer())).rejects.toThrow(/profile declare/);
  });

  it('multi-domain profile without --storage-domain → UsageError naming the flag', async () => {
    const multi = { ...PROFILE, domains: ['resy.com', 'resy.io'] };
    const server = stubServer();
    await expect(runRead({ kind: 'read', profile: 'r', bucket: 'cookies', keys: [] },
      multi, memIo(), () => server)).rejects.toThrow(/--storage-domain/);
    // Refused before connecting: a usage error must not cost a bridge
    // round-trip, and must not trigger pairing.
    expect(server.listen).not.toHaveBeenCalled();
  });

  it('multi-domain profile WITH --storage-domain proceeds', async () => {
    const multi = { ...PROFILE, domains: ['resy.com', 'resy.io'] };
    const server = stubServer();
    const code = await runRead(
      { kind: 'read', profile: 'r', bucket: 'cookies', keys: [], storageDomain: 'resy.io' },
      multi, memIo(), () => server);
    expect(code).toBe(EXIT.OK);
    expect(server.readCookies).toHaveBeenCalledWith(
      { keys: ['a', 'b'], domain: 'resy.io', subdomain: undefined });
  });

  it('empty declared bucket → UsageError with the declare flag', async () => {
    await expect(runRead({ kind: 'read', profile: 'r', bucket: 'sessionStorage', keys: [] },
      PROFILE, memIo(), () => stubServer())).rejects.toThrow(/--session-storage/);
  });

  it('indexeddb: reads every declared scope keyed db/store', async () => {
    const io = memIo();
    const code = await runRead({ kind: 'read', profile: 'r', bucket: 'indexedDb', keys: [] },
      PROFILE, io, () => stubServer());
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs[0])).toEqual({ 'db/s': { k: 'v' } });
  });
});
