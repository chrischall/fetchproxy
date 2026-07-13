import { describe, it, expect, vi } from 'vitest';
import { runDownload } from '../src/verbs/download.js';
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
    readCookies: vi.fn(async () => ''),
    readLocalStorage: vi.fn(async () => ({})),
    readSessionStorage: vi.fn(async () => ({})),
    readIndexedDb: vi.fn(async () => ({})),
    readDom: vi.fn(async () => ({})),
    download: vi.fn(async () => ({ path: '/tmp/f.pdf', bytes: 1234, mime: 'application/pdf' })),
    bridgeHealth: vi.fn(() => ({})),
    ...overrides,
  } as never;
}
const PROFILE = { ...emptyProfile(['resy.com']), download: true };

describe('runDownload', () => {
  it('download:false profile → UsageError before connect', async () => {
    const factory = vi.fn();
    await expect(runDownload(
      { kind: 'download', profile: 'r', url: 'https://resy.com/f.pdf' },
      emptyProfile(['resy.com']), memIo(), factory,
    )).rejects.toThrow(/--allow-download/);
    expect(factory).not.toHaveBeenCalled();
  });

  it('download:true → calls download and prints the stubbed result', async () => {
    const io = memIo();
    const server = stubServer();
    const code = await runDownload(
      { kind: 'download', profile: 'r', url: 'https://resy.com/f.pdf', filename: 'f.pdf' },
      PROFILE, io, () => server,
    );
    expect(code).toBe(EXIT.OK);
    expect(server.download).toHaveBeenCalledWith({ url: 'https://resy.com/f.pdf', filename: 'f.pdf' });
    expect(JSON.parse(io.outs[0])).toEqual({ path: '/tmp/f.pdf', bytes: 1234, mime: 'application/pdf' });
  });

  it('off-domain url → UsageError before connect', async () => {
    const factory = vi.fn();
    await expect(runDownload(
      { kind: 'download', profile: 'r', url: 'https://evil.com/f.pdf' }, PROFILE, memIo(), factory,
    )).rejects.toThrow(/resy\.com/);
    expect(factory).not.toHaveBeenCalled();
  });
});
