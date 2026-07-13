import { describe, it, expect, vi } from 'vitest';
import { runDom } from '../src/verbs/dom.js';
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
    readDom: vi.fn(async () => ({ title: 'Widget' })),
    download: vi.fn(async () => ({ path: '/tmp/x', bytes: 1 })),
    bridgeHealth: vi.fn(() => ({})),
    ...overrides,
  } as never;
}
const PROFILE = {
  ...emptyProfile(['resy.com']),
  domSelectors: [{ name: 'title', selector: 'h1' }, { name: 'price', selector: '.price' }],
};

describe('runDom', () => {
  it('narrows to requested declared names and reads via readDom', async () => {
    const server = stubServer();
    const code = await runDom(
      { kind: 'dom', profile: 'r', names: ['title'] }, PROFILE, memIo(), () => server);
    expect(code).toBe(EXIT.OK);
    expect(server.readDom).toHaveBeenCalledWith({ names: ['title'], domain: undefined, subdomain: undefined });
  });

  it('empty names → reads all declared selectors', async () => {
    const server = stubServer();
    await runDom({ kind: 'dom', profile: 'r', names: [] }, PROFILE, memIo(), () => server);
    expect(server.readDom).toHaveBeenCalledWith({ names: ['title', 'price'], domain: undefined, subdomain: undefined });
  });

  it('undeclared name → UsageError naming profile declare, before connect', async () => {
    const factory = vi.fn();
    await expect(runDom({ kind: 'dom', profile: 'r', names: ['zzz'] }, PROFILE, memIo(), factory))
      .rejects.toThrow(/profile declare/);
    expect(factory).not.toHaveBeenCalled();
  });

  it('empty declared selectors → UsageError pointing at --dom-selector', async () => {
    const factory = vi.fn();
    await expect(runDom({ kind: 'dom', profile: 'r', names: [] }, emptyProfile(['resy.com']), memIo(), factory))
      .rejects.toThrow(/--dom-selector/);
    expect(factory).not.toHaveBeenCalled();
  });

  it('prints the readDom result as JSON', async () => {
    const io = memIo();
    await runDom({ kind: 'dom', profile: 'r', names: ['title'] }, PROFILE, io, () => stubServer());
    expect(JSON.parse(io.outs[0])).toEqual({ title: 'Widget' });
  });

  it('threads storageDomain/storageSubdomain', async () => {
    const server = stubServer();
    await runDom({ kind: 'dom', profile: 'r', names: ['title'], storageDomain: 'resy.com', storageSubdomain: 'app' },
      PROFILE, memIo(), () => server);
    expect(server.readDom).toHaveBeenCalledWith({ names: ['title'], domain: 'resy.com', subdomain: 'app' });
  });
});
