import { describe, it, expect, vi } from 'vitest';
import { runDomList } from '../src/verbs/dom-list.js';
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
    readDomList: vi.fn(async () => [{ title: 'Row 1' }, { title: 'Row 2' }]),
    download: vi.fn(async () => ({ path: '/tmp/x', bytes: 1 })),
    bridgeHealth: vi.fn(() => ({})),
    ...overrides,
  } as never;
}
const PROFILE = {
  ...emptyProfile(['resy.com']),
  domListSelectors: [
    { name: 'rows', itemSelector: '.row', fields: [{ name: 'title', selector: '.title' }] },
  ],
};

describe('runDomList', () => {
  it('multi-domain profile without --storage-domain → UsageError naming the flag', async () => {
    const server = stubServer();
    await expect(runDomList({ kind: 'dom-list', profile: 'r', name: 'rows' },
      { ...PROFILE, domains: ['resy.com', 'resy.io'] }, memIo(), () => server))
      .rejects.toThrow(/--storage-domain/);
    expect(server.listen).not.toHaveBeenCalled();
  });

  it('reads the declared selector by name via readDomList', async () => {
    const server = stubServer();
    const code = await runDomList(
      { kind: 'dom-list', profile: 'r', name: 'rows' }, PROFILE, memIo(), () => server);
    expect(code).toBe(EXIT.OK);
    expect(server.readDomList).toHaveBeenCalledWith({ name: 'rows', domain: undefined, subdomain: undefined });
  });

  it('undeclared name → UsageError naming profile declare, before connect', async () => {
    const factory = vi.fn();
    await expect(runDomList({ kind: 'dom-list', profile: 'r', name: 'zzz' }, PROFILE, memIo(), factory))
      .rejects.toThrow(/profile declare/);
    expect(factory).not.toHaveBeenCalled();
  });

  it('empty declared selectors → UsageError pointing at --dom-list-selector', async () => {
    const factory = vi.fn();
    await expect(runDomList({ kind: 'dom-list', profile: 'r', name: 'rows' }, emptyProfile(['resy.com']), memIo(), factory))
      .rejects.toThrow(/--dom-list-selector/);
    expect(factory).not.toHaveBeenCalled();
  });

  it('prints the readDomList result as JSON', async () => {
    const io = memIo();
    await runDomList({ kind: 'dom-list', profile: 'r', name: 'rows' }, PROFILE, io, () => stubServer());
    expect(JSON.parse(io.outs[0])).toEqual([{ title: 'Row 1' }, { title: 'Row 2' }]);
  });

  it('threads storageDomain/storageSubdomain', async () => {
    const server = stubServer();
    await runDomList({ kind: 'dom-list', profile: 'r', name: 'rows', storageDomain: 'resy.com', storageSubdomain: 'app' },
      PROFILE, memIo(), () => server);
    expect(server.readDomList).toHaveBeenCalledWith({ name: 'rows', domain: 'resy.com', subdomain: 'app' });
  });
});
