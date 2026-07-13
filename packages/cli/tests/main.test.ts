import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from '../src/main.js';
import { EXIT, type Io } from '../src/output.js';
import { loadProfiles } from '../src/profiles.js';
import { VERSION } from '../src/version.js';

function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = []; const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}
let home: string;
let identityDir: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'fpx-main-'));
  identityDir = join(home, 'identity');
  mkdirSync(identityDir, { recursive: true });
});
afterEach(() => rmSync(home, { recursive: true, force: true }));

describe('runCli', () => {
  it('profile add → list → show round-trip', async () => {
    const io = memIo();
    expect(await runCli(['profile', 'add', 'trip', '--domain', 'tripadvisor.com'], io, { home }))
      .toBe(EXIT.OK);
    expect(await runCli(['profile', 'list'], io, { home })).toBe(EXIT.OK);
    expect(io.outs.join('\n')).toMatch(/trip\s+tripadvisor\.com/);
    expect(await runCli(['profile', 'show', 'trip'], io, { home })).toBe(EXIT.OK);
  });

  it('profile add rejects duplicates', async () => {
    const io = memIo();
    await runCli(['profile', 'add', 'trip', '--domain', 'tripadvisor.com'], io, { home });
    expect(await runCli(['profile', 'add', 'trip', '--domain', 'x.com'], io, { home }))
      .toBe(EXIT.USAGE);
    expect(io.errs.join('\n')).toMatch(/already exists/);
  });

  it('profile declare merges uniquely and warns about re-pair', async () => {
    const io = memIo();
    await runCli(['profile', 'add', 'r', '--domain', 'resy.com'], io, { home });
    await runCli(['profile', 'declare', 'r', '--cookie', 'tok', '--cookie', 'tok'], io, { home });
    expect(loadProfiles(home).r.cookies).toEqual(['tok']);
    expect(io.errs.join('\n')).toMatch(/re-pair/i);
  });

  it('profile remove deletes entry and identity file', async () => {
    const io = memIo();
    await runCli(['profile', 'add', 'r', '--domain', 'resy.com'], io, { home });
    const idFile = join(identityDir, 'fpx-r.json');
    writeFileSync(idFile, '{}');
    expect(await runCli(['profile', 'remove', 'r'], io, { home, identityDir })).toBe(EXIT.OK);
    expect(loadProfiles(home)).toEqual({});
    expect(existsSync(idFile)).toBe(false);
    expect(io.errs.join('\n')).toMatch(/extension popup/);
  });

  it('verb dispatch: get uses the injected factory and profile', async () => {
    const io = memIo();
    await runCli(['profile', 'add', 'trip', '--domain', 'tripadvisor.com'], io, { home });
    const makeServer = vi.fn(() => ({
      listen: async () => {}, close: async () => {},
      request: async () => ({ status: 200, body: 'OK', url: 'https://www.tripadvisor.com/' }),
      readCookies: async () => '', readLocalStorage: async () => ({}),
      readSessionStorage: async () => ({}), readIndexedDb: async () => ({}),
      bridgeHealth: () => ({}),
    }));
    const code = await runCli(['get', 'https://www.tripadvisor.com/', '-p', 'trip'],
      io, { home, makeServer: makeServer as never });
    expect(code).toBe(EXIT.OK);
    expect(io.outs).toEqual(['OK']);
    expect((makeServer.mock.calls[0] as unknown[])[0]).toMatchObject({ serverName: 'fpx-trip' });
  });

  it('UsageError → exit 1 with message on stderr', async () => {
    const io = memIo();
    expect(await runCli(['get', 'https://x.com/'], io, { home })).toBe(EXIT.USAGE);
    expect(io.errs.join('\n')).toMatch(/--profile/);
  });

  it('help → exit 0, usage on stderr, stdout untouched', async () => {
    const io = memIo();
    expect(await runCli(['--help'], io, { home })).toBe(EXIT.OK);
    expect(io.outs).toEqual([]);
    expect(io.errs.join('\n')).toMatch(/fpx/);
  });

  it('--version / -v print the bare version to stdout, exit 0', async () => {
    const io = memIo();
    expect(await runCli(['--version'], io, { home })).toBe(EXIT.OK);
    expect(io.outs).toEqual([VERSION]);
    expect(io.errs).toEqual([]);
    const io2 = memIo();
    await runCli(['-v'], io2, { home });
    expect(io2.outs).toEqual([VERSION]);
  });

  it('help header includes the version', async () => {
    const io = memIo();
    await runCli([], io, { home }); // no args → help
    expect(io.errs.join('\n')).toContain(VERSION);
  });
});
