import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from '../src/main.js';
import { EXIT, type Io } from '../src/output.js';
import { serverOptsFor } from '../src/server-opts.js';
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

  // Caught by using it, not by testing it: parsing and capability derivation
  // were both covered while the handler that persists the flag was not, so
  // `--allow-in-page` parsed, derived nothing, and wrote nothing.
  it('profile declare --allow-in-page persists the flag', async () => {
    const io = memIo();
    await runCli(['profile', 'add', 'r', '--domain', 'resy.com'], io, { home });
    expect(loadProfiles(home).r.inPage).toBe(false);
    await runCli(['profile', 'declare', 'r', '--allow-in-page'], io, { home });
    expect(loadProfiles(home).r.inPage).toBe(true);
  });

  it('profile declare without --allow-in-page leaves an existing grant alone', async () => {
    const io = memIo();
    await runCli(['profile', 'add', 'r', '--domain', 'resy.com'], io, { home });
    await runCli(['profile', 'declare', 'r', '--allow-in-page'], io, { home });
    await runCli(['profile', 'declare', 'r', '--cookie', 'tok'], io, { home });
    expect(loadProfiles(home).r.inPage, 'declare merges, it does not reset').toBe(true);
  });

  it('profile declare re-declaring a --dom-selector handle updates its selector (upsert)', async () => {
    const io = memIo();
    await runCli(['profile', 'add', 'r', '--domain', 'resy.com'], io, { home });
    await runCli(['profile', 'declare', 'r', '--dom-selector', 'title=h1'], io, { home });
    expect(loadProfiles(home).r.domSelectors).toEqual([{ name: 'title', selector: 'h1' }]);

    await runCli(['profile', 'declare', 'r', '--dom-selector', 'title=h1.new'], io, { home });
    expect(loadProfiles(home).r.domSelectors).toEqual([{ name: 'title', selector: 'h1.new' }]);
  });

  it('profile declare with a repeated --dom-selector handle in one call keeps the last value', async () => {
    const io = memIo();
    await runCli(['profile', 'add', 'r', '--domain', 'resy.com'], io, { home });
    await runCli(['profile', 'declare', 'r',
      '--dom-selector', 'title=h1', '--dom-selector', 'title=h1.final'], io, { home });
    expect(loadProfiles(home).r.domSelectors).toEqual([{ name: 'title', selector: 'h1.final' }]);
  });

  it('profile remove deletes entry, identity file and extension pin', async () => {
    const io = memIo();
    await runCli(['profile', 'add', 'r', '--domain', 'resy.com'], io, { home });
    const idFile = join(identityDir, 'fpx-r.json');
    // #208: the pin lives beside the identity, and a profile re-created under
    // this name must not inherit a browser identity it never paired with.
    const pinFile = join(identityDir, 'fpx-r.extension-trust.json');
    writeFileSync(idFile, '{}');
    writeFileSync(pinFile, '{}');
    expect(await runCli(['profile', 'remove', 'r'], io, { home, identityDir })).toBe(EXIT.OK);
    expect(loadProfiles(home)).toEqual({});
    expect(existsSync(idFile)).toBe(false);
    expect(existsSync(pinFile)).toBe(false);
    expect(io.errs.join('\n')).toMatch(/extension popup/);
  });

  /**
   * "Beside the identity" is where the pin lands by default and no longer
   * where it must land: `FETCHPROXY_TRUST_DIR` (a `trustDir` here) moves it,
   * for a host that provisions the identity directory read-only. So the
   * removal has to take the pin where it ACTUALLY is — and, the other half of
   * the same rule, must not take a file that merely sits in the identity
   * directory under the pin's name, which is what re-deriving the path from
   * the identity directory would do. The identity itself stays in the
   * identity directory: the two paths diverge, so each is asserted apart.
   */
  it('profile remove takes the pin from a trustDir that diverges from identityDir', async () => {
    const io = memIo();
    const trustDir = join(home, 'trust');
    mkdirSync(trustDir, { recursive: true });
    await runCli(['profile', 'add', 'r', '--domain', 'resy.com'], io, { home });
    const idFile = join(identityDir, 'fpx-r.json');
    const pinFile = join(trustDir, 'fpx-r.extension-trust.json');
    // Same name, wrong directory: nothing this installation writes, so nothing
    // this removal may delete.
    const decoy = join(identityDir, 'fpx-r.extension-trust.json');
    writeFileSync(idFile, '{}');
    writeFileSync(pinFile, '{}');
    writeFileSync(decoy, '{}');
    expect(await runCli(['profile', 'remove', 'r'], io, { home, identityDir, trustDir }))
      .toBe(EXIT.OK);
    expect(loadProfiles(home)).toEqual({});
    expect(existsSync(idFile), 'the identity comes from identityDir').toBe(false);
    expect(existsSync(pinFile), 'the pin comes from trustDir').toBe(false);
    expect(existsSync(decoy), 'a pin-shaped file in identityDir is not the pin').toBe(true);
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

/**
 * declare → persist → derive, end to end.
 *
 * Both halves of this were tested alone and BOTH were broken: the handler
 * never wrote `captureRedirect`/`graphqlOps`, and `serverOptsFor` derived the
 * `graphql` capability while dropping the operations the extension needs to
 * resolve a handle. Each unit test passed; the feature did not exist. The seam
 * is what has to be asserted, and it is the same regression class as the
 * `--allow-in-page` one directly above.
 */
describe('declared scope survives the whole path', () => {
  it('persists --allow-capture-redirect and --graphql-op, and derives both', async () => {
    const io = memIo();
    await runCli(['profile', 'add', 'r', '--domain', 'resy.com'], io, { home });
    await runCli([
      'profile', 'declare', 'r',
      '--allow-capture-redirect', '--graphql-op', 'avail=RestaurantsAvailability',
    ], io, { home });

    const p = loadProfiles(home).r;
    expect(p.captureRedirect, 'flag must reach the stored profile').toBe(true);
    expect(p.graphqlOps).toEqual([{ name: 'avail', operationName: 'RestaurantsAvailability' }]);

    const opts = serverOptsFor('r', p, '2.10.0');
    expect(opts.capabilities).toContain('capture_redirect');
    expect(opts.capabilities).toContain('graphql');
    // The capability alone is not enough: `graphqlQuery` rejects every
    // operation and the server hello omits the allowlist without these.
    expect(opts.graphqlOps, 'operations must reach the server').toEqual([
      { name: 'avail', operationName: 'RestaurantsAvailability' },
    ]);
  });

  it('re-declaring a --graphql-op handle updates it rather than duplicating', async () => {
    const io = memIo();
    await runCli(['profile', 'add', 'r', '--domain', 'resy.com'], io, { home });
    await runCli(['profile', 'declare', 'r', '--graphql-op', 'avail=Old'], io, { home });
    await runCli(['profile', 'declare', 'r', '--graphql-op', 'avail=New'], io, { home });
    expect(loadProfiles(home).r.graphqlOps).toEqual([
      { name: 'avail', operationName: 'New' },
    ]);
  });

  it('a later unrelated declare leaves both alone', async () => {
    const io = memIo();
    await runCli(['profile', 'add', 'r', '--domain', 'resy.com'], io, { home });
    await runCli([
      'profile', 'declare', 'r', '--allow-capture-redirect', '--graphql-op', 'avail=Op',
    ], io, { home });
    await runCli(['profile', 'declare', 'r', '--cookie', 'sid'], io, { home });
    const p = loadProfiles(home).r;
    expect(p.captureRedirect, 'declare merges, it does not reset').toBe(true);
    expect(p.graphqlOps).toHaveLength(1);
  });
});
