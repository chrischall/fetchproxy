import { describe, it, expect, vi } from 'vitest';
import {
  runFetch, assertHostOnProfile, assertUrlOnProfile, type VerbServer,
} from '../src/verbs/fetch.js';
import { emptyProfile } from '../src/profiles.js';
import { EXIT, UsageError, type Io } from '../src/output.js';
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

  it('multi-domain profile: threads the matched declared domain to request()', async () => {
    // The real server calls resolveBaseDomain(opts.domain) eagerly and throws
    // when >1 domain is declared and no domain is passed — even for absolute
    // URLs. This stub mimics that guard so the test would fail if runFetch
    // omitted the domain (regression: PR #151 auto-review).
    const io = memIo();
    const profile = emptyProfile(['honeybook.com', 'hbportal.co']);
    let sawDomain: string | undefined = 'UNSET';
    const server = stubServer({
      request: vi.fn(async (_method: string, _url: string, opts?: { domain?: string }) => {
        if (opts?.domain === undefined) {
          throw new Error('FetchproxyServer: this MCP declared multiple domains — pass { domain }');
        }
        sawDomain = opts.domain;
        return { status: 200, body: 'OK', url: 'https://app.hbportal.co/x' };
      }),
    });
    const cmd = { kind: 'fetch', profile: 'hb', method: 'GET',
      url: 'https://app.hbportal.co/x', headers: {}, body: undefined, json: false } as const;
    const code = await runFetch(cmd, profile, io, () => server);
    expect(code).toBe(EXIT.OK);
    // subdomain host resolves to its declared apex, not the first declared domain
    expect(sawDomain).toBe('hbportal.co');
  });
});

describe('runFetch — --via-tab', () => {
  it('passes the relay tab to the server', async () => {
    const server = stubServer();
    await runFetch(
      { ...CMD, url: 'https://api.tripadvisor.com/x', viaTab: 'https://www.tripadvisor.com/' },
      PROFILE,
      memIo(),
      () => server,
    );
    expect(server.request).toHaveBeenCalledWith(
      'GET',
      'https://api.tripadvisor.com/x',
      expect.objectContaining({ viaTab: 'https://www.tripadvisor.com/' }),
    );
  });

  it('leaves it undefined when not given', async () => {
    const server = stubServer();
    await runFetch(CMD, PROFILE, memIo(), () => server);
    expect(server.request).toHaveBeenCalledWith(
      'GET',
      CMD.url,
      expect.objectContaining({ viaTab: undefined }),
    );
  });
});

describe('runFetch — --via-tab is validated like the request URL', () => {
  // The request URL is checked against the profile before connecting, so a
  // typo is exit 1 with guidance. --via-tab skipped that check, so the same
  // class of mistake travelled to the bridge and came back as exit 2 — a
  // "bridge error" for what is purely a usage error (#209).
  it('rejects a malformed relay tab as a usage error', async () => {
    const server = stubServer();
    await expect(
      runFetch({ ...CMD, viaTab: 'not a url' }, PROFILE, memIo(), () => server),
    ).rejects.toThrow(UsageError);
    // Must fail before connecting — no bridge round-trip for a typo.
    expect(server.listen).not.toHaveBeenCalled();
  });

  it('rejects an off-domain relay tab as a usage error', async () => {
    const server = stubServer();
    await expect(
      runFetch({ ...CMD, viaTab: 'https://evil.example/' }, PROFILE, memIo(), () => server),
    ).rejects.toThrow(UsageError);
    expect(server.listen).not.toHaveBeenCalled();
  });

  it('accepts a relay tab on a declared domain', async () => {
    const server = stubServer();
    const code = await runFetch(
      { ...CMD, viaTab: 'https://www.tripadvisor.com/' },
      PROFILE,
      memIo(),
      () => server,
    );
    expect(code).toBe(EXIT.OK);
  });
});

describe('--in-page', () => {
  // The extension refuses an undeclared capability, but that refusal lands
  // after the bridge is up and reads as a bridge error. #324 is the standing
  // example of a misleading failure costing rounds, and --in-page exists to
  // diagnose exactly that, so it must not add one of its own.
  it('is a usage error when the profile does not declare it, before any dial', async () => {
    const server = stubServer();
    await expect(
      runFetch({ ...CMD, inPage: true } as never, PROFILE, memIo(), () => server),
    ).rejects.toThrow(UsageError);
    expect(server.listen, 'must fail before opening the bridge').not.toHaveBeenCalled();
  });

  it('sets inPage on the request when the profile declares it', async () => {
    const server = stubServer();
    const profile = { ...PROFILE, inPage: true };
    await runFetch({ ...CMD, inPage: true } as never, profile, memIo(), () => server);
    expect(server.request).toHaveBeenCalledWith(
      'GET', CMD.url, expect.objectContaining({ inPage: true }),
    );
  });

  it("--no-credentials asks the server for credentials: 'omit'", async () => {
    const server = stubServer();
    await runFetch({ ...CMD, inPage: false, noCredentials: true } as never, PROFILE, memIo(), () => server);
    expect(server.request).toHaveBeenCalledWith(
      'GET', CMD.url, expect.objectContaining({ credentials: 'omit' }),
    );
  });

  it('omits credentials entirely by default, so an ordinary fetch is unchanged', async () => {
    const server = stubServer();
    await runFetch({ ...CMD, inPage: false, noCredentials: false } as never, PROFILE, memIo(), () => server);
    const opts = (server.request as unknown as { mock: { calls: unknown[][] } }).mock.calls[0]![2];
    expect(Object.prototype.hasOwnProperty.call(opts, 'credentials')).toBe(false);
  });

  // Absent, not `false`: the wire validator distinguishes the two, and the
  // server's own call site spreads for the same reason.
  it('omits inPage entirely on an ordinary fetch', async () => {
    const server = stubServer();
    await runFetch({ ...CMD, inPage: false } as never, PROFILE, memIo(), () => server);
    const opts = (server.request as unknown as { mock: { calls: unknown[][] } }).mock.calls[0]![2];
    expect(Object.prototype.hasOwnProperty.call(opts, 'inPage')).toBe(false);
  });
});

describe('assertUrlOnProfile — judged by hostname, as the server is', () => {
  // The extension (`isUrlAllowedForDomain`) and the server
  // (`assertUrlInDomains`) both compare `URL.hostname`, which carries no
  // port. The CLI compared `URL.host`, which does, so a declared
  // `example.com` refused `https://example.com:8443/x` here and accepted it
  // one hop later — the CLI's pre-flight refusal disagreeing with the rule it
  // exists to report early. The protocol's rule is the one that binds.
  const PROF = emptyProfile(['example.com']);

  it('accepts a default-port URL on a declared domain', () => {
    expect(assertUrlOnProfile('https://example.com/x', PROF)).toBe('example.com');
  });

  it('accepts an explicit-port URL on a declared domain', () => {
    expect(assertUrlOnProfile('https://example.com:8443/x', PROF)).toBe('example.com');
  });

  it('accepts an explicit port on a subdomain of a declared domain', () => {
    expect(assertUrlOnProfile('http://api.example.com:3000/x', PROF)).toBe('example.com');
  });

  it('still refuses a host that is not on the profile, port or no port', () => {
    expect(() => assertUrlOnProfile('https://evil.com/x', PROF)).toThrow(UsageError);
    expect(() => assertUrlOnProfile('https://evil.com:8443/x', PROF)).toThrow(UsageError);
    // Not a suffix match on the raw string either: "notexample.com" ends with
    // "example.com" without being on it.
    expect(() => assertUrlOnProfile('https://notexample.com:8443/x', PROF)).toThrow(UsageError);
  });
});

/**
 * The same class of divergence as the port one above, from the same cause: a
 * host name is case-insensitive, and the layer that ENFORCES this rule says so
 * — the server's `assertUrlInDomains` lowercases the URL's hostname AND each
 * declared domain before comparing. The CLI compared both raw, so a profile
 * declaring `Example.com` refused `https://example.com/x` at the pre-flight
 * while the bridge would have accepted it one hop later. The protocol's rule
 * is the one that binds; the CLI's job is to report it early, not to add to
 * it.
 *
 * `assertHostOnProfile` is tested directly as well as through the URL form,
 * because `capture-redirect` hands it a BARE host off the command line — that
 * name never passes through `new URL()` and so is never lowercased for it.
 */
describe('assertHostOnProfile — domain case is not a rule the server has', () => {
  it('accepts a lower-case URL host on a mixed-case declared domain', () => {
    expect(assertUrlOnProfile('https://example.com/x', emptyProfile(['Example.com'])))
      .toBe('Example.com');
  });

  it('accepts a subdomain of a mixed-case declared domain', () => {
    expect(assertUrlOnProfile('https://api.example.com/x', emptyProfile(['Example.COM'])))
      .toBe('Example.COM');
  });

  // The reverse, which only a bare host can reach: `new URL()` lowercases a
  // hostname, so `capture-redirect`'s argument is the one that arrives cased.
  it('accepts a mixed-case bare host on a lower-case declared domain', () => {
    const prof = emptyProfile(['example.com']);
    expect(assertHostOnProfile('Example.com', prof)).toBe('example.com');
    expect(assertHostOnProfile('API.Example.COM', prof)).toBe('example.com');
  });

  /**
   * The DECLARED spelling comes back, never a lowercased copy: the return is
   * threaded to `request()` as `{ domain }`, and the server's
   * `resolveBaseDomain` checks it with an exact `domains.includes(domain)`
   * against the same array the profile supplied. A normalised return would
   * pass this gate and fail that one.
   */
  it('returns the declared spelling rather than a normalised one', () => {
    expect(assertUrlOnProfile('https://example.com/x', emptyProfile(['Example.com'])))
      .toBe('Example.com');
    expect(assertHostOnProfile('EXAMPLE.COM', emptyProfile(['Example.com'])))
      .toBe('Example.com');
  });

  it('refuses a host that is off the profile whatever the case', () => {
    const prof = emptyProfile(['Example.com']);
    expect(() => assertUrlOnProfile('https://evil.com/x', prof)).toThrow(UsageError);
    expect(() => assertHostOnProfile('EVIL.COM', prof)).toThrow(UsageError);
    // Still not a raw suffix match once case is out of the way.
    expect(() => assertHostOnProfile('NotExample.com', prof)).toThrow(UsageError);
  });
});
