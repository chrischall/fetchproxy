import { describe, it, expect } from 'vitest';
import { parseCliArgs } from '../src/args.js';
import { UsageError } from '../src/output.js';

describe('parseCliArgs', () => {
  it('parses profile add with repeated domains', () => {
    expect(parseCliArgs(['profile', 'add', 'hb', '--domain', 'honeybook.com', '--domain', 'hbportal.co']))
      .toEqual({ kind: 'profile-add', name: 'hb', domains: ['honeybook.com', 'hbportal.co'] });
  });

  it('parses profile declare with capture-header name@host/path', () => {
    const cmd = parseCliArgs(['profile', 'declare', 'trip', '--cookie', 'datadome',
      '--capture-header', 'x-csrf-token@www.tripadvisor.com/data/*']);
    expect(cmd).toEqual({
      kind: 'profile-declare', name: 'trip', cookies: ['datadome'],
      localStorage: [], sessionStorage: [],
      captureHeaders: [{ headerName: 'x-csrf-token', host: 'www.tripadvisor.com', path: '/data/*' }],
      domSelectors: [], download: false, cookieWrite: false, inPage: false,
    });
  });

  it('parses profile declare with --dom-selector and --allow-download', () => {
    const cmd = parseCliArgs(['profile', 'declare', 'r',
      '--dom-selector', 'title=h1.title', '--allow-download']);
    expect(cmd).toEqual({
      kind: 'profile-declare', name: 'r', cookies: [], localStorage: [], sessionStorage: [],
      captureHeaders: [], domSelectors: [{ name: 'title', selector: 'h1.title' }], download: true,
      cookieWrite: false, inPage: false,
    });
  });

  it('--dom-selector splits at the first = only', () => {
    const cmd = parseCliArgs(['profile', 'declare', 'r', '--dom-selector', 'q=a[href="="]']);
    expect(cmd.kind).toBe('profile-declare');
    expect((cmd as { domSelectors: unknown }).domSelectors).toEqual([{ name: 'q', selector: 'a[href="="]' }]);
  });

  it('--dom-selector without = throws a UsageError', () => {
    expect(() => parseCliArgs(['profile', 'declare', 'r', '--dom-selector', 'nope']))
      .toThrow(UsageError);
  });

  it('--dom-selector with an empty handle throws a UsageError', () => {
    expect(() => parseCliArgs(['profile', 'declare', 'r', '--dom-selector', '=h1']))
      .toThrow(UsageError);
  });

  it('parses dom with names and storage-domain/subdomain', () => {
    expect(parseCliArgs(['dom', 'a', 'b', '-p', 'x', '--storage-domain', 'd.com', '--storage-subdomain', 's']))
      .toEqual({ kind: 'dom', profile: 'x', names: ['a', 'b'], storageDomain: 'd.com', storageSubdomain: 's' });
  });

  it('parses download with url and --filename', () => {
    expect(parseCliArgs(['download', 'https://x.com/f', '-p', 'x', '--filename', 'f']))
      .toEqual({ kind: 'download', profile: 'x', url: 'https://x.com/f', filename: 'f' });
  });

  it('download without a URL throws a UsageError', () => {
    expect(() => parseCliArgs(['download', '-p', 'x'])).toThrow(UsageError);
  });

  it('parses get with headers and --json', () => {
    const cmd = parseCliArgs(['get', 'https://www.tripadvisor.com/x', '-p', 'trip',
      '--json', '-H', 'Accept: application/json']);
    expect(cmd).toEqual({
      kind: 'fetch', profile: 'trip', method: 'GET', url: 'https://www.tripadvisor.com/x',
      headers: { Accept: 'application/json' }, body: undefined, json: true,
      inPage: false, noCredentials: false,
    });
  });

  it('post-json resolves @file bodies and sets content-type', () => {
    const cmd = parseCliArgs(['post-json', 'https://x.com/api', '@body.json', '-p', 'x'],
      (p) => { expect(p).toBe('body.json'); return '{"a":1}'; });
    expect(cmd).toEqual({
      kind: 'fetch', profile: 'x', method: 'POST', url: 'https://x.com/api',
      headers: { 'Content-Type': 'application/json' }, body: '{"a":1}', json: false,
      inPage: false, noCredentials: false,
    });
  });

  it('post-json rejects invalid JSON bodies', () => {
    expect(() => parseCliArgs(['post-json', 'https://x.com/a', 'not json', '-p', 'x']))
      .toThrow(UsageError);
  });

  it('parses read verbs with keys and storage-domain', () => {
    expect(parseCliArgs(['local-storage', 'tok', '-p', 'hb', '--storage-domain', 'hbportal.co']))
      .toEqual({ kind: 'read', profile: 'hb', bucket: 'localStorage', keys: ['tok'],
        storageDomain: 'hbportal.co', storageSubdomain: undefined });
  });

  it('requires -p on verb commands', () => {
    expect(() => parseCliArgs(['get', 'https://x.com/'])).toThrow(/--profile/);
  });

  it('rejects unknown commands with a UsageError', () => {
    expect(() => parseCliArgs(['frobnicate'])).toThrow(UsageError);
  });

  it('parses --version and -v to the version command', () => {
    expect(parseCliArgs(['--version'])).toEqual({ kind: 'version' });
    expect(parseCliArgs(['-v'])).toEqual({ kind: 'version' });
  });

  it('rejects unknown flags with a UsageError, not a raw TypeError', () => {
    expect(() => parseCliArgs(['get', 'https://x.com/', '--bogus', '-p', 'x'])).toThrow(UsageError);
  });
});

describe('parseCliArgs — --via-tab', () => {
  // API hosts serve no page, so the tab that relays the request has to be
  // nameable separately from the request's own host (#203).
  it.each([
    [['get', 'https://api.x.com/v1', '-p', 'x'], 'GET'],
    [['request', 'https://api.x.com/v1', '-p', 'x', '-X', 'PUT'], 'PUT'],
  ])('threads it through %j', (argv, method) => {
    const cmd = parseCliArgs([...argv, '--via-tab', 'https://www.x.com/']);
    expect(cmd).toMatchObject({ kind: 'fetch', method, viaTab: 'https://www.x.com/' });
  });

  it('threads it through post-json', () => {
    const cmd = parseCliArgs(
      ['post-json', 'https://api.x.com/gql', '{"a":1}', '-p', 'x', '--via-tab', 'https://www.x.com/'],
    );
    expect(cmd).toMatchObject({ kind: 'fetch', method: 'POST', viaTab: 'https://www.x.com/' });
  });

  it('is absent when not passed, so the request host stays the default', () => {
    const cmd = parseCliArgs(['get', 'https://api.x.com/v1', '-p', 'x']);
    expect((cmd as { viaTab?: string }).viaTab).toBeUndefined();
  });
});

describe('--in-page', () => {
  it('parses --in-page on get / post-json / request', () => {
    for (const argv of [
      ['get', 'https://x.com/a', '-p', 'x', '--in-page'],
      ['post-json', 'https://x.com/a', '{"a":1}', '-p', 'x', '--in-page'],
      ['request', 'https://x.com/a', '-p', 'x', '--in-page'],
    ]) {
      const cmd = parseCliArgs(argv) as Extract<ReturnType<typeof parseCliArgs>, { kind: 'fetch' }>;
      expect(cmd.kind).toBe('fetch');
      expect(cmd.inPage, `--in-page lost on: ${argv[0]}`).toBe(true);
    }
  });

  it('parses --no-credentials on every fetch command', () => {
    for (const argv of [
      ['get', 'https://x.com/a', '-p', 'x', '--no-credentials'],
      ['post-json', 'https://x.com/a', '{"a":1}', '-p', 'x', '--no-credentials'],
      ['request', 'https://x.com/a', '-p', 'x', '--no-credentials'],
    ]) {
      const cmd = parseCliArgs(argv) as Extract<ReturnType<typeof parseCliArgs>, { kind: 'fetch' }>;
      expect(cmd.noCredentials, `--no-credentials lost on: ${argv[0]}`).toBe(true);
    }
  });

  it('defaults to false, so an ordinary fetch is byte-identical to before', () => {
    const cmd = parseCliArgs(['get', 'https://x.com/a', '-p', 'x']) as
      Extract<ReturnType<typeof parseCliArgs>, { kind: 'fetch' }>;
    expect(cmd.inPage).toBe(false);
  });

  it('parses profile declare --allow-in-page', () => {
    const cmd = parseCliArgs(['profile', 'declare', 'x', '--allow-in-page']) as
      Extract<ReturnType<typeof parseCliArgs>, { kind: 'profile-declare' }>;
    expect(cmd.inPage).toBe(true);
  });
});

describe('capture / write-cookies parsing', () => {
  const asCapture = (argv: string[]) =>
    parseCliArgs(argv) as Extract<ReturnType<typeof parseCliArgs>, { kind: 'capture' }>;
  const asWrite = (argv: string[]) =>
    parseCliArgs(argv) as Extract<ReturnType<typeof parseCliArgs>, { kind: 'write-cookies' }>;

  it('parses capture with no names as "every declared header"', () => {
    const cmd = asCapture(['capture', '-p', 'x']);
    expect(cmd.names).toEqual([]);
    expect(cmd.timeoutMs).toBeUndefined();
  });

  it('parses named captures', () => {
    expect(asCapture(['capture', 'authorization@api.x.com', '-p', 'x']).names)
      .toEqual(['authorization@api.x.com']);
  });

  // SECONDS on the command line, milliseconds internally — like every other
  // timeout the CLI takes.
  it('converts --capture-timeout from seconds to milliseconds', () => {
    expect(asCapture(['capture', '-p', 'x', '--capture-timeout', '45']).timeoutMs).toBe(45_000);
    expect(asCapture(['capture', '-p', 'x', '--capture-timeout', '2.5']).timeoutMs).toBe(2_500);
  });

  it('refuses a --capture-timeout that is not a positive number', () => {
    for (const bad of ['0', '-5', 'soon', '']) {
      expect(() => asCapture(['capture', '-p', 'x', '--capture-timeout', bad]), bad)
        .toThrow(UsageError);
    }
  });

  it('parses name=value pairs, keeping "=" inside the value', () => {
    const cmd = asWrite(['write-cookies', 'sid=abc', 'tok=a=b=c', '-p', 'x']);
    expect(cmd.cookies).toEqual({ sid: 'abc', tok: 'a=b=c' });
  });

  it('accepts an empty value but refuses a missing or empty name', () => {
    expect(asWrite(['write-cookies', 'sid=', '-p', 'x']).cookies).toEqual({ sid: '' });
    for (const bad of ['sid', '=abc', '']) {
      expect(() => asWrite(['write-cookies', bad, '-p', 'x']), bad).toThrow(UsageError);
    }
  });

  it('carries the storage scope through', () => {
    const cmd = asWrite([
      'write-cookies', 'sid=a', '-p', 'x', '--storage-domain', 'd.com', '--storage-subdomain', 's',
    ]);
    expect(cmd.storageDomain).toBe('d.com');
    expect(cmd.storageSubdomain).toBe('s');
  });
});
