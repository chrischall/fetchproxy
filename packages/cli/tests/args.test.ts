import { describe, it, expect } from 'vitest';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseCliArgs, readStdinSync } from '../src/args.js';
import { UsageError } from '../src/output.js';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));
const stdinChild = fileURLToPath(new URL('./fixtures/from-stdin-child.ts', import.meta.url));

/**
 * Run the parser's REAL default stdin reader against a REAL pipe, with the
 * producer writing only after `delayMs`. The delay is the whole test: every
 * realistic producer for this flag (`op read`, `gpg -d`, `pass show`, a curl)
 * is slower than the child's first read, and a reader that does not wait loses
 * the set with an EAGAIN that reads like a bridge failure.
 */
function parseFromRealPipe(
  chunks: string[],
  delayMs: number,
): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--import', 'tsx', stdinChild], {
      cwd: repoRoot,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = ''; let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d: string) => { stdout += d; });
    child.stderr.on('data', (d: string) => { stderr += d; });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    // A child that gives up on the read closes the pipe under us; let the
    // assertions report that rather than an unhandled EPIPE.
    child.stdin.on('error', () => {});
    setTimeout(() => {
      for (const c of chunks) child.stdin.write(c);
      child.stdin.end();
    }, delayMs);
  });
}

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
      captureRedirect: false, graphqlOps: [],
    });
  });

  it('parses profile declare with --dom-selector and --allow-download', () => {
    const cmd = parseCliArgs(['profile', 'declare', 'r',
      '--dom-selector', 'title=h1.title', '--allow-download']);
    expect(cmd).toEqual({
      kind: 'profile-declare', name: 'r', cookies: [], localStorage: [], sessionStorage: [],
      captureHeaders: [], domSelectors: [{ name: 'title', selector: 'h1.title' }], download: true,
      cookieWrite: false, inPage: false, captureRedirect: false, graphqlOps: [],
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

/**
 * A cookie value must not have to sit in a shell command: on argv it lands in
 * shell history, in `ps` output, and in `/proc/<pid>/cmdline`. These two forms
 * are the ways to keep a live session cookie off the command line.
 */
describe('write-cookies value sources', () => {
  const asWrite = (
    argv: string[],
    readFile?: (p: string) => string,
    readStdin?: () => string,
  ) =>
    parseCliArgs(argv, readFile, readStdin) as
      Extract<ReturnType<typeof parseCliArgs>, { kind: 'write-cookies' }>;

  describe('name=@file', () => {
    it('reads the value out of the file instead of argv', () => {
      const cmd = asWrite(['write-cookies', 'sid=@/tmp/sid.txt', '-p', 'x'], (p) => {
        expect(p).toBe('/tmp/sid.txt');
        return 'abc123';
      });
      expect(cmd.cookies).toEqual({ sid: 'abc123' });
    });

    // Documented: EXACTLY ONE trailing line ending is stripped, so
    // `printf %s` and `echo` write the same cookie.
    it('strips exactly one trailing newline, CRLF included', () => {
      expect(asWrite(['write-cookies', 'a=@f', '-p', 'x'], () => 'v\n').cookies).toEqual({ a: 'v' });
      expect(asWrite(['write-cookies', 'a=@f', '-p', 'x'], () => 'v\r\n').cookies)
        .toEqual({ a: 'v' });
      expect(asWrite(['write-cookies', 'a=@f', '-p', 'x'], () => 'v').cookies).toEqual({ a: 'v' });
    });

    it('keeps a newline the value really ends with, when the file ends with two', () => {
      expect(asWrite(['write-cookies', 'a=@f', '-p', 'x'], () => 'v\n\n').cookies)
        .toEqual({ a: 'v\n' });
    });

    it('keeps "=" and whitespace inside the value, and trims neither end', () => {
      expect(asWrite(['write-cookies', 'tok=@f', '-p', 'x'], () => 'a=b=c\n').cookies)
        .toEqual({ tok: 'a=b=c' });
      expect(asWrite(['write-cookies', 'tok=@f', '-p', 'x'], () => ' a b \tc \n').cookies)
        .toEqual({ tok: ' a b \tc ' });
    });

    it('reports an unreadable file as a usage error naming the path', () => {
      expect(() => asWrite(['write-cookies', 'sid=@nope.txt', '-p', 'x'], () => {
        throw new Error('ENOENT: no such file or directory');
      })).toThrow(/nope\.txt/);
      expect(() => asWrite(['write-cookies', 'sid=@nope.txt', '-p', 'x'], () => {
        throw new Error('ENOENT');
      })).toThrow(UsageError);
    });

    it('refuses an empty path', () => {
      expect(() => asWrite(['write-cookies', 'sid=@', '-p', 'x'], () => 'v'))
        .toThrow(UsageError);
    });
  });

  describe('--from-stdin', () => {
    it('reads one name=value per line and ignores the terminating newline', () => {
      const cmd = asWrite(['write-cookies', '-p', 'x', '--from-stdin'], undefined,
        () => 'sid=abc\ntok=def\n');
      expect(cmd.cookies).toEqual({ sid: 'abc', tok: 'def' });
    });

    it('keeps "=" and whitespace in a value, and tolerates CRLF', () => {
      const cmd = asWrite(['write-cookies', '-p', 'x', '--from-stdin'], undefined,
        () => 'tok=a=b=c\r\nspaced= two words \r\n');
      expect(cmd.cookies).toEqual({ tok: 'a=b=c', spaced: ' two words ' });
    });

    // Values here are LITERAL: stdin is already off argv, so a second
    // indirection would only make a value that starts with "@" unwritable.
    it('takes an @ value literally rather than as a file', () => {
      const cmd = asWrite(['write-cookies', '-p', 'x', '--from-stdin'],
        () => { throw new Error('readFile must not be called'); },
        () => 'sid=@not-a-file\n');
      expect(cmd.cookies).toEqual({ sid: '@not-a-file' });
    });

    it('skips blank lines', () => {
      const cmd = asWrite(['write-cookies', '-p', 'x', '--from-stdin'], undefined,
        () => '\nsid=abc\n\n');
      expect(cmd.cookies).toEqual({ sid: 'abc' });
    });

    it('names the line number and never echoes a malformed line', () => {
      let message = '';
      try {
        asWrite(['write-cookies', '-p', 'x', '--from-stdin'], undefined,
          () => 'sid=abc\nsupersecret\n');
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toMatch(/line 2/);
      expect(message).not.toMatch(/supersecret/);
    });

    it('refuses pairs on argv alongside it', () => {
      expect(() => asWrite(['write-cookies', 'sid=a', '-p', 'x', '--from-stdin'], undefined,
        () => 'tok=b\n')).toThrow(UsageError);
    });

    /**
     * The defect this exists for: `readFileSync(0)` makes ONE read attempt,
     * and Node has already put fd 0 into non-blocking mode by the time the
     * parser touches `process.stdin`, so a producer that has not written yet
     * comes back EAGAIN rather than waiting. An immediate write passes either
     * way and proves nothing; the delay is the test.
     */
    it('waits for a slow producer instead of failing the read', async () => {
      const r = await parseFromRealPipe(['sid=abc\n'], 300);
      expect(r.stderr).toBe('');
      expect(r.code).toBe(0);
      expect(JSON.parse(r.stdout)).toEqual({ sid: 'abc' });
    }, 30_000);

    // And it keeps reading: a set bigger than one read buffer, arriving in
    // pieces, is one set rather than whichever piece landed first.
    it('accumulates a set that arrives in several chunks', async () => {
      const big = 'x'.repeat(200_000);
      const r = await parseFromRealPipe(['sid=ab', 'c\ntok=', big, '\n'], 200);
      expect(r.stderr).toBe('');
      expect(r.code).toBe(0);
      expect(JSON.parse(r.stdout)).toEqual({ sid: 'abc', tok: big });
    }, 30_000);

    /**
     * A read that genuinely fails is the operator's problem, not the bridge's.
     * Left raw it escapes as an `Error`, which `runCli` maps to exit 2,
     * "bridge unavailable" — the same mis-mapping the `@file` half goes out of
     * its way to avoid one function away.
     */
    it('reports an unreadable stdin as a usage error naming stdin', () => {
      let thrown: unknown;
      try { readStdinSync(2 ** 30); } catch (e) { thrown = e; }
      expect(thrown).toBeInstanceOf(UsageError);
      expect((thrown as Error).message).toMatch(/stdin/);
      expect((thrown as Error).message).toMatch(/EBADF/);
    });

    it('carries the storage scope through', () => {
      const cmd = asWrite(['write-cookies', '-p', 'x', '--from-stdin', '--storage-domain', 'd.com'],
        undefined, () => 'sid=a\n');
      expect(cmd.storageDomain).toBe('d.com');
    });

    /**
     * stdin is a ONE-SHOT pipe carrying a live session cookie: once drained it
     * cannot be re-read, and the shell that produced it has already exited. So
     * a check that needs nothing from it has to be made FIRST. Parsing used to
     * read the pipe and only then evaluate `requireProfile`, which sits in the
     * RETURNED object literal — so `--from-stdin` with no `-p` spent the
     * user's secret to reach a usage error that could have been raised before
     * the pipe was touched: the command did nothing and the cookie was gone.
     * Asserting the error alone cannot see that, so the READER is what is
     * asserted on.
     */
    it('refuses a missing profile before the one-shot pipe is drained', () => {
      let reads = 0;
      const drain = () => { reads += 1; return 'sid=abc\n'; };
      expect(() => asWrite(['write-cookies', '--from-stdin'], undefined, drain))
        .toThrow(UsageError);
      expect(() => asWrite(['write-cookies', '--from-stdin'], undefined, drain))
        .toThrow(/-p\/--profile/);
      expect(reads).toBe(0);
    });

    // The same rule for the other indirection. `name=@file` is re-readable
    // rather than one-shot, but a missing profile is knowable without the
    // disk either way, and the two branches are one command's two spellings.
    it('refuses a missing profile before an @file value is read', () => {
      let reads = 0;
      expect(() => asWrite(['write-cookies', 'sid=@/tmp/sid.txt'],
        () => { reads += 1; return 'abc'; })).toThrow(UsageError);
      expect(reads).toBe(0);
    });

    // A terminal never reaches EOF on its own, so the default reader would
    // block with nothing on screen to say why. Refusing is the only outcome
    // that can be diagnosed from the scrollback.
    it('refuses a terminal rather than blocking on a read that never ends', () => {
      const was = process.stdin.isTTY;
      try {
        process.stdin.isTTY = true;
        expect(() => parseCliArgs(['write-cookies', '-p', 'x', '--from-stdin']))
          .toThrow(UsageError);
        expect(() => parseCliArgs(['write-cookies', '-p', 'x', '--from-stdin']))
          .toThrow(/terminal/i);
      } finally {
        process.stdin.isTTY = was;
      }
    });
  });
});

describe('capture-redirect / graphql parsing', () => {
  const asRedirect = (argv: string[]) =>
    parseCliArgs(argv) as Extract<ReturnType<typeof parseCliArgs>, { kind: 'capture-redirect' }>;
  const asGraphql = (argv: string[]) =>
    parseCliArgs(argv) as Extract<ReturnType<typeof parseCliArgs>, { kind: 'graphql' }>;
  const asDeclare = (argv: string[]) =>
    parseCliArgs(argv) as Extract<ReturnType<typeof parseCliArgs>, { kind: 'profile-declare' }>;

  it('splits <host>/<path> at the FIRST slash, keeping the rest as the path', () => {
    const cmd = asRedirect(['capture-redirect', 'api.x.com/dl/a/b', '-p', 'x']);
    expect(cmd.host).toBe('api.x.com');
    expect(cmd.path).toBe('/dl/a/b');
  });

  it('leaves the path undefined when only a host is given', () => {
    expect(asRedirect(['capture-redirect', 'api.x.com', '-p', 'x']).path).toBeUndefined();
  });

  it('refuses a missing host or a leading slash', () => {
    expect(() => asRedirect(['capture-redirect', '-p', 'x'])).toThrow(UsageError);
    expect(() => asRedirect(['capture-redirect', '/nohost', '-p', 'x'])).toThrow(UsageError);
  });

  it('parses --allow-capture-redirect and --graphql-op', () => {
    const cmd = asDeclare([
      'profile', 'declare', 'x', '--allow-capture-redirect',
      '--graphql-op', 'avail=RestaurantsAvailability',
    ]);
    expect(cmd.captureRedirect).toBe(true);
    expect(cmd.graphqlOps).toEqual([{ name: 'avail', operationName: 'RestaurantsAvailability' }]);
  });

  it('refuses a malformed --graphql-op', () => {
    for (const bad of ['avail', '=Op', 'avail=']) {
      expect(() => asDeclare(['profile', 'declare', 'x', '--graphql-op', bad]), bad)
        .toThrow(UsageError);
    }
  });

  // JSON when it parses, string when it does not — so `first=10` is the NUMBER
  // a GraphQL variable usually wants, and `slug=idlewild` needs no quoting.
  it('types --var values as JSON where possible', () => {
    const cmd = asGraphql([
      'graphql', 'avail', '-p', 'x',
      '--var', 'first=10', '--var', 'slug=idlewild', '--var', 'deep={"a":[1]}',
      '--var', 'on=true', '--var', 'nil=null',
    ]);
    expect(cmd.variables).toEqual({
      first: 10, slug: 'idlewild', deep: { a: [1] }, on: true, nil: null,
    });
  });

  it('refuses a --var without a name', () => {
    for (const bad of ['=1', 'novalue']) {
      expect(() => asGraphql(['graphql', 'avail', '-p', 'x', '--var', bad]), bad)
        .toThrow(UsageError);
    }
  });

  it('requires an operation handle', () => {
    expect(() => asGraphql(['graphql', '-p', 'x'])).toThrow(UsageError);
  });
});
