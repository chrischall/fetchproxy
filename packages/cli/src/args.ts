import { readFileSync, readSync } from 'node:fs';
import { parseArgs } from 'node:util';
import type { CaptureHeaderDecl, DomSelectorDecl, GraphqlOpDeclaration } from '@fetchproxy/protocol';
import { UsageError } from './output.js';

export type Bucket = 'cookies' | 'localStorage' | 'sessionStorage' | 'indexedDb';

export type Command =
  | { kind: 'help' }
  | { kind: 'version' }
  | { kind: 'profile-list' }
  | { kind: 'profile-show'; name: string }
  | { kind: 'profile-remove'; name: string }
  | { kind: 'profile-add'; name: string; domains: string[] }
  | { kind: 'profile-declare'; name: string; cookies: string[]; localStorage: string[];
      sessionStorage: string[]; captureHeaders: CaptureHeaderDecl[];
      domSelectors: DomSelectorDecl[]; download: boolean; cookieWrite: boolean;
      inPage: boolean; captureRedirect: boolean; graphqlOps: GraphqlOpDeclaration[] }
  | { kind: 'pair'; profile: string; domain?: string; subdomain?: string }
  | { kind: 'health'; profile: string }
  | { kind: 'trust'; action: 'list'; json: boolean }
  | { kind: 'trust'; action: 'clear'; serverName?: string; all?: boolean }
  | { kind: 'fetch'; profile: string; method: string; url: string;
      headers: Record<string, string>; body?: string; json: boolean; viaTab?: string;
      inPage: boolean; noCredentials: boolean }
  | { kind: 'read'; profile: string; bucket: Bucket; keys: string[];
      storageDomain?: string; storageSubdomain?: string }
  | { kind: 'session'; profile: string; storageDomain?: string; storageSubdomain?: string }
  | { kind: 'dom'; profile: string; names: string[];
      storageDomain?: string; storageSubdomain?: string }
  | { kind: 'download'; profile: string; url: string; filename?: string }
  | { kind: 'capture'; profile: string; names: string[]; timeoutMs?: number }
  | {
      kind: 'write-cookies'; profile: string; cookies: Record<string, string>;
      storageDomain?: string; storageSubdomain?: string;
    }
  | { kind: 'capture-redirect'; profile: string; host: string; path?: string; timeoutMs?: number }
  | {
      kind: 'graphql'; profile: string; name: string;
      variables: Record<string, unknown>; viaTab?: string;
    };

const READ_BUCKETS: Record<string, Bucket> = {
  cookies: 'cookies',
  'local-storage': 'localStorage',
  'session-storage': 'sessionStorage',
  indexeddb: 'indexedDb',
};

function parseHeaderFlag(raw: string): [string, string] {
  const colon = raw.indexOf(':');
  if (colon <= 0) throw new UsageError(`-H expects 'Name: value', got ${JSON.stringify(raw)}`);
  return [raw.slice(0, colon).trim(), raw.slice(colon + 1).trim()];
}

function parseCaptureHeaderFlag(raw: string): CaptureHeaderDecl {
  const at = raw.indexOf('@');
  if (at <= 0 || at === raw.length - 1) {
    throw new UsageError(
      `--capture-header expects 'header-name@host[/path]', got ${JSON.stringify(raw)}`,
    );
  }
  const headerName = raw.slice(0, at);
  const rest = raw.slice(at + 1);
  const slash = rest.indexOf('/');
  if (slash === -1) return { headerName, host: rest };
  return { headerName, host: rest.slice(0, slash), path: rest.slice(slash) };
}

function parseDomSelectorFlag(raw: string): DomSelectorDecl {
  const eq = raw.indexOf('=');
  if (eq <= 0 || eq === raw.length - 1) {
    throw new UsageError(`--dom-selector expects 'handle=css-selector', got ${JSON.stringify(raw)}`);
  }
  return { name: raw.slice(0, eq), selector: raw.slice(eq + 1) };
}

function parseGraphqlOpFlag(raw: string): GraphqlOpDeclaration {
  const eq = raw.indexOf('=');
  if (eq <= 0 || eq === raw.length - 1) {
    throw new UsageError(
      `--graphql-op expects 'handle=OperationName', got ${JSON.stringify(raw)}`,
    );
  }
  return { name: raw.slice(0, eq), operationName: raw.slice(eq + 1) };
}

/**
 * `--var k=v`, repeated. Values are parsed as JSON when they parse, and kept
 * as a string when they do not — so `--var first=10` is the NUMBER a GraphQL
 * variable usually wants, while `--var slug=idlewild` stays a string without
 * anyone quoting it on the command line.
 */
function parseVarFlag(raw: string): [string, unknown] {
  const eq = raw.indexOf('=');
  if (eq <= 0) {
    throw new UsageError(`--var expects 'name=value', got ${JSON.stringify(raw)}`);
  }
  const name = raw.slice(0, eq);
  const text = raw.slice(eq + 1);
  try {
    return [name, JSON.parse(text)];
  } catch {
    return [name, text];
  }
}

/**
 * `--capture-timeout`, in SECONDS on the command line and milliseconds
 * everywhere inside. Shared by `capture` and `capture-redirect` rather than
 * copied: two parsers for one flag drift, and the direction that hurts is one
 * of them silently accepting a value the other rejects.
 */
function parseCaptureTimeoutFlag(raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  const secs = Number(raw);
  if (!Number.isFinite(secs) || secs <= 0) {
    throw new UsageError(`--capture-timeout expects seconds, got ${JSON.stringify(raw)}`);
  }
  return Math.round(secs * 1000);
}

function resolveBody(raw: string, readFile: (p: string) => string): string {
  return raw.startsWith('@') ? readFile(raw.slice(1)) : raw;
}

/**
 * EXACTLY ONE trailing line ending comes off a file-read cookie value — a
 * `\n`, or the `\r\n` of a CRLF — and nothing else.
 *
 * Stripping one rather than none because `echo "$v" > f` is how the value
 * gets into the file nine times out of ten, and a cookie carrying a stray
 * newline fails in a way that is hard to see: the write is accepted, the site
 * rejects the session, and nothing in between prints the character. Stripping
 * one rather than trimming because a value with spaces at either end is still
 * that value; only the line ending the shell added is assumed not to be. A
 * value that genuinely ends in a newline keeps it by ending the file with two.
 */
function stripOneTrailingNewline(text: string): string {
  if (text.endsWith('\r\n')) return text.slice(0, -2);
  if (text.endsWith('\n')) return text.slice(0, -1);
  return text;
}

/**
 * One `name=value` cookie pair off the command line. The value may be
 * `@<path>`, read from that file: typed on argv a live session cookie lands
 * in shell history, in `ps` output, and in `/proc/<pid>/cmdline`, and moving
 * a live credential is the whole of what this verb does.
 *
 * The split is at the FIRST `=`, so a value may hold as many more as it likes;
 * the name may not be empty, the value may.
 */
function parseCookiePair(raw: string, readFile: (p: string) => string): [string, string] {
  const eq = raw.indexOf('=');
  if (eq <= 0) {
    throw new UsageError(`fpx write-cookies expects name=value, got ${JSON.stringify(raw)}`);
  }
  const name = raw.slice(0, eq);
  const value = raw.slice(eq + 1);
  if (!value.startsWith('@')) return [name, value];
  const path = value.slice(1);
  if (path.length === 0) {
    throw new UsageError(
      `fpx write-cookies: ${JSON.stringify(name)}=@ names no file`,
      'pass name=@path/to/value — or --from-stdin, where a value starting with @ is literal',
    );
  }
  let text: string;
  try {
    text = readFile(path);
  } catch (e) {
    // A file that cannot be read is the operator's mistake, not the bridge's:
    // exit 1, and named, since the value never appears anywhere to compare.
    throw new UsageError(
      `fpx write-cookies: cannot read ${JSON.stringify(path)} for cookie ` +
        `${JSON.stringify(name)}: ${(e as Error).message}`,
    );
  }
  return [name, stripOneTrailingNewline(text)];
}

/**
 * `--from-stdin`: the whole set, one `name=value` per line.
 *
 * Values here are LITERAL — no `@file` indirection. Stdin is already off the
 * command line, so a second level of magic would buy nothing and would make a
 * value that genuinely starts with `@` unwritable. Blank lines are skipped,
 * which is what makes the stream's own terminating newline a terminator
 * rather than an empty pair, and a trailing `\r` is dropped so a CRLF stream
 * writes the same cookies a LF one does.
 *
 * A malformed line is reported by NUMBER and never quoted: a line that is not
 * a pair is, as often as not, a value pasted without its name, and an error
 * message is the one place a credential must not turn up.
 */
function parseCookieSet(text: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  text.split('\n').forEach((rawLine, i) => {
    const line = rawLine.endsWith('\r') ? rawLine.slice(0, -1) : rawLine;
    if (line.length === 0) return;
    const eq = line.indexOf('=');
    if (eq <= 0) {
      throw new UsageError(
        `fpx write-cookies: stdin line ${i + 1} is not name=value`,
        'one name=value per line — the line itself is not echoed, in case it is a value',
      );
    }
    cookies[line.slice(0, eq)] = line.slice(eq + 1);
  });
  return cookies;
}

function requireProfile(profile: string | undefined): string {
  if (!profile) throw new UsageError('this command requires -p/--profile <name>');
  return profile;
}

const STDIN_HINT =
  'pipe the set in, e.g. printf \'sid=%s\\n\' "$SID" | fpx write-cookies --from-stdin -p <name>';

/**
 * Drain a descriptor to EOF, synchronously, WAITING for the writer.
 *
 * `readFileSync(fd)` is the obvious spelling and is the wrong one here. Node
 * puts fd 0 into non-blocking mode as soon as anything touches
 * `process.stdin` — the terminal check below does — so a single read against
 * a pipe whose producer has not written yet returns EAGAIN instead of
 * waiting. Every producer this flag exists for is slower than the child's
 * first read (`op read op://…`, `gpg -d`, `pass show`, a curl, any script);
 * only `printf … | fpx`, which has already written by then, is fast enough to
 * make one attempt look like it works. So the read is a LOOP: EAGAIN sleeps
 * and retries, zero bytes or EOF ends it, and every chunk is kept — a set
 * larger than one buffer arrives in pieces.
 *
 * `Atomics.wait` is the sleep because it is the only synchronous one Node
 * has, and this parser is synchronous: the set is wanted before anything
 * dials the bridge.
 */
function drainFdSync(fd: number): string {
  const chunks: Buffer[] = [];
  const buf = Buffer.alloc(64 * 1024);
  const idle = new Int32Array(new SharedArrayBuffer(4));
  for (;;) {
    let n: number;
    try {
      n = readSync(fd, buf, 0, buf.length, null);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === 'EAGAIN') {
        Atomics.wait(idle, 0, 0, 5);
        continue;
      }
      if (code === 'EOF') break;
      throw e;
    }
    if (n === 0) break;
    chunks.push(Buffer.from(buf.subarray(0, n)));
  }
  return Buffer.concat(chunks).toString('utf8');
}

/**
 * The whole of stdin, read synchronously because this parser is synchronous
 * and the set is wanted before anything dials the bridge.
 *
 * A terminal is refused rather than read: nothing closes it, so the loop
 * above would spin forever with nothing on screen to say why. A redirect or a
 * pipe is not a terminal, so the forms this flag exists for are untouched.
 *
 * A read that genuinely fails — EBADF, EIO — becomes a `UsageError`, the same
 * shape `parseCookiePair` gives an unreadable `@file`: left raw it reaches
 * `runCli`'s catch-all and exits 2, "bridge unavailable", which points at the
 * browser for a problem that is entirely on this side of it.
 *
 * `fd` is a parameter only so a test can point the reader at a descriptor it
 * controls; production reads 0.
 */
export function readStdinSync(fd = 0): string {
  if (process.stdin.isTTY) {
    throw new UsageError('--from-stdin found a terminal, not a pipe or a redirect', STDIN_HINT);
  }
  try {
    return drainFdSync(fd);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    throw new UsageError(
      `fpx write-cookies: cannot read stdin: ${err.code ?? ''} ${err.message}`.replace(/\s+/g, ' ').trim(),
      STDIN_HINT,
    );
  }
}

export function parseCliArgs(
  argv: string[],
  readFile: (p: string) => string = (p) => readFileSync(p, 'utf8'),
  readStdin: () => string = readStdinSync,
): Command {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        profile: { type: 'string', short: 'p' },
        json: { type: 'boolean', default: false },
        all: { type: 'boolean', default: false },
        header: { type: 'string', short: 'H', multiple: true, default: [] },
        data: { type: 'string', short: 'd' },
        method: { type: 'string', short: 'X' },
        domain: { type: 'string', multiple: true, default: [] },
        cookie: { type: 'string', multiple: true, default: [] },
        'local-storage': { type: 'string', multiple: true, default: [] },
        'session-storage': { type: 'string', multiple: true, default: [] },
        'capture-header': { type: 'string', multiple: true, default: [] },
        'dom-selector': { type: 'string', multiple: true, default: [] },
        'allow-download': { type: 'boolean', default: false },
        'allow-cookie-write': { type: 'boolean', default: false },
        'allow-in-page': { type: 'boolean', default: false },
        'allow-capture-redirect': { type: 'boolean', default: false },
        'graphql-op': { type: 'string', multiple: true, default: [] },
        var: { type: 'string', multiple: true, default: [] },
        filename: { type: 'string' },
        'from-stdin': { type: 'boolean', default: false },
        'storage-domain': { type: 'string' },
        'storage-subdomain': { type: 'string' },
        'via-tab': { type: 'string' },
        'in-page': { type: 'boolean', default: false },
        'no-credentials': { type: 'boolean', default: false },
        // SECONDS on the command line, like every other timeout the CLI takes.
        'capture-timeout': { type: 'string' },
        subdomain: { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
        version: { type: 'boolean', short: 'v', default: false },
      },
    });
  } catch (e) {
    // parseArgs throws TypeError on unknown/malformed flags — that's a
    // usage problem (exit 1), not a bridge failure (exit 2).
    throw new UsageError((e as Error).message, 'run: fpx --help');
  }
  const { values, positionals } = parsed;
  if (values.version) return { kind: 'version' };
  if (values.help || positionals[0] === 'help' || positionals.length === 0) return { kind: 'help' };

  const [cmd, ...rest] = positionals;
  const headers: Record<string, string> = {};
  for (const raw of values.header ?? []) {
    const [k, v] = parseHeaderFlag(raw);
    headers[k] = v;
  }

  if (cmd === 'profile') {
    const [sub, name] = rest;
    if (sub === 'list') return { kind: 'profile-list' };
    if (!name) throw new UsageError(`fpx profile ${sub ?? ''} requires a profile name`);
    if (sub === 'show') return { kind: 'profile-show', name };
    if (sub === 'remove') return { kind: 'profile-remove', name };
    if (sub === 'add') {
      const domains = values.domain ?? [];
      if (domains.length === 0) {
        throw new UsageError('fpx profile add requires at least one --domain');
      }
      return { kind: 'profile-add', name, domains };
    }
    if (sub === 'declare') {
      return {
        kind: 'profile-declare',
        name,
        cookies: values.cookie ?? [],
        localStorage: values['local-storage'] ?? [],
        sessionStorage: values['session-storage'] ?? [],
        captureHeaders: (values['capture-header'] ?? []).map(parseCaptureHeaderFlag),
        domSelectors: (values['dom-selector'] ?? []).map(parseDomSelectorFlag),
        download: values['allow-download'] ?? false,
        cookieWrite: values['allow-cookie-write'] ?? false,
        inPage: values['allow-in-page'] ?? false,
        captureRedirect: values['allow-capture-redirect'] ?? false,
        graphqlOps: (values['graphql-op'] ?? []).map(parseGraphqlOpFlag),
      };
    }
    throw new UsageError(`unknown profile subcommand ${JSON.stringify(sub)}`,
      'expected: add | declare | list | show | remove');
  }

  if (cmd === 'pair') {
    return {
      kind: 'pair',
      profile: requireProfile(values.profile),
      domain: values.domain?.[0],
      subdomain: values.subdomain,
    };
  }
  if (cmd === 'health') return { kind: 'health', profile: requireProfile(values.profile) };
  if (cmd === 'trust') {
    const sub = rest[0];
    if (sub === 'list' || sub === undefined) {
      return { kind: 'trust', action: 'list', json: values.json ?? false };
    }
    if (sub === 'clear') {
      // A bare `clear` is refused: dropping every pin is a real decision (a
      // fleet re-pairs on the next connection), so it takes saying `--all`
      // rather than happening by omitting an argument.
      const named = rest[1];
      if (values.all) {
        // Naming a server AND asking for all of them is two different
        // intentions in one command; silently doing the broader one is the
        // wrong guess to make about a security control.
        if (named) {
          throw new UsageError(
            'fpx trust clear takes a server name or --all, not both',
            `drop just one with: fpx trust clear ${named}`,
          );
        }
        return { kind: 'trust', action: 'clear', all: true };
      }
      const serverName = named;
      if (!serverName) {
        throw new UsageError(
          'fpx trust clear requires a server name (or --all)',
          'e.g. fpx trust clear opentable-mcp — --all re-pairs every MCP, which is what an extension re-install needs',
        );
      }
      return { kind: 'trust', action: 'clear', serverName };
    }
    throw new UsageError(`unknown trust subcommand ${JSON.stringify(sub)}`, 'expected: list | clear <server-name>');
  }
  if (cmd === 'session') {
    return {
      kind: 'session', profile: requireProfile(values.profile),
      storageDomain: values['storage-domain'], storageSubdomain: values['storage-subdomain'],
    };
  }
  if (cmd === 'dom') {
    return {
      kind: 'dom', profile: requireProfile(values.profile), names: rest,
      storageDomain: values['storage-domain'], storageSubdomain: values['storage-subdomain'],
    };
  }
  if (cmd === 'capture') {
    const timeoutMs = parseCaptureTimeoutFlag(values['capture-timeout']);
    return {
      kind: 'capture', profile: requireProfile(values.profile), names: rest,
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    };
  }

  if (cmd === 'capture-redirect') {
    const target = rest[0];
    if (!target) throw new UsageError('fpx capture-redirect requires <host>[/path]');
    const slash = target.indexOf('/');
    const host = slash === -1 ? target : target.slice(0, slash);
    const path = slash === -1 ? undefined : target.slice(slash);
    if (host.length === 0) {
      throw new UsageError(`fpx capture-redirect: no host in ${JSON.stringify(target)}`);
    }
    const timeoutMs = parseCaptureTimeoutFlag(values['capture-timeout']);
    return {
      kind: 'capture-redirect', profile: requireProfile(values.profile), host,
      ...(path !== undefined ? { path } : {}),
      ...(timeoutMs !== undefined ? { timeoutMs } : {}),
    };
  }

  if (cmd === 'graphql') {
    const name = rest[0];
    if (!name) throw new UsageError('fpx graphql requires a declared operation handle');
    const variables: Record<string, unknown> = {};
    for (const raw of values.var ?? []) {
      const [k, v] = parseVarFlag(raw);
      variables[k] = v;
    }
    return {
      kind: 'graphql', profile: requireProfile(values.profile), name, variables,
      viaTab: values['via-tab'],
    };
  }

  if (cmd === 'write-cookies') {
    let cookies: Record<string, string> = {};
    if (values['from-stdin']) {
      // Two sources for one set is two intentions in one command, and the
      // precedence between them would be invisible in the scrollback — so it
      // is refused rather than guessed at, as `trust clear <name> --all` is.
      if (rest.length > 0) {
        throw new UsageError(
          'fpx write-cookies takes pairs on the command line or --from-stdin, not both',
          'put every pair on stdin, or drop --from-stdin',
        );
      }
      cookies = parseCookieSet(readStdin());
    } else {
      for (const pair of rest) {
        const [name, value] = parseCookiePair(pair, readFile);
        cookies[name] = value;
      }
    }
    return {
      kind: 'write-cookies', profile: requireProfile(values.profile), cookies,
      storageDomain: values['storage-domain'], storageSubdomain: values['storage-subdomain'],
    };
  }

  if (cmd === 'download') {
    const url = rest[0];
    if (!url) throw new UsageError('fpx download requires a URL');
    return {
      kind: 'download', profile: requireProfile(values.profile), url,
      filename: values.filename,
    };
  }

  if (typeof cmd === 'string') {
    const bucket = READ_BUCKETS[cmd];
    if (bucket !== undefined) {
      return {
        kind: 'read', profile: requireProfile(values.profile), bucket,
        keys: rest,
        storageDomain: values['storage-domain'], storageSubdomain: values['storage-subdomain'],
      };
    }
  }

  if (cmd === 'get' || cmd === 'post-json' || cmd === 'request') {
    const url = rest[0];
    if (!url) throw new UsageError(`fpx ${cmd} requires a URL`);
    const profile = requireProfile(values.profile);
    if (cmd === 'get') {
      return { kind: 'fetch', profile, method: 'GET', url, headers, body: undefined,
        json: values.json ?? false, viaTab: values['via-tab'],
        inPage: values['in-page'] ?? false,
        noCredentials: values['no-credentials'] ?? false };
    }
    if (cmd === 'post-json') {
      const rawBody = rest[1];
      if (rawBody === undefined) {
        throw new UsageError('fpx post-json requires a body argument (literal JSON or @file)');
      }
      const body = resolveBody(rawBody, readFile);
      try {
        JSON.parse(body);
      } catch {
        throw new UsageError('post-json body is not valid JSON', 'pass literal JSON or @file');
      }
      const hasContentType = Object.keys(headers).some((k) => k.toLowerCase() === 'content-type');
      if (!hasContentType) headers['Content-Type'] = 'application/json';
      return { kind: 'fetch', profile, method: 'POST', url, headers, body,
        json: values.json ?? false, viaTab: values['via-tab'],
        inPage: values['in-page'] ?? false,
        noCredentials: values['no-credentials'] ?? false };
    }
    const body = values.data === undefined ? undefined : resolveBody(values.data, readFile);
    return { kind: 'fetch', profile, method: (values.method ?? 'GET').toUpperCase(), url,
      headers, body, json: values.json ?? false, viaTab: values['via-tab'],
      inPage: values['in-page'] ?? false,
      noCredentials: values['no-credentials'] ?? false };
  }

  throw new UsageError(`unknown command ${JSON.stringify(cmd)}`, 'run: fpx --help');
}
