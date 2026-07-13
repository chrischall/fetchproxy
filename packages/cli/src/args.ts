import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import type { CaptureHeaderDecl } from '@fetchproxy/protocol';
import { UsageError } from './output.js';

export type Bucket = 'cookies' | 'localStorage' | 'sessionStorage' | 'indexedDb';

export type Command =
  | { kind: 'help' }
  | { kind: 'profile-list' }
  | { kind: 'profile-show'; name: string }
  | { kind: 'profile-remove'; name: string }
  | { kind: 'profile-add'; name: string; domains: string[] }
  | { kind: 'profile-declare'; name: string; cookies: string[]; localStorage: string[];
      sessionStorage: string[]; captureHeaders: CaptureHeaderDecl[] }
  | { kind: 'pair'; profile: string; domain?: string }
  | { kind: 'health'; profile: string }
  | { kind: 'fetch'; profile: string; method: string; url: string;
      headers: Record<string, string>; body?: string; json: boolean }
  | { kind: 'read'; profile: string; bucket: Bucket; keys: string[];
      storageDomain?: string; storageSubdomain?: string }
  | { kind: 'session'; profile: string; storageDomain?: string; storageSubdomain?: string };

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

function resolveBody(raw: string, readFile: (p: string) => string): string {
  return raw.startsWith('@') ? readFile(raw.slice(1)) : raw;
}

function requireProfile(profile: string | undefined): string {
  if (!profile) throw new UsageError('this command requires -p/--profile <name>');
  return profile;
}

export function parseCliArgs(
  argv: string[],
  readFile: (p: string) => string = (p) => readFileSync(p, 'utf8'),
): Command {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        profile: { type: 'string', short: 'p' },
        json: { type: 'boolean', default: false },
        header: { type: 'string', short: 'H', multiple: true, default: [] },
        data: { type: 'string', short: 'd' },
        method: { type: 'string', short: 'X' },
        domain: { type: 'string', multiple: true, default: [] },
        cookie: { type: 'string', multiple: true, default: [] },
        'local-storage': { type: 'string', multiple: true, default: [] },
        'session-storage': { type: 'string', multiple: true, default: [] },
        'capture-header': { type: 'string', multiple: true, default: [] },
        'storage-domain': { type: 'string' },
        'storage-subdomain': { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    });
  } catch (e) {
    // parseArgs throws TypeError on unknown/malformed flags — that's a
    // usage problem (exit 1), not a bridge failure (exit 2).
    throw new UsageError((e as Error).message, 'run: fpx --help');
  }
  const { values, positionals } = parsed;
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
      };
    }
    throw new UsageError(`unknown profile subcommand ${JSON.stringify(sub)}`,
      'expected: add | declare | list | show | remove');
  }

  if (cmd === 'pair') {
    return { kind: 'pair', profile: requireProfile(values.profile), domain: values.domain?.[0] };
  }
  if (cmd === 'health') return { kind: 'health', profile: requireProfile(values.profile) };
  if (cmd === 'session') {
    return {
      kind: 'session', profile: requireProfile(values.profile),
      storageDomain: values['storage-domain'], storageSubdomain: values['storage-subdomain'],
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
        json: values.json ?? false };
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
        json: values.json ?? false };
    }
    const body = values.data === undefined ? undefined : resolveBody(values.data, readFile);
    return { kind: 'fetch', profile, method: (values.method ?? 'GET').toUpperCase(), url,
      headers, body, json: values.json ?? false };
  }

  throw new UsageError(`unknown command ${JSON.stringify(cmd)}`, 'run: fpx --help');
}
