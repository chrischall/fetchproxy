import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { CaptureHeaderDecl, DomSelectorDecl, IndexedDbScopeDecl } from '@fetchproxy/protocol';
import { UsageError } from './output.js';

export interface PointerDecl {
  outputKey: string;
  storageKey: string;
  jsonPointer: string;
}

/** One per-service trust scope. Shape mirrors bootstrap's `Declarations` plus `domains`. */
export interface Profile {
  domains: string[];
  cookies: string[];
  localStorage: string[];
  sessionStorage: string[];
  captureHeaders: CaptureHeaderDecl[];
  indexedDb: IndexedDbScopeDecl[];
  localStoragePointers: PointerDecl[];
  sessionStoragePointers: PointerDecl[];
  domSelectors: DomSelectorDecl[];
  download: boolean;
}

export function cliHome(env: Record<string, string | undefined> = process.env): string {
  return env.FETCHPROXY_CLI_HOME ?? join(homedir(), '.fetchproxy', 'cli');
}

export function identityPath(
  name: string,
  identityDir: string = join(homedir(), '.fetchproxy', 'identity'),
): string {
  return join(identityDir, `fpx-${name}.json`);
}

export function emptyProfile(domains: string[]): Profile {
  return {
    domains,
    cookies: [],
    localStorage: [],
    sessionStorage: [],
    captureHeaders: [],
    indexedDb: [],
    localStoragePointers: [],
    sessionStoragePointers: [],
    domSelectors: [],
    download: false,
  };
}

const isStringArray = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length > 0);

const isRecord = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v);

const hasStrings = (e: Record<string, unknown>, keys: readonly string[]): boolean =>
  keys.every((k) => typeof e[k] === 'string' && (e[k] as string).length > 0);

const optionalString = (v: unknown): boolean =>
  v === undefined || (typeof v === 'string' && v.length > 0);

/**
 * Per-element shape checks for the object arrays. These arrays are hand-edited
 * into profiles.json (only --capture-header and --dom-selector have flags), so
 * `Array.isArray` alone let a typo through here and surface much later as a
 * ProtocolError from the extension's hello validator, mid-pair.
 *
 * Deliberately structural: required fields present and string-typed. The
 * protocol's format rules (origin scheme, key/selector character sets, JSON
 * pointer syntax) stay in @fetchproxy/protocol's validator — duplicating them
 * here would give two definitions of valid, and they would drift.
 */
const ELEMENT_SHAPE: Record<string, (e: Record<string, unknown>) => boolean> = {
  captureHeaders: (e) => hasStrings(e, ['host', 'headerName']) && optionalString(e.path),
  indexedDb: (e) =>
    hasStrings(e, ['origin', 'database', 'store']) && isStringArray(e.keys) && e.keys.length > 0,
  localStoragePointers: (e) => hasStrings(e, ['outputKey', 'storageKey', 'jsonPointer']),
  sessionStoragePointers: (e) => hasStrings(e, ['outputKey', 'storageKey', 'jsonPointer']),
  domSelectors: (e) => hasStrings(e, ['name', 'selector']) && optionalString(e.attribute),
};

function validateProfile(name: string, raw: unknown): Profile {
  const fail = (field: string): never => {
    throw new UsageError(
      `profiles.json: profile "${name}" has an invalid "${field}"`,
      `Fix or remove the entry (fpx profile remove ${name}) and re-add it.`,
    );
  };
  if (raw === null || typeof raw !== 'object') fail('entry');
  const p = raw as Record<string, unknown>;
  if (!isStringArray(p.domains) || p.domains.length === 0) fail('domains');
  for (const k of ['cookies', 'localStorage', 'sessionStorage'] as const) {
    if (p[k] !== undefined && !isStringArray(p[k])) fail(k);
  }
  for (const k of [
    'captureHeaders', 'indexedDb', 'localStoragePointers', 'sessionStoragePointers', 'domSelectors',
  ] as const) {
    if (p[k] === undefined) continue;
    if (!Array.isArray(p[k])) fail(k);
    const shapeOk = ELEMENT_SHAPE[k]!;
    (p[k] as unknown[]).forEach((entry, i) => {
      if (!isRecord(entry) || !shapeOk(entry)) fail(`${k}[${i}]`);
    });
  }
  if (p.download !== undefined && typeof p.download !== 'boolean') fail('download');
  return { ...emptyProfile(p.domains as string[]), ...(p as Partial<Profile>) } as Profile;
}

const profilesPath = (home: string) => join(home, 'profiles.json');

export function loadProfiles(home: string = cliHome()): Record<string, Profile> {
  const path = profilesPath(home);
  if (!existsSync(path)) return {};
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new UsageError(`profiles.json is not valid JSON: ${(e as Error).message}`, path);
  }
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new UsageError('profiles.json must be an object of {name: profile}', path);
  }
  const out: Record<string, Profile> = {};
  for (const [name, value] of Object.entries(raw)) out[name] = validateProfile(name, value);
  return out;
}

export function saveProfiles(map: Record<string, Profile>, home: string = cliHome()): void {
  mkdirSync(home, { recursive: true, mode: 0o700 });
  writeFileSync(profilesPath(home), `${JSON.stringify(map, null, 2)}\n`, { mode: 0o600 });
}

export function getProfile(name: string, home: string = cliHome()): Profile {
  const all = loadProfiles(home);
  const p = all[name];
  if (!p) {
    const known = Object.keys(all).sort().join(', ') || '(none)';
    throw new UsageError(
      `unknown profile "${name}" — known profiles: ${known}`,
      `Create it with: fpx profile add ${name} --domain <apex-domain>`,
    );
  }
  return p;
}
