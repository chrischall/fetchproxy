import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type {
  CaptureHeaderDecl,
  DomSelectorDecl,
  GraphqlOpDeclaration,
  IndexedDbScopeDecl,
} from '@fetchproxy/protocol';
import { defaultTrustDir } from '@fetchproxy/server';
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
  /**
   * 1.12.0+: may this profile OVERWRITE the cookies it declares?
   *
   * Its own flag rather than implied by `cookies`, because a write is a
   * different privilege from a read and the user approves it as its own line
   * in the pair popup. It still cannot reach beyond the declared `cookies`.
   */
  cookieWrite: boolean;
  /**
   * 2.9.2+: may a fetch from this profile run in the page's MAIN world?
   *
   * Its own flag for the reason `cookieWrite` has one: routing a request
   * through page script gives up fetchproxy's tamper resistance, so it is a
   * separate line in the pair popup rather than something `fetch` implies.
   *
   * It exists on the CLI at all so this class of failure is reproducible from
   * a shell against the real extension. chrischall/fetchproxy#324 spent two
   * rounds on wrong answers because the only prober that could reach the MAIN
   * world was a hosted MCP, and the browser harness reached for instead cannot
   * make cross-origin requests at all.
   */
  inPage: boolean;
  /**
   * 2.10.0+: may this profile snapshot a redirect TARGET?
   *
   * Its own flag rather than implied by `fetch`, because what it reads is a
   * URL the page was sent to and never asked for — a presigned link behind a
   * 302 is the motivating case, and it is exactly the kind of value worth
   * approving deliberately. Scope is the profile's declared `domains`; unlike
   * `captureHeaders` there is no per-entry declaration, so the flag is all
   * there is to approve.
   */
  captureRedirect: boolean;
  /**
   * 2.10.0+: GraphQL operations this profile may invoke, as `name` →
   * `operationName`.
   *
   * Declared per operation rather than granted wholesale: the extension
   * resolves the name to a DocumentNode the page's own Apollo client already
   * holds and runs it through the site's own client, so an undeclared name
   * would be an arbitrary query on the user's session. An empty list means no
   * operations, even with the capability present.
   */
  graphqlOps: GraphqlOpDeclaration[];
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

/**
 * The extension pin that sits beside a profile's identity (#208).
 *
 * Paired with `identityPath` deliberately: removing a profile has to take both.
 * Leaving the pin behind means a profile of the same name created later starts
 * life already committed to a browser identity it never met — inheriting a
 * refusal, or a trust, that nobody in this installation decided.
 *
 * "Beside" is where the pin lands by default and no longer where it must land:
 * `FETCHPROXY_TRUST_DIR` moves it, and this has to follow the same resolution
 * the server writes through or `profile remove` deletes a file that is not the
 * pin.
 */
export function extensionPinPath(
  name: string,
  trustDir: string = defaultTrustDir(),
): string {
  return join(trustDir, `fpx-${name}.extension-trust.json`);
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
    cookieWrite: false,
    inPage: false,
    captureRedirect: false,
    graphqlOps: [],
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
  if (p.cookieWrite !== undefined && typeof p.cookieWrite !== 'boolean') fail('cookieWrite');
  if (p.inPage !== undefined && typeof p.inPage !== 'boolean') fail('inPage');
  if (p.captureRedirect !== undefined && typeof p.captureRedirect !== 'boolean') {
    fail('captureRedirect');
  }
  if (p.graphqlOps !== undefined) {
    // ELEMENT shape, not just "is an array". A malformed entry reaches the
    // extension as a declared operation and is refused there, long after the
    // profile that produced it looked fine — the sibling declarations
    // (`captureHeaders`, `domSelectors`) are validated the same way.
    if (
      !Array.isArray(p.graphqlOps) ||
      !p.graphqlOps.every(
        (op) =>
          op !== null &&
          typeof op === 'object' &&
          typeof (op as { name?: unknown }).name === 'string' &&
          (op as { name: string }).name.length > 0 &&
          typeof (op as { operationName?: unknown }).operationName === 'string' &&
          (op as { operationName: string }).operationName.length > 0,
      )
    ) {
      fail('graphqlOps');
    }
  }
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
