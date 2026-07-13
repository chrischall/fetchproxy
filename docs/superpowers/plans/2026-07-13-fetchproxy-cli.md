# `@fetchproxy/cli` (`fpx`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A one-shot CLI (`fpx`) for the fetchproxy bridge so skills and shell scripts can make authenticated fetches and bootstrap-parity reads through the user's signed-in browser tab, scoped by per-service profiles.

**Architecture:** New `packages/cli` workspace wrapping `@fetchproxy/server` (fetch/read/health verbs) and `@fetchproxy/bootstrap` (session verb). Every invocation: load profile → construct server → `listen()` → one verb → `close()`. Per-service identities (`fpx-<profile>`) with domains + read scope pinned in `~/.fetchproxy/cli/profiles.json`.

**Tech Stack:** Node ≥ 20 ESM TypeScript, `node:util.parseArgs`, vitest. Zero new runtime deps — only `@fetchproxy/{protocol,server,bootstrap}` workspace siblings.

**Spec:** `docs/superpowers/specs/2026-07-13-fetchproxy-cli-design.md` (approved 2026-07-13).

## Global Constraints

- **stdout is data-only.** All logging via `console.error` / the `Io.err` sink. Never `console.log` / `console.info` / `console.debug` anywhere under `packages/cli/src/` (repo-wide rule; see CLAUDE.md).
- **Capability parity (critical).** Extension trust is keyed to (identity, domains, capabilities). EVERY connect for a profile must send an identical hello, or alternating verbs re-triggers pairing. `serverOptsFor()` (Task 5) replicates `bootstrap()`'s derivation exactly — capabilities pushed in bootstrap's order (`fetch`, `read_cookies`, `read_local_storage`, `read_session_storage`, `capture_request_header`, `read_indexed_db`), pointer `storageKey`s auto-added to `localStorageKeys`/`sessionStorageKeys` — and ALL direct-server verbs construct from it. The `session` verb goes through `bootstrap()` itself, which produces the same hello by construction (`packages/bootstrap/src/index.ts:215-247` is the reference algorithm).
- **Exit codes:** `0` success (2xx for fetch verbs) · `1` usage error · `2` bridge unavailable (not paired / extension down / no tab / timeout) · `3` bot wall detected · `4` upstream HTTP error status.
- **Versions:** new package starts at the current lockstep version `1.4.0`; all `@fetchproxy/*` dep ranges are caret (`^1.4.0`), never literal. Never hand-bump after this — release-please owns it.
- **Tests:** vitest, in `packages/cli/tests/`, import via `../src/<file>.js` specifiers. All mocked — no network, no live bridge, no writes outside a per-test temp `FETCHPROXY_CLI_HOME`. Root `npm test` (currently 865 tests) must stay green.
- **Commits:** conventional-commit subject per task, on branch `feat/cli` in the `~/git/fetchproxy-wt-cli` worktree.

## File Structure

```
packages/cli/
  package.json               # @fetchproxy/cli, bin "fpx" → dist/index.js
  tsconfig.json              # composite, refs protocol/server/bootstrap
  README.md                  # Task 11
  src/
    version.ts               # release-please-managed VERSION constant
    output.ts                # Io sinks, EXIT codes, UsageError, JSON printing
    profiles.ts              # profiles.json store: load/save/validate/CRUD, 0700/0600
    args.ts                  # argv → Command union (pure; @file reads injected)
    server-opts.ts           # profile → FetchproxyServerOpts (bootstrap-parity)
    bridge-errors.ts         # thrown error → exit code + actionable stderr message
    verbs/
      fetch.ts               # get / post-json / request
      read.ts                # cookies / local-storage / session-storage / indexeddb
      session.ts             # session (via @fetchproxy/bootstrap)
      health.ts              # health + pair
    main.ts                  # runCli(argv, io, deps) dispatcher (incl. profile cmds)
    index.ts                 # #!/usr/bin/env node → runCli(process.argv.slice(2))
  tests/
    output.test.ts  profiles.test.ts  args.test.ts  server-opts.test.ts
    fetch.test.ts   read.test.ts      session.test.ts  health.test.ts  main.test.ts
```

---

### Task 1: Workspace scaffold

**Files:**
- Create: `packages/cli/package.json`, `packages/cli/tsconfig.json`, `packages/cli/src/version.ts`, `packages/cli/src/index.ts` (placeholder)
- Modify: root `package.json` (typecheck script)

**Interfaces:**
- Produces: `VERSION: string` from `src/version.ts`; a workspace that builds under `tsc -b` and is picked up by root vitest/typecheck.

- [ ] **Step 1: Create `packages/cli/package.json`**

```json
{
  "name": "@fetchproxy/cli",
  "version": "1.4.0",
  "description": "One-shot CLI for the fetchproxy bridge: authenticated fetches and session reads through the user's signed-in browser tab, scoped by per-service profiles.",
  "type": "module",
  "bin": { "fpx": "./dist/index.js" },
  "main": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": { ".": { "import": "./dist/index.js", "types": "./dist/index.d.ts" } },
  "files": ["dist"],
  "scripts": { "build": "tsc -b" },
  "publishConfig": { "access": "public" },
  "repository": {
    "type": "git",
    "url": "git+https://github.com/chrischall/fetchproxy.git",
    "directory": "packages/cli"
  },
  "license": "MIT",
  "dependencies": {
    "@fetchproxy/bootstrap": "^1.4.0",
    "@fetchproxy/protocol": "^1.4.0",
    "@fetchproxy/server": "^1.4.0"
  },
  "devDependencies": {
    "@fetchproxy/test-helpers": "^1.4.0"
  }
}
```

- [ ] **Step 2: Create `packages/cli/tsconfig.json`** (mirror of bootstrap's)

```json
{
  "extends": "../../tsconfig.base.json",
  "compilerOptions": {
    "outDir": "./dist",
    "rootDir": "./src",
    "composite": true
  },
  "include": ["src/**/*"],
  "references": [
    { "path": "../protocol" },
    { "path": "../server" },
    { "path": "../bootstrap" }
  ]
}
```

- [ ] **Step 3: Create `packages/cli/src/version.ts`**

```ts
// Managed by release-please (generic updater) — do not hand-edit.
export const VERSION = '1.4.0'; // x-release-please-version
```

- [ ] **Step 4: Create placeholder `packages/cli/src/index.ts`**

```ts
#!/usr/bin/env node
// Bin entry — wired to runCli() in a later task.
export {};
```

- [ ] **Step 5: Add cli to the root typecheck script** in root `package.json`:

```
"typecheck": "tsc -b packages/protocol packages/server packages/bootstrap packages/cli packages/extension-core packages/test-helpers"
```

- [ ] **Step 6: Install + verify**

Run: `npm install && npm run typecheck && npm run build && npm test`
Expected: install links the new workspace; typecheck/build green; test count unchanged (865).

- [ ] **Step 7: Commit**

```bash
git add packages/cli package.json package-lock.json
git commit -m "feat(cli): scaffold @fetchproxy/cli workspace"
```

---

### Task 2: Output contract (`src/output.ts`)

**Files:**
- Create: `packages/cli/src/output.ts`
- Test: `packages/cli/tests/output.test.ts`

**Interfaces:**
- Produces:
  - `interface Io { out(line: string): void; err(line: string): void }`
  - `const EXIT: { OK: 0; USAGE: 1; BRIDGE: 2; BOTWALL: 3; HTTP: 4 }`
  - `class UsageError extends Error` (optional `hint?: string` second arg, stored as `.hint`)
  - `printJson(io: Io, value: unknown): void` — 2-space JSON to stdout
  - `fetchEnvelope(res: { status: number; url: string; body: string }): string` — the `--json` envelope (NO headers field — the bridge protocol does not return response headers; body is always a UTF-8 string)

- [ ] **Step 1: Write the failing test** `packages/cli/tests/output.test.ts`

```ts
import { describe, it, expect } from 'vitest';
import { EXIT, UsageError, printJson, fetchEnvelope, type Io } from '../src/output.js';

function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = [];
  const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}

describe('output', () => {
  it('pins the exit-code table', () => {
    expect(EXIT).toEqual({ OK: 0, USAGE: 1, BRIDGE: 2, BOTWALL: 3, HTTP: 4 });
  });

  it('UsageError carries message and hint', () => {
    const e = new UsageError('bad flag', 'try --help');
    expect(e.message).toBe('bad flag');
    expect(e.hint).toBe('try --help');
    expect(e).toBeInstanceOf(Error);
  });

  it('printJson writes 2-space JSON to out only', () => {
    const io = memIo();
    printJson(io, { a: 1 });
    expect(io.outs).toEqual([JSON.stringify({ a: 1 }, null, 2)]);
    expect(io.errs).toEqual([]);
  });

  it('fetchEnvelope wraps status/url/body with no headers field', () => {
    const parsed = JSON.parse(fetchEnvelope({ status: 200, url: 'https://x.com/a', body: 'hi' }));
    expect(parsed).toEqual({ status: 200, url: 'https://x.com/a', body: 'hi' });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/cli/tests/output.test.ts`
Expected: FAIL — cannot resolve `../src/output.js`.

- [ ] **Step 3: Implement `packages/cli/src/output.ts`**

```ts
/** stdout/stderr sinks, injected everywhere so tests capture output. */
export interface Io {
  /** Data channel — response bodies and JSON results ONLY. */
  out(line: string): void;
  /** Everything else: status lines, pair codes, errors, hints. */
  err(line: string): void;
}

export const EXIT = { OK: 0, USAGE: 1, BRIDGE: 2, BOTWALL: 3, HTTP: 4 } as const;

/** Invalid invocation or profile state — maps to EXIT.USAGE. */
export class UsageError extends Error {
  readonly hint?: string;
  constructor(message: string, hint?: string) {
    super(message);
    this.name = 'UsageError';
    this.hint = hint;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export function printJson(io: Io, value: unknown): void {
  io.out(JSON.stringify(value, null, 2));
}

/**
 * `--json` envelope for fetch verbs. The bridge returns `{status, url,
 * body}` — response headers never cross the protocol, and `body` is
 * always a UTF-8 string (the extension decodes it).
 */
export function fetchEnvelope(res: { status: number; url: string; body: string }): string {
  return JSON.stringify({ status: res.status, url: res.url, body: res.body }, null, 2);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/cli/tests/output.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/output.ts packages/cli/tests/output.test.ts
git commit -m "feat(cli): output contract — Io sinks, exit codes, json envelope"
```

---

### Task 3: Profile store (`src/profiles.ts`)

**Files:**
- Create: `packages/cli/src/profiles.ts`
- Test: `packages/cli/tests/profiles.test.ts`

**Interfaces:**
- Consumes: `UsageError` from `../src/output.js`; `CaptureHeaderDecl`, `IndexedDbScopeDecl` types from `@fetchproxy/protocol`.
- Produces:
  - `interface PointerDecl { outputKey: string; storageKey: string; jsonPointer: string }`
  - `interface Profile { domains: string[]; cookies: string[]; localStorage: string[]; sessionStorage: string[]; captureHeaders: CaptureHeaderDecl[]; indexedDb: IndexedDbScopeDecl[]; localStoragePointers: PointerDecl[]; sessionStoragePointers: PointerDecl[] }`
  - `cliHome(env?): string` — `$FETCHPROXY_CLI_HOME` or `~/.fetchproxy/cli`
  - `emptyProfile(domains: string[]): Profile`
  - `loadProfiles(home?): Record<string, Profile>` / `saveProfiles(map, home?): void` (dir 0700, file 0600)
  - `getProfile(name, home?): Profile` — UsageError listing known profiles if absent
  - `identityPath(name: string, identityDir?: string): string` — `~/.fetchproxy/identity/fpx-<name>.json`

- [ ] **Step 1: Write the failing test** `packages/cli/tests/profiles.test.ts`

```ts
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  cliHome, emptyProfile, loadProfiles, saveProfiles, getProfile, identityPath,
} from '../src/profiles.js';
import { UsageError } from '../src/output.js';

let home: string;
beforeEach(() => { home = mkdtempSync(join(tmpdir(), 'fpx-test-')); });
afterEach(() => { rmSync(home, { recursive: true, force: true }); });

describe('profiles', () => {
  it('cliHome prefers FETCHPROXY_CLI_HOME', () => {
    expect(cliHome({ FETCHPROXY_CLI_HOME: '/x' })).toBe('/x');
    expect(cliHome({})).toMatch(/\.fetchproxy[\\/]cli$/);
  });

  it('round-trips a profile with 0600/0700 permissions', () => {
    saveProfiles({ trip: emptyProfile(['tripadvisor.com']) }, home);
    const loaded = loadProfiles(home);
    expect(loaded.trip.domains).toEqual(['tripadvisor.com']);
    expect(loaded.trip.cookies).toEqual([]);
    expect(statSync(join(home, 'profiles.json')).mode & 0o777).toBe(0o600);
    expect(statSync(home).mode & 0o777).toBe(0o700);
  });

  it('loadProfiles returns {} when no file exists', () => {
    expect(loadProfiles(join(home, 'nope'))).toEqual({});
  });

  it('rejects malformed profile entries with a UsageError naming the field', () => {
    saveProfiles({ bad: { ...emptyProfile(['x.com']), domains: [] } as never }, home);
    expect(() => loadProfiles(home)).toThrow(UsageError);
    expect(() => loadProfiles(home)).toThrow(/bad.*domains/);
  });

  it('getProfile throws a UsageError listing known profiles', () => {
    saveProfiles({ trip: emptyProfile(['tripadvisor.com']) }, home);
    expect(() => getProfile('nope', home)).toThrow(/known profiles: trip/);
  });

  it('identityPath derives the fpx-prefixed identity file', () => {
    expect(identityPath('trip', '/id')).toBe(join('/id', 'fpx-trip.json'));
    expect(identityPath('trip')).toMatch(/\.fetchproxy[\\/]identity[\\/]fpx-trip\.json$/);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/cli/tests/profiles.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `packages/cli/src/profiles.ts`**

```ts
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { CaptureHeaderDecl, IndexedDbScopeDecl } from '@fetchproxy/protocol';
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
  };
}

const isStringArray = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((s) => typeof s === 'string' && s.length > 0);

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
    'captureHeaders', 'indexedDb', 'localStoragePointers', 'sessionStoragePointers',
  ] as const) {
    if (p[k] !== undefined && !Array.isArray(p[k])) fail(k);
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/cli/tests/profiles.test.ts`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/profiles.ts packages/cli/tests/profiles.test.ts
git commit -m "feat(cli): per-service profile store with 0600/0700 permissions"
```

---

### Task 4: Argument parsing (`src/args.ts`)

**Files:**
- Create: `packages/cli/src/args.ts`
- Test: `packages/cli/tests/args.test.ts`

**Interfaces:**
- Consumes: `UsageError`; `CaptureHeaderDecl` from `@fetchproxy/protocol`.
- Produces:

```ts
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
export function parseCliArgs(argv: string[], readFile?: (p: string) => string): Command;
```

Grammar (options may be interspersed; `-p/--profile` required for verb commands):
`fpx help|--help|-h` · `fpx profile add <name> --domain d [--domain d2…]` · `fpx profile declare <name> [--cookie c]… [--local-storage k]… [--session-storage k]… [--capture-header name@host[/path]]…` · `fpx profile list|show <name>|remove <name>` · `fpx pair -p prof [--domain d]` · `fpx health -p prof` · `fpx get <url> -p prof [--json] [-H 'K: V']…` · `fpx post-json <url> <body|@file> -p prof [--json] [-H …]…` · `fpx request <url> -p prof [-X METHOD] [-H …]… [-d body|@file] [--json]` · `fpx cookies|local-storage|session-storage|indexeddb [keys…] -p prof [--storage-domain d] [--storage-subdomain s]` · `fpx session -p prof [--storage-domain d] [--storage-subdomain s]`

`@file` bodies resolve through the injected `readFile` (defaults to `node:fs.readFileSync(path, 'utf8')`). `post-json` validates the body with `JSON.parse` and defaults method POST + `Content-Type: application/json` (unless a `-H` already sets one). `--capture-header` splits at the FIRST `@`; host may carry a `/path` suffix which becomes the optional `path` field.

- [ ] **Step 1: Write the failing test** `packages/cli/tests/args.test.ts`

```ts
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
    });
  });

  it('parses get with headers and --json', () => {
    const cmd = parseCliArgs(['get', 'https://www.tripadvisor.com/x', '-p', 'trip',
      '--json', '-H', 'Accept: application/json']);
    expect(cmd).toEqual({
      kind: 'fetch', profile: 'trip', method: 'GET', url: 'https://www.tripadvisor.com/x',
      headers: { Accept: 'application/json' }, body: undefined, json: true,
    });
  });

  it('post-json resolves @file bodies and sets content-type', () => {
    const cmd = parseCliArgs(['post-json', 'https://x.com/api', '@body.json', '-p', 'x'],
      (p) => { expect(p).toBe('body.json'); return '{"a":1}'; });
    expect(cmd).toMatchObject({
      kind: 'fetch', method: 'POST', body: '{"a":1}',
      headers: { 'Content-Type': 'application/json' },
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

  it('rejects unknown flags with a UsageError, not a raw TypeError', () => {
    expect(() => parseCliArgs(['get', 'https://x.com/', '--bogus', '-p', 'x'])).toThrow(UsageError);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/cli/tests/args.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `packages/cli/src/args.ts`**

```ts
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

  if (cmd in READ_BUCKETS) {
    return {
      kind: 'read', profile: requireProfile(values.profile), bucket: READ_BUCKETS[cmd],
      keys: rest,
      storageDomain: values['storage-domain'], storageSubdomain: values['storage-subdomain'],
    };
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/cli/tests/args.test.ts`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/args.ts packages/cli/tests/args.test.ts
git commit -m "feat(cli): argv parser producing the Command union"
```

---

### Task 5: Server-opts derivation with bootstrap parity (`src/server-opts.ts`)

**Files:**
- Create: `packages/cli/src/server-opts.ts`
- Test: `packages/cli/tests/server-opts.test.ts`

**Interfaces:**
- Consumes: `Profile` from `../src/profiles.js`; `Capability` type from `@fetchproxy/server`.
- Produces:

```ts
export interface DerivedServerOpts {
  serverName: string;        // `fpx-${profileName}`
  version: string;
  domains: string[];
  capabilities: Capability[];
  cookieKeys: string[];
  localStorageKeys: string[];   // declared keys ∪ localStoragePointers[].storageKey
  sessionStorageKeys: string[]; // declared keys ∪ sessionStoragePointers[].storageKey
  captureHeaders: CaptureHeaderDecl[];
  indexedDbScopes: IndexedDbScopeDecl[];
}
export function serverOptsFor(profileName: string, p: Profile, version: string): DerivedServerOpts;
```

**CRITICAL:** this must replicate `bootstrap()`'s algorithm at `packages/bootstrap/src/index.ts:212-247` exactly — same capability push order, same pointer auto-add — so the hello frame is byte-identical whichever verb connects. A comment in the file must point at that reference.

- [ ] **Step 1: Write the failing test** `packages/cli/tests/server-opts.test.ts`

```ts
import { describe, it, expect } from 'vitest';
import { serverOptsFor } from '../src/server-opts.js';
import { emptyProfile } from '../src/profiles.js';

describe('serverOptsFor', () => {
  it('fetch-only profile → capabilities [fetch] and empty scopes', () => {
    const opts = serverOptsFor('trip', emptyProfile(['tripadvisor.com']), '1.4.0');
    expect(opts).toEqual({
      serverName: 'fpx-trip', version: '1.4.0', domains: ['tripadvisor.com'],
      capabilities: ['fetch'], cookieKeys: [], localStorageKeys: [],
      sessionStorageKeys: [], captureHeaders: [], indexedDbScopes: [],
    });
  });

  it('derives capabilities in bootstrap push order and auto-adds pointer storageKeys', () => {
    const p = {
      ...emptyProfile(['resy.com']),
      cookies: ['authToken'],
      localStoragePointers: [{ outputKey: 'tok', storageKey: 'persist:auth', jsonPointer: '/t' }],
      sessionStorage: ['sid'],
      captureHeaders: [{ headerName: 'x-api-key', host: 'api.resy.com' }],
      indexedDb: [{ origin: 'https://resy.com', database: 'db', store: 's', keys: ['k'] }],
    };
    const opts = serverOptsFor('resy', p, '1.4.0');
    expect(opts.capabilities).toEqual([
      'fetch', 'read_cookies', 'read_local_storage', 'read_session_storage',
      'capture_request_header', 'read_indexed_db',
    ]);
    expect(opts.localStorageKeys).toEqual(['persist:auth']);
    expect(opts.sessionStorageKeys).toEqual(['sid']);
  });

  it('read_local_storage appears for raw keys with no pointers (and vice versa)', () => {
    const raw = serverOptsFor('a', { ...emptyProfile(['x.com']), localStorage: ['k'] }, '1.4.0');
    expect(raw.capabilities).toEqual(['fetch', 'read_local_storage']);
    expect(raw.localStorageKeys).toEqual(['k']);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/cli/tests/server-opts.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `packages/cli/src/server-opts.ts`**

```ts
import type { Capability } from '@fetchproxy/server';
import type { CaptureHeaderDecl, IndexedDbScopeDecl } from '@fetchproxy/protocol';
import type { Profile } from './profiles.js';

export interface DerivedServerOpts {
  serverName: string;
  version: string;
  domains: string[];
  capabilities: Capability[];
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: CaptureHeaderDecl[];
  indexedDbScopes: IndexedDbScopeDecl[];
}

/**
 * Derive the FetchproxyServer opts for a profile.
 *
 * MUST stay in lockstep with `bootstrap()`'s derivation
 * (packages/bootstrap/src/index.ts, "capabilities" block): extension
 * trust is keyed to (identity, domains, capabilities), so every fpx
 * verb — and the `session` verb, which goes through bootstrap() itself
 * — has to send an identical hello or the user gets re-pair prompts
 * when alternating verbs. Same push order, same pointer auto-add.
 */
export function serverOptsFor(profileName: string, p: Profile, version: string): DerivedServerOpts {
  const capabilities: Capability[] = ['fetch'];
  if (p.cookies.length > 0) capabilities.push('read_cookies');
  if (p.localStorage.length > 0 || p.localStoragePointers.length > 0) {
    capabilities.push('read_local_storage');
  }
  if (p.sessionStorage.length > 0 || p.sessionStoragePointers.length > 0) {
    capabilities.push('read_session_storage');
  }
  if (p.captureHeaders.length > 0) capabilities.push('capture_request_header');
  if (p.indexedDb.length > 0) capabilities.push('read_indexed_db');

  const localStorageKeys = new Set(p.localStorage);
  for (const ptr of p.localStoragePointers) localStorageKeys.add(ptr.storageKey);
  const sessionStorageKeys = new Set(p.sessionStorage);
  for (const ptr of p.sessionStoragePointers) sessionStorageKeys.add(ptr.storageKey);

  return {
    serverName: `fpx-${profileName}`,
    version,
    domains: [...p.domains],
    capabilities,
    cookieKeys: [...p.cookies],
    localStorageKeys: [...localStorageKeys],
    sessionStorageKeys: [...sessionStorageKeys],
    captureHeaders: p.captureHeaders.map((d) => ({ ...d })),
    indexedDbScopes: p.indexedDb.map((d) => ({ ...d, keys: [...d.keys] })),
  };
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/cli/tests/server-opts.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/server-opts.ts packages/cli/tests/server-opts.test.ts
git commit -m "feat(cli): bootstrap-parity server-opts derivation per profile"
```

---

### Task 6: Bridge-error mapping + fetch verbs (`src/bridge-errors.ts`, `src/verbs/fetch.ts`)

**Files:**
- Create: `packages/cli/src/bridge-errors.ts`, `packages/cli/src/verbs/fetch.ts`
- Test: `packages/cli/tests/fetch.test.ts`

**Interfaces:**
- Consumes: `EXIT`, `Io`, `UsageError`, `fetchEnvelope`; `serverOptsFor`; `classifyBridgeError`, `classifyBotWall`, `FetchproxySessionNotReadyError`, `FetchproxyServer` from `@fetchproxy/server`.
- Produces:
  - `mapBridgeError(err: unknown, io: Io): number` — prints actionable message to stderr, returns exit code (`FetchproxySessionNotReadyError` → EXIT.BRIDGE with pair-code hint; `classifyBridgeError` kinds `bridge_down`/`timeout`/`protocol`/`other` → EXIT.BRIDGE; rethrows `UsageError`)
  - `interface VerbServer { listen(): Promise<void>; close(): Promise<void>; request(method: string, path: string, opts?: { headers?: Record<string, string>; body?: string; domain?: string }): Promise<{ status: number; body: string; url: string }>; readCookies(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<string>; readLocalStorage(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<Record<string, string>>; readSessionStorage(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<Record<string, string>>; readIndexedDb(o: { database: string; store: string; keys: string[]; domain?: string; subdomain?: string }): Promise<Record<string, unknown>>; bridgeHealth(): unknown }`
  - `type VerbServerFactory = (opts: DerivedServerOpts & { onPairCode: (code: string) => void }) => VerbServer` (default: `new FetchproxyServer(opts)`)
  - `runFetch(cmd: Extract<Command, {kind:'fetch'}>, profile: Profile, io: Io, makeServer?: VerbServerFactory): Promise<number>`

Behavior: pre-check URL host is on a declared domain (or subdomain) → else UsageError naming profile domains. `listen()`, `request(method, url, {headers, body})`, `close()` in finally. Success path: `--json` → envelope, else raw body to stdout. `classifyBotWall(body, status)` blocked → vendor note on stderr, body on stdout, EXIT.BOTWALL. 2xx → EXIT.OK; other statuses → `HTTP <status> <url>` on stderr, EXIT.HTTP. `onPairCode` prints `fetchproxy pair code: XXX-XXX — approve in the Transporter extension popup` to stderr.

- [ ] **Step 1: Write the failing test** `packages/cli/tests/fetch.test.ts`

```ts
import { describe, it, expect, vi } from 'vitest';
import { runFetch, type VerbServer } from '../src/verbs/fetch.js';
import { emptyProfile } from '../src/profiles.js';
import { EXIT, type Io } from '../src/output.js';
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
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/cli/tests/fetch.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `packages/cli/src/bridge-errors.ts`**

```ts
import { classifyBridgeError, FetchproxySessionNotReadyError } from '@fetchproxy/server';
import { EXIT, UsageError, type Io } from './output.js';

/**
 * Map a thrown bridge error to an exit code, printing one actionable
 * line to stderr. UsageErrors propagate — main() owns those.
 */
export function mapBridgeError(err: unknown, io: Io): number {
  if (err instanceof UsageError) throw err;
  if (err instanceof FetchproxySessionNotReadyError) {
    const code = (err as { pairCode?: string | null }).pairCode;
    io.err(
      code
        ? `bridge not ready — pairing pending. Approve pair code ${code} in the Transporter extension popup and retry.`
        : 'bridge not ready — is Chrome running with the Transporter extension installed and connected?',
    );
    return EXIT.BRIDGE;
  }
  const kind = classifyBridgeError(err);
  const msg = err instanceof Error ? err.message : String(err);
  const hints: Record<string, string> = {
    bridge_down: 'is Chrome running with the Transporter extension installed?',
    timeout: 'is a tab open on the declared domain and signed in?',
    protocol: 'extension/server version mismatch — update both.',
    http: '',
    other: '',
  };
  io.err(`bridge error (${kind}): ${msg}${hints[kind] ? ` — ${hints[kind]}` : ''}`);
  return EXIT.BRIDGE;
}
```

- [ ] **Step 4: Implement `packages/cli/src/verbs/fetch.ts`**

```ts
import { classifyBotWall, FetchproxyServer } from '@fetchproxy/server';
import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor, type DerivedServerOpts } from '../server-opts.js';
import { EXIT, UsageError, fetchEnvelope, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { VERSION } from '../version.js';

/** The surface every fpx verb touches on FetchproxyServer (mock-friendly). */
export interface VerbServer {
  listen(): Promise<void>;
  close(): Promise<void>;
  request(
    method: string,
    path: string,
    opts?: { headers?: Record<string, string>; body?: string; domain?: string },
  ): Promise<{ status: number; body: string; url: string }>;
  readCookies(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<string>;
  readLocalStorage(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<Record<string, string>>;
  readSessionStorage(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<Record<string, string>>;
  readIndexedDb(o: {
    database: string; store: string; keys: string[]; domain?: string; subdomain?: string;
  }): Promise<Record<string, unknown>>;
  bridgeHealth(): unknown;
}

export type VerbServerFactory = (
  opts: DerivedServerOpts & { onPairCode: (code: string) => void },
) => VerbServer;

export const defaultServerFactory: VerbServerFactory = (opts) =>
  new FetchproxyServer(opts) as unknown as VerbServer;

export function pairCodePrinter(io: Io): (code: string) => void {
  return (code) =>
    io.err(`fetchproxy pair code: ${code} — approve in the Transporter extension popup`);
}

export function assertUrlOnProfile(url: string, profile: Profile): void {
  let host: string;
  try {
    host = new URL(url).host;
  } catch {
    throw new UsageError(`not a valid URL: ${JSON.stringify(url)}`);
  }
  const ok = profile.domains.some((d) => host === d || host.endsWith(`.${d}`));
  if (!ok) {
    throw new UsageError(
      `${host} is not on this profile's declared domains (${profile.domains.join(', ')})`,
      'add a domain with: fpx profile add <name> --domain … (new profile) or edit profiles.json',
    );
  }
}

export async function runFetch(
  cmd: Extract<Command, { kind: 'fetch' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  assertUrlOnProfile(cmd.url, profile);
  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    const res = await server.request(cmd.method, cmd.url, {
      headers: Object.keys(cmd.headers).length ? cmd.headers : undefined,
      body: cmd.body,
    });
    io.out(cmd.json ? fetchEnvelope(res) : res.body);
    const wall = classifyBotWall(res.body, res.status);
    if (wall.blocked) {
      io.err(`bot wall detected (${wall.vendor}) — open ${cmd.url} in Chrome, pass the check, retry.`);
      return EXIT.BOTWALL;
    }
    if (res.status < 200 || res.status >= 300) {
      io.err(`HTTP ${res.status} ${res.url}`);
      return EXIT.HTTP;
    }
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `npx vitest run packages/cli/tests/fetch.test.ts`
Expected: PASS (6 tests). If `classifyBotWall`'s DataDome marker differs from the test fixture body, adjust the fixture to a marker from `packages/server/src/bot-wall.ts` (read the `DD_MARKERS` list) — do not touch `bot-wall.ts`.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/bridge-errors.ts packages/cli/src/verbs/fetch.ts packages/cli/tests/fetch.test.ts
git commit -m "feat(cli): fetch verbs with bot-wall and bridge-error exit mapping"
```

---

### Task 7: Read verbs (`src/verbs/read.ts`)

**Files:**
- Create: `packages/cli/src/verbs/read.ts`
- Test: `packages/cli/tests/read.test.ts`

**Interfaces:**
- Consumes: `VerbServer`, `VerbServerFactory`, `defaultServerFactory`, `pairCodePrinter` from `./fetch.js`; `serverOptsFor`; `mapBridgeError`; `printJson`.
- Produces: `runRead(cmd: Extract<Command, {kind:'read'}>, profile: Profile, io: Io, makeServer?: VerbServerFactory): Promise<number>`

Behavior: keys narrow the DECLARED scope only — an undeclared key is a UsageError telling the user to run `fpx profile declare`. Empty `keys` = all declared. `indexedDb` bucket ignores `keys` positionals (UsageError if given — scopes are structured; read all declared scopes, output keyed `"db/store"` like bootstrap's `Session.indexedDb`). Cookies output parses the bridge's `k=v; k2=v2` join into a record (same split as `bootstrap()`). All reads pass `domain: storageDomain, subdomain: storageSubdomain`. Declared-empty bucket → UsageError with the matching declare flag. Hello uses full-profile `serverOptsFor` (capability parity — narrowing happens per-call, never in the hello).

- [ ] **Step 1: Write the failing test** `packages/cli/tests/read.test.ts`

```ts
import { describe, it, expect, vi } from 'vitest';
import { runRead } from '../src/verbs/read.js';
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
    readCookies: vi.fn(async () => 'a=1; b=2'),
    readLocalStorage: vi.fn(async () => ({ tok: 'T' })),
    readSessionStorage: vi.fn(async () => ({})),
    readIndexedDb: vi.fn(async () => ({ k: 'v' })),
    bridgeHealth: vi.fn(() => ({})),
    ...overrides,
  } as never;
}
const PROFILE = {
  ...emptyProfile(['resy.com']),
  cookies: ['a', 'b'],
  localStorage: ['tok'],
  indexedDb: [{ origin: 'https://resy.com', database: 'db', store: 's', keys: ['k'] }],
};

describe('runRead', () => {
  it('cookies: parses the joined string into a JSON record', async () => {
    const io = memIo();
    const code = await runRead(
      { kind: 'read', profile: 'r', bucket: 'cookies', keys: [] }, PROFILE, io, () => stubServer());
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs[0])).toEqual({ a: '1', b: '2' });
  });

  it('narrows to requested declared keys', async () => {
    const server = stubServer();
    await runRead({ kind: 'read', profile: 'r', bucket: 'cookies', keys: ['a'] },
      PROFILE, memIo(), () => server);
    expect(server.readCookies).toHaveBeenCalledWith({ keys: ['a'], domain: undefined, subdomain: undefined });
  });

  it('undeclared key → UsageError naming profile declare', async () => {
    await expect(runRead({ kind: 'read', profile: 'r', bucket: 'cookies', keys: ['zzz'] },
      PROFILE, memIo(), () => stubServer())).rejects.toThrow(/profile declare/);
  });

  it('empty declared bucket → UsageError with the declare flag', async () => {
    await expect(runRead({ kind: 'read', profile: 'r', bucket: 'sessionStorage', keys: [] },
      PROFILE, memIo(), () => stubServer())).rejects.toThrow(/--session-storage/);
  });

  it('indexeddb: reads every declared scope keyed db/store', async () => {
    const io = memIo();
    const code = await runRead({ kind: 'read', profile: 'r', bucket: 'indexedDb', keys: [] },
      PROFILE, io, () => stubServer());
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs[0])).toEqual({ 'db/s': { k: 'v' } });
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/cli/tests/read.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `packages/cli/src/verbs/read.ts`**

```ts
import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor } from '../server-opts.js';
import { EXIT, UsageError, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { defaultServerFactory, pairCodePrinter, type VerbServerFactory } from './fetch.js';
import { VERSION } from '../version.js';

const DECLARE_FLAG: Record<string, string> = {
  cookies: '--cookie',
  localStorage: '--local-storage',
  sessionStorage: '--session-storage',
};

/** Same split bootstrap() uses on the bridge's `k=v; k2=v2` join. */
function cookieRecord(joined: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const piece of joined.split('; ')) {
    if (!piece) continue;
    const eq = piece.indexOf('=');
    if (eq < 0) continue;
    out[piece.slice(0, eq)] = piece.slice(eq + 1);
  }
  return out;
}

function narrowKeys(requested: string[], declared: string[], bucket: string): string[] {
  if (declared.length === 0) {
    throw new UsageError(
      `profile declares no ${bucket} scope`,
      `declare it first: fpx profile declare <name> ${DECLARE_FLAG[bucket]} <key>`,
    );
  }
  if (requested.length === 0) return declared;
  const undeclared = requested.filter((k) => !declared.includes(k));
  if (undeclared.length > 0) {
    throw new UsageError(
      `key(s) not in the profile's declared ${bucket} scope: ${undeclared.join(', ')}`,
      `widen the scope with: fpx profile declare <name> ${DECLARE_FLAG[bucket]} <key> (forces a re-pair)`,
    );
  }
  return requested;
}

export async function runRead(
  cmd: Extract<Command, { kind: 'read' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  // Validate scope narrowing BEFORE connecting — usage errors must not
  // cost a bridge round-trip (and must not trigger pairing).
  const scope = { domain: cmd.storageDomain, subdomain: cmd.storageSubdomain };
  let keys: string[] = [];
  if (cmd.bucket === 'indexedDb') {
    if (cmd.keys.length > 0) {
      throw new UsageError('indexeddb does not take key arguments — it reads all declared scopes',
        'edit the profile\'s "indexedDb" array in profiles.json to change scopes');
    }
    if (profile.indexedDb.length === 0) {
      throw new UsageError('profile declares no indexedDb scopes',
        'add entries to the profile\'s "indexedDb" array in profiles.json (forces a re-pair)');
    }
  } else {
    keys = narrowKeys(cmd.keys, profile[cmd.bucket], cmd.bucket);
  }

  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    switch (cmd.bucket) {
      case 'cookies':
        printJson(io, cookieRecord(await server.readCookies({ keys, ...scope })));
        break;
      case 'localStorage':
        printJson(io, await server.readLocalStorage({ keys, ...scope }));
        break;
      case 'sessionStorage':
        printJson(io, await server.readSessionStorage({ keys, ...scope }));
        break;
      case 'indexedDb': {
        const out: Record<string, Record<string, unknown>> = {};
        for (const s of profile.indexedDb) {
          out[`${s.database}/${s.store}`] = await server.readIndexedDb({
            database: s.database, store: s.store, keys: [...s.keys], ...scope,
          });
        }
        printJson(io, out);
        break;
      }
    }
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/cli/tests/read.test.ts`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/verbs/read.ts packages/cli/tests/read.test.ts
git commit -m "feat(cli): scoped read verbs (cookies/storage/indexeddb)"
```

---

### Task 8: Session verb (`src/verbs/session.ts`)

**Files:**
- Create: `packages/cli/src/verbs/session.ts`
- Test: `packages/cli/tests/session.test.ts`

**Interfaces:**
- Consumes: `bootstrap`, types `Session`, `BootstrapOpts` from `@fetchproxy/bootstrap`; `printJson`, `EXIT`, `Io`; `mapBridgeError`; `Profile`.
- Produces: `runSession(cmd: Extract<Command, {kind:'session'}>, profile: Profile, io: Io, bootstrapFn?: typeof bootstrap): Promise<number>`

Behavior: map the profile onto `BootstrapOpts` — `serverName: 'fpx-<profile>'`, `version: VERSION`, `domains`, `declare` = the profile's eight buckets, `storageDomain`/`storageSubdomain` passthrough, `onPairCode` → the shared stderr printer, `onWaiting: (hint) => io.err('waiting: ' + hint)`. Print the returned `Session` as JSON on stdout, EXIT.OK. Errors through `mapBridgeError`. (Capability parity holds by construction — bootstrap derives the same hello `serverOptsFor` does.)

- [ ] **Step 1: Write the failing test** `packages/cli/tests/session.test.ts`

```ts
import { describe, it, expect, vi } from 'vitest';
import { runSession } from '../src/verbs/session.js';
import { emptyProfile } from '../src/profiles.js';
import { EXIT, type Io } from '../src/output.js';
import type { Session } from '@fetchproxy/bootstrap';

function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = []; const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}
const SESSION: Session = {
  cookies: { a: '1' }, localStorage: {}, sessionStorage: {}, capturedHeaders: {}, indexedDb: {},
};

describe('runSession', () => {
  it('maps profile → BootstrapOpts and prints the Session JSON', async () => {
    const io = memIo();
    const profile = { ...emptyProfile(['honeybook.com', 'hbportal.co']), cookies: ['a'] };
    const boot = vi.fn(async () => SESSION);
    const code = await runSession(
      { kind: 'session', profile: 'hb', storageDomain: 'hbportal.co', storageSubdomain: undefined },
      profile, io, boot as never);
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs[0])).toEqual(SESSION);
    const opts = boot.mock.calls[0][0] as Record<string, unknown>;
    expect(opts.serverName).toBe('fpx-hb');
    expect(opts.domains).toEqual(['honeybook.com', 'hbportal.co']);
    expect(opts.storageDomain).toBe('hbportal.co');
    expect((opts.declare as Record<string, unknown>).cookies).toEqual(['a']);
  });

  it('onPairCode and onWaiting go to stderr', async () => {
    const io = memIo();
    const boot = vi.fn(async (opts: { onPairCode?: (c: string) => void; onWaiting?: (h: string) => void }) => {
      opts.onPairCode?.('111-222');
      opts.onWaiting?.('trigger a request to api.x.com');
      return SESSION;
    });
    await runSession({ kind: 'session', profile: 'x', storageDomain: undefined, storageSubdomain: undefined },
      emptyProfile(['x.com']), io, boot as never);
    expect(io.errs.join('\n')).toMatch(/111-222/);
    expect(io.errs.join('\n')).toMatch(/waiting: trigger a request/);
  });

  it('bridge failure → exit 2', async () => {
    const io = memIo();
    const boot = vi.fn(async () => { throw new Error('extension gone'); });
    const code = await runSession(
      { kind: 'session', profile: 'x', storageDomain: undefined, storageSubdomain: undefined },
      emptyProfile(['x.com']), io, boot as never);
    expect(code).toBe(EXIT.BRIDGE);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/cli/tests/session.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `packages/cli/src/verbs/session.ts`**

```ts
import { bootstrap } from '@fetchproxy/bootstrap';
import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { EXIT, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { pairCodePrinter } from './fetch.js';
import { VERSION } from '../version.js';

export async function runSession(
  cmd: Extract<Command, { kind: 'session' }>,
  profile: Profile,
  io: Io,
  bootstrapFn: typeof bootstrap = bootstrap,
): Promise<number> {
  try {
    const session = await bootstrapFn({
      serverName: `fpx-${cmd.profile}`,
      version: VERSION,
      domains: [...profile.domains],
      declare: {
        cookies: [...profile.cookies],
        localStorage: [...profile.localStorage],
        sessionStorage: [...profile.sessionStorage],
        captureHeaders: profile.captureHeaders.map((d) => ({ ...d })),
        indexedDb: profile.indexedDb.map((d) => ({ ...d, keys: [...d.keys] })),
        localStoragePointers: profile.localStoragePointers.map((p) => ({ ...p })),
        sessionStoragePointers: profile.sessionStoragePointers.map((p) => ({ ...p })),
      },
      storageDomain: cmd.storageDomain,
      storageSubdomain: cmd.storageSubdomain,
      onPairCode: pairCodePrinter(io),
      onWaiting: (hint) => io.err(`waiting: ${hint}`),
    });
    printJson(io, session);
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/cli/tests/session.test.ts`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/verbs/session.ts packages/cli/tests/session.test.ts
git commit -m "feat(cli): session verb via @fetchproxy/bootstrap"
```

---

### Task 9: Health + pair verbs (`src/verbs/health.ts`)

**Files:**
- Create: `packages/cli/src/verbs/health.ts`
- Test: `packages/cli/tests/health.test.ts`

**Interfaces:**
- Consumes: `VerbServerFactory`, `defaultServerFactory`, `pairCodePrinter`; `serverOptsFor`; `printJson`; `mapBridgeError`; `UsageError`.
- Produces:
  - `runHealth(cmd: Extract<Command, {kind:'health'}>, profile: Profile, io: Io, makeServer?: VerbServerFactory): Promise<number>` — listen, `printJson(io, server.bridgeHealth())`, EXIT.OK; errors via `mapBridgeError`.
  - `runPair(cmd: Extract<Command, {kind:'pair'}>, profile: Profile, io: Io, makeServer?: VerbServerFactory): Promise<number>` — listen, then `request('HEAD', '/', { domain })` as an end-to-end probe (`domain` = `cmd.domain` ?? sole declared domain; multi-domain without `--domain` is a UsageError). ANY HttpResponse (any status) proves pairing + tab: `paired ✓ (<profile> → <domain>, HTTP <status>)` on stderr, EXIT.OK. Bridge errors via `mapBridgeError`.

- [ ] **Step 1: Write the failing test** `packages/cli/tests/health.test.ts`

```ts
import { describe, it, expect, vi } from 'vitest';
import { runHealth, runPair } from '../src/verbs/health.js';
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
    request: vi.fn(async () => ({ status: 405, body: '', url: 'https://x.com/' })),
    readCookies: vi.fn(async () => ''), readLocalStorage: vi.fn(async () => ({})),
    readSessionStorage: vi.fn(async () => ({})), readIndexedDb: vi.fn(async () => ({})),
    bridgeHealth: vi.fn(() => ({ role: 'host', consecutiveFailures: 0 })),
    ...overrides,
  } as never;
}

describe('health & pair', () => {
  it('health prints bridgeHealth JSON', async () => {
    const io = memIo();
    const code = await runHealth({ kind: 'health', profile: 'x' },
      emptyProfile(['x.com']), io, () => stubServer());
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs[0])).toEqual({ role: 'host', consecutiveFailures: 0 });
  });

  it('pair succeeds on ANY http status (405 included)', async () => {
    const io = memIo();
    const code = await runPair({ kind: 'pair', profile: 'x', domain: undefined },
      emptyProfile(['x.com']), io, () => stubServer());
    expect(code).toBe(EXIT.OK);
    expect(io.errs.join('\n')).toMatch(/paired ✓/);
    expect(io.outs).toEqual([]);
  });

  it('pair on a multi-domain profile without --domain is a UsageError', async () => {
    await expect(runPair({ kind: 'pair', profile: 'hb', domain: undefined },
      emptyProfile(['honeybook.com', 'hbportal.co']), memIo(), () => stubServer()))
      .rejects.toThrow(/--domain/);
  });

  it('pair maps bridge failure to exit 2', async () => {
    const io = memIo();
    const server = stubServer({ request: vi.fn(async () => { throw new Error('down'); }) });
    const code = await runPair({ kind: 'pair', profile: 'x', domain: undefined },
      emptyProfile(['x.com']), io, () => server);
    expect(code).toBe(EXIT.BRIDGE);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/cli/tests/health.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `packages/cli/src/verbs/health.ts`**

```ts
import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor } from '../server-opts.js';
import { EXIT, UsageError, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { defaultServerFactory, pairCodePrinter, type VerbServerFactory } from './fetch.js';
import { VERSION } from '../version.js';

export async function runHealth(
  cmd: Extract<Command, { kind: 'health' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    printJson(io, server.bridgeHealth());
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}

export async function runPair(
  cmd: Extract<Command, { kind: 'pair' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  const domain =
    cmd.domain ??
    (profile.domains.length === 1
      ? profile.domains[0]
      : ((): string => {
          throw new UsageError(
            `profile declares multiple domains (${profile.domains.join(', ')}) — pick one with --domain`,
          );
        })());
  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    // HEAD / through the tab: any HttpResponse — any status — proves the
    // extension is paired and a matching tab answered. Bridge-level
    // failures throw and map to EXIT.BRIDGE instead.
    const res = await server.request('HEAD', '/', { domain });
    io.err(`paired ✓ (${cmd.profile} → ${domain}, HTTP ${res.status})`);
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx vitest run packages/cli/tests/health.test.ts`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/verbs/health.ts packages/cli/tests/health.test.ts
git commit -m "feat(cli): health and pair verbs"
```

---

### Task 10: Dispatcher + bin entry (`src/main.ts`, `src/index.ts`)

**Files:**
- Create: `packages/cli/src/main.ts`
- Modify: `packages/cli/src/index.ts` (replace placeholder)
- Test: `packages/cli/tests/main.test.ts`

**Interfaces:**
- Consumes: everything above.
- Produces: `runCli(argv: string[], io: Io, deps?: { home?: string; identityDir?: string; makeServer?: VerbServerFactory; bootstrapFn?: typeof bootstrap; readFile?: (p: string) => string }): Promise<number>`

Behavior: `parseCliArgs` → dispatch. Profile commands operate on the store: `add` (reject duplicate names, reject re-add), `declare` (merge-append uniquely into existing arrays; warn on stderr that scope changes force a re-pair), `list` (names + domains, one per line, to stdout), `show` (JSON to stdout), `remove` (delete entry + `rm -f` identity file via `node:fs.rmSync(path, {force: true})`; remind on stderr to also revoke the trust row in the extension popup). `help` prints usage text to stderr, returns EXIT.OK. All `UsageError`s are caught HERE (message + optional hint → stderr, EXIT.USAGE); unexpected errors print `unexpected error: <message>` and return EXIT.BRIDGE. Verb commands `getProfile()` then delegate to the Task 6–9 runners.

- [ ] **Step 1: Write the failing test** `packages/cli/tests/main.test.ts`

```ts
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { mkdtempSync, rmSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runCli } from '../src/main.js';
import { EXIT, type Io } from '../src/output.js';
import { loadProfiles } from '../src/profiles.js';

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
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx vitest run packages/cli/tests/main.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement `packages/cli/src/main.ts`**

```ts
import { rmSync } from 'node:fs';
import type { bootstrap } from '@fetchproxy/bootstrap';
import { parseCliArgs } from './args.js';
import {
  cliHome, emptyProfile, getProfile, identityPath, loadProfiles, saveProfiles,
} from './profiles.js';
import { EXIT, UsageError, printJson, type Io } from './output.js';
import { runFetch, type VerbServerFactory } from './verbs/fetch.js';
import { runRead } from './verbs/read.js';
import { runSession } from './verbs/session.js';
import { runHealth, runPair } from './verbs/health.js';

const USAGE = `fpx — fetchproxy CLI: authenticated fetches through your signed-in browser tab

  fpx profile add <name> --domain <apex> [--domain <apex>]…
  fpx profile declare <name> [--cookie k]… [--local-storage k]… [--session-storage k]… [--capture-header name@host[/path]]…
  fpx profile list | show <name> | remove <name>
  fpx pair -p <name> [--domain <apex>]
  fpx health -p <name>
  fpx get <url> -p <name> [--json] [-H 'K: V']…
  fpx post-json <url> <body|@file> -p <name> [--json] [-H …]…
  fpx request <url> -p <name> [-X METHOD] [-H …]… [-d body|@file] [--json]
  fpx cookies|local-storage|session-storage|indexeddb [keys…] -p <name> [--storage-domain d] [--storage-subdomain s]
  fpx session -p <name> [--storage-domain d] [--storage-subdomain s]

Data on stdout, everything else on stderr.
Exit codes: 0 ok · 1 usage · 2 bridge unavailable · 3 bot wall · 4 upstream HTTP error`;

export interface CliDeps {
  home?: string;
  identityDir?: string;
  makeServer?: VerbServerFactory;
  bootstrapFn?: typeof bootstrap;
  readFile?: (p: string) => string;
}

const uniqMerge = (base: string[], extra: string[]): string[] => [...new Set([...base, ...extra])];

export async function runCli(argv: string[], io: Io, deps: CliDeps = {}): Promise<number> {
  const home = deps.home ?? cliHome();
  try {
    const cmd = parseCliArgs(argv, deps.readFile);
    switch (cmd.kind) {
      case 'help':
        io.err(USAGE);
        return EXIT.OK;
      case 'profile-list': {
        const all = loadProfiles(home);
        for (const [name, p] of Object.entries(all).sort(([a], [b]) => a.localeCompare(b))) {
          io.out(`${name}\t${p.domains.join(',')}`);
        }
        return EXIT.OK;
      }
      case 'profile-show':
        printJson(io, getProfile(cmd.name, home));
        return EXIT.OK;
      case 'profile-add': {
        const all = loadProfiles(home);
        if (all[cmd.name]) {
          throw new UsageError(`profile "${cmd.name}" already exists`,
            `edit its scope with: fpx profile declare ${cmd.name} …`);
        }
        all[cmd.name] = emptyProfile(cmd.domains);
        saveProfiles(all, home);
        io.err(`profile "${cmd.name}" created (${cmd.domains.join(', ')}) — first use will show a pair code`);
        return EXIT.OK;
      }
      case 'profile-declare': {
        const all = loadProfiles(home);
        const p = all[cmd.name];
        if (!p) return runCliUnknownProfile(cmd.name, home);
        p.cookies = uniqMerge(p.cookies, cmd.cookies);
        p.localStorage = uniqMerge(p.localStorage, cmd.localStorage);
        p.sessionStorage = uniqMerge(p.sessionStorage, cmd.sessionStorage);
        for (const decl of cmd.captureHeaders) {
          if (!p.captureHeaders.some((d) => d.headerName === decl.headerName && d.host === decl.host && d.path === decl.path)) {
            p.captureHeaders.push(decl);
          }
        }
        saveProfiles(all, home);
        io.err(`profile "${cmd.name}" scope updated — the next connect will ask you to re-pair (scope diff)`);
        return EXIT.OK;
      }
      case 'profile-remove': {
        const all = loadProfiles(home);
        if (!all[cmd.name]) return runCliUnknownProfile(cmd.name, home);
        delete all[cmd.name];
        saveProfiles(all, home);
        rmSync(identityPath(cmd.name, deps.identityDir), { force: true });
        io.err(`profile "${cmd.name}" removed — also revoke fpx-${cmd.name} in the Transporter extension popup`);
        return EXIT.OK;
      }
      case 'fetch':
        return await runFetch(cmd, getProfile(cmd.profile, home), io, deps.makeServer);
      case 'read':
        return await runRead(cmd, getProfile(cmd.profile, home), io, deps.makeServer);
      case 'session':
        return await runSession(cmd, getProfile(cmd.profile, home), io, deps.bootstrapFn);
      case 'health':
        return await runHealth(cmd, getProfile(cmd.profile, home), io, deps.makeServer);
      case 'pair':
        return await runPair(cmd, getProfile(cmd.profile, home), io, deps.makeServer);
    }
  } catch (err) {
    if (err instanceof UsageError) {
      io.err(`fpx: ${err.message}`);
      if (err.hint) io.err(`  hint: ${err.hint}`);
      return EXIT.USAGE;
    }
    io.err(`fpx: unexpected error: ${err instanceof Error ? err.message : String(err)}`);
    return EXIT.BRIDGE;
  }
}

function runCliUnknownProfile(name: string, home: string): never {
  getProfile(name, home); // always throws the canonical UsageError
  throw new Error('unreachable');
}
```

- [ ] **Step 4: Replace `packages/cli/src/index.ts`**

```ts
#!/usr/bin/env node
import { runCli } from './main.js';

const io = {
  out: (line: string) => process.stdout.write(`${line}\n`),
  err: (line: string) => process.stderr.write(`${line}\n`),
};

process.exitCode = await runCli(process.argv.slice(2), io);
```

- [ ] **Step 5: Run tests + full suite**

Run: `npx vitest run packages/cli/tests/main.test.ts && npm test && npm run typecheck && npm run build`
Expected: main tests PASS (7); full monorepo suite green (865 + new cli tests); build green.

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/main.ts packages/cli/src/index.ts packages/cli/tests/main.test.ts
git commit -m "feat(cli): runCli dispatcher and fpx bin entry"
```

---

### Task 11: Release plumbing + docs

**Files:**
- Modify: `release-please-config.json`, root `README.md`
- Create: `packages/cli/README.md`

**Interfaces:** none (config + docs).

- [ ] **Step 1: Add cli to release-please `extra-files`** in `release-please-config.json`, keeping alphabetical position:

```json
{ "type": "json", "path": "packages/cli/package.json", "jsonpath": "$.version" },
{ "type": "generic", "path": "packages/cli/src/version.ts" },
```

(The `generic` updater rewrites the `x-release-please-version`-annotated line in `version.ts`.)

- [ ] **Step 2: Write `packages/cli/README.md`** — document: install (`npm i -g @fetchproxy/cli` / `npx`), the profile model (per-service identity `fpx-<name>`, pair-code flow, re-pair on scope change, revocation via extension popup), every verb with one example each, the output contract + exit-code table (0/1/2/3/4), `FETCHPROXY_CLI_HOME`, and the capability-parity note (why all verbs send the same hello). Add a "skills" section showing the tripadvisor-style usage: `fpx -p opentable get https://www.opentable.com/dapi/... | jq .`

- [ ] **Step 3: Add the workspace row to the root `README.md` package table** (after `@fetchproxy/test-helpers`):

```markdown
| [`@fetchproxy/cli`](packages/cli) | `fpx` — one-shot CLI for the bridge: per-service profiles, authenticated fetch/read/session verbs for skills and shell scripts. | `packages/cli/` |
```

Also update the intro sentence ("MCP servers … embed the library") to mention the CLI as a second consumer.

- [ ] **Step 4: Full verification**

Run: `npm run typecheck && npm run build && npm test`
Expected: all green. Then smoke the bin with no bridge running:
`FETCHPROXY_CLI_HOME=$(mktemp -d) node packages/cli/dist/index.js --help` → usage on stderr, exit 0;
`FETCHPROXY_CLI_HOME=$(mktemp -d) node packages/cli/dist/index.js profile add t --domain example.com` → exit 0.

- [ ] **Step 5: Commit**

```bash
git add release-please-config.json README.md packages/cli/README.md
git commit -m "feat(cli): release plumbing and docs for @fetchproxy/cli"
```

---

## Post-plan (human / PR steps — not part of task execution)

1. Open PR from `feat/cli` titled `feat(cli): @fetchproxy/cli one-shot bridge CLI (fpx)` with label `enhancement`; auto-review + auto-merge pipeline takes it from there. **Do not merge manually.**
2. **Human step before first release:** configure the npm Trusted Publisher for `@fetchproxy/cli` on npmjs.com (workflow `release-please.yml`), or its publish leg fails with `ENEEDAUTH`.
3. Live verification after the extension pairs: `fpx profile add opentable --domain opentable.com && fpx pair -p opentable && fpx -p opentable get https://www.opentable.com/ | head -c 300` (out-of-band, matching repo convention).
