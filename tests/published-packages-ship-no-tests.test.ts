import { describe, it, expect } from 'vitest';
import { execFile } from 'node:child_process';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const run = promisify(execFile);
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const TSC = join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc');

/**
 * `@fetchproxy/server` shipped `dist/session-ready.test.js` — a compiled test
 * file, importing `vitest`, inside the package every cohort MCP installs and
 * every mcp-host tenant child therefore holds. Its tsconfig said
 * `include: ["src/**\/*"]` and nothing else, so a test file placed beside the
 * source it covers was compiled and published along with it.
 *
 * The guard asks TSC ITSELF which files a package compiles — `--showConfig`
 * resolves `files`/`include`/`exclude` into the final list — rather than
 * reading an `exclude` line back to itself. A second test file under `src/`,
 * or an `exclude` narrowed so it stops covering one, fails here. The
 * workspaces are DISCOVERED rather than listed, so a published package written
 * tomorrow is governed the day it is written.
 */
const TEST_FILE = /\.(test|spec)\.[cm]?tsx?$/;

/** Read synchronously: `it.each` needs the list at collection time. */
function publishedWorkspaces(): { name: string; tsconfig: string }[] {
  const out: { name: string; tsconfig: string }[] = [];
  for (const entry of readdirSync(join(ROOT, 'packages'))) {
    const dir = join(ROOT, 'packages', entry);
    const manifestPath = join(dir, 'package.json');
    if (!existsSync(manifestPath)) continue;
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8')) as {
      name: string;
      private?: boolean;
    };
    // A private workspace is never published, so nothing of it ships. The two
    // here (extension-core, extension-chrome) reach a user only as esbuild
    // output bundled from named entry points, which a test file is not.
    if (manifest.private) continue;
    const tsconfig = join(dir, 'tsconfig.json');
    if (!existsSync(tsconfig)) continue;
    out.push({ name: manifest.name, tsconfig });
  }
  return out;
}

const PUBLISHED = publishedWorkspaces();

describe('published packages compile no test file into what ships', () => {
  it('found the published workspaces', () => {
    // Guard against a discovery bug emptying the sweep, which would make every
    // case below vacuous and silent.
    expect(PUBLISHED.map((p) => p.name).sort()).toEqual([
      '@fetchproxy/bootstrap',
      '@fetchproxy/cli',
      '@fetchproxy/protocol',
      '@fetchproxy/server',
      '@fetchproxy/test-helpers',
    ]);
  });

  it.each(PUBLISHED.map((p) => [p.name, p.tsconfig] as const))(
    '%s compiles no *.test.ts',
    async (_name, tsconfig) => {
      const { stdout } = await run(process.execPath, [TSC, '-p', tsconfig, '--showConfig'], {
        cwd: ROOT,
        maxBuffer: 16 * 1024 * 1024,
      });
      const config = JSON.parse(stdout) as { files?: string[] };
      // Guard against --showConfig answering with an empty list, which would
      // pass for the wrong reason.
      expect(config.files?.length ?? 0).toBeGreaterThan(0);
      expect(config.files!.filter((f) => TEST_FILE.test(f))).toEqual([]);
    },
  );
});
