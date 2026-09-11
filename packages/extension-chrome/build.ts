import { build, type BuildOptions } from 'esbuild';
import { mkdir, copyFile, readdir } from 'node:fs/promises';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, 'dist');
const CORE = resolve(HERE, '..', 'extension-core', 'src');

/**
 * Which build this is. The release `.zip` attached to every GitHub Release is
 * produced by the plain `tsx build.ts` the release workflow runs, so whatever
 * the DEFAULT is, is what ships — which is why `'release'` is the default and
 * `--dev` is the opt-in, rather than a release flag the workflow has to
 * remember. `npm run build:dev` is the developer's path.
 */
export type BuildMode = 'release' | 'development';

/**
 * Sourcemaps are a development affordance only. `sourcemap: 'inline'` was
 * unconditional, so the shipped `dist/background.js` (754 KB) carried a base64
 * copy of every extension-core and protocol source inside it.
 */
function sharedOptions(mode: BuildMode): BuildOptions {
  return {
    bundle: true,
    platform: 'browser',
    target: 'chrome120',
    outdir: OUT,
    sourcemap: mode === 'development' ? 'inline' : false,
  };
}

/**
 * The background service worker (manifest `"type": "module"`) and the
 * popup (loaded via `<script type="module">`) are genuine ES modules,
 * so they build with `format: 'esm'`.
 */
export function moduleEntryOptions(mode: BuildMode = 'release'): BuildOptions {
  return {
    ...sharedOptions(mode),
    format: 'esm',
    entryPoints: {
      background: join(CORE, 'background.ts'),
      popup: join(CORE, 'popup', 'popup.ts'),
    },
  };
}

/**
 * `content.ts` + `capture-logger.ts` are injected as **classic** content
 * scripts — MV3 has no module content scripts. A content-script file that
 * contains a top-level `import`/`export` statement is not a valid classic
 * script: Chrome silently refuses to inject it, so its
 * `chrome.runtime.onMessage` listener never registers and every
 * service-worker→content-script `sendMessage` fails with "Could not
 * establish connection. Receiving end does not exist." (surfaced by the
 * bridge as "N URL match(es), none responded").
 *
 * `format: 'iife'` wraps each bundle in a function expression and emits
 * **no** top-level `import`/`export`, regardless of what the source
 * module exports (e.g. `content.ts` exports `readDomValues` /
 * `runGraphqlQuery` and `capture-logger.ts` exports `installApolloBridge`
 * / `recordDocsFromLink` for unit tests). This is the invariant enforced
 * by `tests/content-scripts-classic.test.ts`. Do not switch these entries
 * back to `esm`.
 */
export function contentScriptEntryOptions(mode: BuildMode = 'release'): BuildOptions {
  return {
    ...sharedOptions(mode),
    format: 'iife',
    entryPoints: {
      content: join(CORE, 'content.ts'),
      'capture-logger': join(CORE, 'capture-logger.ts'),
    },
  };
}

async function main(mode: BuildMode): Promise<void> {
  await mkdir(OUT, { recursive: true });
  await mkdir(join(OUT, 'icons'), { recursive: true });

  // Two builds: ES-module entries (background, popup) and classic
  // content-script entries (content, capture-logger). See the option
  // docs above for why the split is load-bearing.
  await build(moduleEntryOptions(mode));
  await build(contentScriptEntryOptions(mode));

  // Copy static files.
  await copyFile(join(HERE, 'manifest.json'), join(OUT, 'manifest.json'));
  await copyFile(join(CORE, 'popup', 'popup.html'), join(OUT, 'popup.html'));
  // Icons (placeholder solid-color PNGs; replace with real artwork later)
  const iconsDir = join(HERE, 'icons');
  for (const f of await readdir(iconsDir)) {
    await copyFile(join(iconsDir, f), join(OUT, 'icons', f));
  }
  console.log(`extension-chrome built (${mode}) →`, OUT);
}

// Only build when run directly (`tsx build.ts`), not when imported by the
// regression tests (which call the exported option factories themselves).
// `--dev` is the only argument: release is the default because this same plain
// command is what the release workflow zips.
const invokedPath = process.argv[1] ? resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url) || invokedPath.endsWith('build.ts')) {
  void main(process.argv.includes('--dev') ? 'development' : 'release');
}
