import { build, type BuildOptions } from 'esbuild';
import { mkdir, copyFile, readdir } from 'node:fs/promises';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, 'dist');
const CORE = resolve(HERE, '..', 'extension-core', 'src');

const SHARED: BuildOptions = {
  bundle: true,
  platform: 'browser',
  target: 'chrome120',
  outdir: OUT,
  sourcemap: 'inline',
};

/**
 * The background service worker (manifest `"type": "module"`) and the
 * popup (loaded via `<script type="module">`) are genuine ES modules,
 * so they build with `format: 'esm'`.
 */
export const moduleEntryOptions: BuildOptions = {
  ...SHARED,
  format: 'esm',
  entryPoints: {
    background: join(CORE, 'background.ts'),
    popup: join(CORE, 'popup', 'popup.ts'),
  },
};

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
export const contentScriptEntryOptions: BuildOptions = {
  ...SHARED,
  format: 'iife',
  entryPoints: {
    content: join(CORE, 'content.ts'),
    'capture-logger': join(CORE, 'capture-logger.ts'),
  },
};

async function main(): Promise<void> {
  await mkdir(OUT, { recursive: true });
  await mkdir(join(OUT, 'icons'), { recursive: true });

  // Two builds: ES-module entries (background, popup) and classic
  // content-script entries (content, capture-logger). See the option
  // docs above for why the split is load-bearing.
  await build(moduleEntryOptions);
  await build(contentScriptEntryOptions);

  // Copy static files.
  await copyFile(join(HERE, 'manifest.json'), join(OUT, 'manifest.json'));
  await copyFile(join(CORE, 'popup', 'popup.html'), join(OUT, 'popup.html'));
  // Icons (placeholder solid-color PNGs; replace with real artwork later)
  const iconsDir = join(HERE, 'icons');
  for (const f of await readdir(iconsDir)) {
    await copyFile(join(iconsDir, f), join(OUT, 'icons', f));
  }
  console.log('extension-chrome built →', OUT);
}

// Only build when run directly (`tsx build.ts`), not when imported by the
// regression test (which reuses the exported option objects).
const invokedPath = process.argv[1] ? resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url) || invokedPath.endsWith('build.ts')) {
  void main();
}
