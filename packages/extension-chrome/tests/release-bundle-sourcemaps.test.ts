import { describe, it, expect } from 'vitest';
import { build, type BuildOptions } from 'esbuild';
import { contentScriptEntryOptions, moduleEntryOptions } from '../build.js';

/**
 * The release `.zip` attached to every GitHub Release is built by the plain
 * `tsx build.ts` the release workflow runs, so whatever that command's DEFAULT
 * is, is what ships. It used to be `sourcemap: 'inline'`, which put a
 * base64 copy of every extension-core and protocol source inside
 * `dist/background.js` (754 KB of it).
 *
 * So release is the default and the sourcemaps are the opt-in: a workflow that
 * forgets a flag ships the stripped bundle, never the other way round. Both
 * halves are pinned here — the second one because "strip the maps" is
 * satisfiable by deleting the dev affordance outright, and a developer
 * reloading the unpacked extension is who needs it.
 *
 * Asserted on the EMITTED TEXT rather than on the options object, which would
 * only restate `build.ts` to itself.
 */
async function bundle(options: BuildOptions) {
  const result = await build({ ...options, write: false });
  return result.outputFiles.map((f) => ({ path: f.path, text: f.text }));
}

const SOURCEMAP_COMMENT = /\/\/# sourceMappingURL=/;

describe('the release extension bundle carries no sourcemaps', () => {
  it.each([
    ['module entries', moduleEntryOptions],
    ['content-script entries', contentScriptEntryOptions],
  ])('%s emit no map file and no sourceMappingURL', async (_label, options) => {
    const files = await bundle(options('release'));
    // Guard against the build silently emitting nothing.
    expect(files.length).toBeGreaterThan(0);

    for (const { path, text } of files) {
      expect(path.endsWith('.map'), `${path} is a sourcemap`).toBe(false);
      expect(SOURCEMAP_COMMENT.test(text), `${path} has a sourceMappingURL`).toBe(false);
    }
  });

  it('release is the DEFAULT, so the plain `tsx build.ts` ships stripped', async () => {
    const files = await bundle(moduleEntryOptions());
    for (const { path, text } of files) {
      expect(path.endsWith('.map'), `${path} is a sourcemap`).toBe(false);
      expect(SOURCEMAP_COMMENT.test(text), `${path} has a sourceMappingURL`).toBe(false);
    }
  });
});

describe('the development bundle keeps its sourcemaps', () => {
  it.each([
    ['module entries', moduleEntryOptions],
    ['content-script entries', contentScriptEntryOptions],
  ])('%s are still debuggable', async (_label, options) => {
    const files = await bundle(options('development'));
    expect(files.length).toBeGreaterThan(0);
    for (const { path, text } of files) {
      expect(SOURCEMAP_COMMENT.test(text), `${path} lost its sourceMappingURL`).toBe(true);
    }
  });
});
