import { describe, it, expect } from 'vitest';
import { build } from 'esbuild';
import { contentScriptEntryOptions, moduleEntryOptions } from '../build.js';

/**
 * Regression guard for the "Receiving end does not exist" bridge outage.
 *
 * MV3 injects content scripts as **classic** scripts. A built
 * content-script file that carries a top-level `import`/`export` statement
 * is not valid as a classic script — Chrome silently refuses to inject it,
 * so `content.ts`'s `chrome.runtime.onMessage` listener never registers and
 * every fetch through the bridge fails with
 * "Could not establish connection. Receiving end does not exist."
 *
 * This shipped for real: commit 0ce0949 (#148) added
 * `export function readDomValues` to `content.ts`, and the build compiled
 * every entry as `format: 'esm'`, so `content.js` ended in
 * `export { readDomValues };` and stopped injecting. `capture-logger.js`
 * (no exports) kept injecting, which is why storage/CSRF capture still
 * worked while every `fetch()` died.
 *
 * The invariant: the content-script entries must build to import/export-free
 * output (`format: 'iife'`), no matter what their source modules export.
 */

const TOP_LEVEL_EXPORT = /^\s*export[\s{*]/m;
// `import(` (dynamic import) is legal in a classic script; a top-level
// `import ...` / `import {` / `import "x"` statement is not.
const TOP_LEVEL_IMPORT = /^\s*import[\s{'"*]/m;

async function bundleText(options: typeof contentScriptEntryOptions) {
  const result = await build({
    ...options,
    write: false,
    sourcemap: false, // keep output text free of base64 map noise
  });
  return result.outputFiles.map((f) => ({ path: f.path, text: f.text }));
}

describe('content scripts build as classic (injectable) scripts', () => {
  it('emit no top-level import/export so Chrome MV3 injects them', async () => {
    const files = await bundleText(contentScriptEntryOptions);
    // Guard against the build silently producing nothing.
    expect(files.map((f) => f.path).join(',')).toMatch(/content\.js/);
    expect(files.map((f) => f.path).join(',')).toMatch(/capture-logger\.js/);

    for (const { path, text } of files) {
      expect(TOP_LEVEL_EXPORT.test(text), `${path} has a top-level export`).toBe(false);
      expect(TOP_LEVEL_IMPORT.test(text), `${path} has a top-level import`).toBe(false);
    }
  });

  it('content.js still registers its onMessage listener (sanity)', async () => {
    const files = await bundleText(contentScriptEntryOptions);
    const content = files.find((f) => /content\.js$/.test(f.path));
    expect(content).toBeDefined();
    expect(content!.text).toContain('onMessage');
    expect(content!.text).toContain('fetchproxy-fetch');
  });
});

describe('module entries (background, popup) remain ES modules', () => {
  it('background is loaded as a module service worker', async () => {
    // Not asserting on export/import here — background is declared
    // `"type": "module"` in the manifest and popup via
    // `<script type="module">`, so ESM output is correct for them.
    expect(moduleEntryOptions.format).toBe('esm');
    expect(contentScriptEntryOptions.format).toBe('iife');
  });
});
