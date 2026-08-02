import { describe, it, expect } from 'vitest';
import { build } from 'esbuild';
import { readFile } from 'node:fs/promises';
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
 * worked while every `fetch()` died. The graphql-capability work then added
 * top-level exports to `capture-logger.ts` too (`installApolloBridge`,
 * `recordDocsFromLink`), so both worlds are inert without the iife split.
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
  // The previous version of this test asserted `moduleEntryOptions.format ===
  // 'esm'` — re-stating the config object to itself, which cannot fail for any
  // reason a reader would care about. The invariant actually worth guarding
  // spans TWO artifacts that are edited independently: manifest.json declares
  // `background.type`, and build.ts decides the format the service worker is
  // compiled to. Chrome refuses to start the worker when those disagree
  // ("type": "module" + an IIFE bundle, or a bare worker fed ESM), and nothing
  // else in the build would catch the drift.
  it('the built service worker matches the type manifest.json declares', async () => {
    const manifest = JSON.parse(
      await readFile(new URL('../manifest.json', import.meta.url), 'utf8'),
    ) as { background: { service_worker: string; type?: string } };

    const files = await bundleText(moduleEntryOptions);
    const worker = files.find((f) =>
      f.path.endsWith('/' + manifest.background.service_worker),
    );
    // Guard against the build silently emitting nothing under this name.
    expect(worker, `no build output named ${manifest.background.service_worker}`)
      .toBeDefined();
    expect(worker!.text.length).toBeGreaterThan(0);

    // esbuild wraps `format: 'iife'` output in an invoked function expression
    // and leaves `format: 'esm'` output at the top level. That difference is
    // observable in the emitted text, so it holds the build honest rather than
    // trusting the options object.
    const isIife = /^\s*\(\s*\(\s*\)\s*=>\s*\{/m.test(worker!.text);
    if (manifest.background.type === 'module') {
      expect(isIife, 'manifest says type:module but the worker built as IIFE').toBe(false);
    } else {
      expect(isIife, 'manifest omits type:module but the worker built as ESM').toBe(true);
    }
  });

  it('content scripts build to the opposite format from the service worker', async () => {
    // The pair matters more than either value alone: MV3 has no module content
    // scripts, so these two entries must never converge on one format.
    expect(moduleEntryOptions.format).not.toBe(contentScriptEntryOptions.format);
    expect(contentScriptEntryOptions.format).toBe('iife');
  });
});
