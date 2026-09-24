import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The security model and the extension README are read by people deciding
 * whether to install the extension, so a page-visible surface they leave
 * out is a claim the code contradicts.
 *
 * - fleet-audit #1003: SECURITY.md described fingerprinting as history, while
 *   the MAIN-world bridge answered a same-window probe on every site. The
 *   bridge is now registered only on approved hosts; the docs must say so and
 *   name what remains detectable.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (path: string): string => readFileSync(join(ROOT, path), 'utf8');

describe('SECURITY.md describes where the MAIN-world bridge runs', () => {
  const sec = read('docs/SECURITY.md');

  it('says the bridge is limited to approved hosts and what stays detectable', () => {
    expect(sec).toMatch(/main-world-bridge\.ts/);
    expect(sec).toMatch(/approved (MCP )?hosts?/i);
    expect(sec).toMatch(/can still detect/i);
  });

  it('no longer says the bridges install on every page', () => {
    expect(sec).not.toMatch(/on \*\*every\*\* page the content script runs in/);
    expect(sec).not.toMatch(/wraps `client\.link\.request` on \*\*every\*\* page/);
  });
});

describe('extension-chrome README', () => {
  it('does not describe capture-logger.js as a manifest content script on <all_urls>', () => {
    const readme = read('packages/extension-chrome/README.md');
    expect(readme).not.toMatch(/registers `capture-logger\.js` as a `world: MAIN`, `document_start` script on `<all_urls>`/);
    expect(readme).not.toMatch(/MAIN-world capture helper \(`capture-logger\.js`\) at `<all_urls>`/);
  });
});
