import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Audit #1003: a MAIN-world script declared in the manifest runs on every site
// the user visits, and its postMessage bridges answer any page that asks —
// an extension fingerprint on sites no MCP is paired with. capture-logger.js
// is registered at runtime for approved hosts only (main-world-bridge.ts).
const manifest = JSON.parse(
  readFileSync(fileURLToPath(new URL('../manifest.json', import.meta.url)), 'utf8'),
) as { content_scripts?: { js?: string[]; world?: string; matches?: string[] }[] };

describe('manifest content_scripts', () => {
  it('declares no MAIN-world script', () => {
    const main = (manifest.content_scripts ?? []).filter(
      (cs) => cs.world === 'MAIN' || (cs.js ?? []).includes('capture-logger.js'),
    );
    expect(main).toEqual([]);
  });
});
