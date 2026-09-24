import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * The privacy policy is read by people deciding whether to install the
 * extension, so a network path it leaves out is a claim the code contradicts.
 *
 * - fleet-audit #1004: PRIVACY.md §4 listed two network paths and said the
 *   extension makes no outbound connections, while user-configured remote
 *   bridge targets are outbound `wss://` connections carrying hellos, mcpIds
 *   and pair codes to a relay.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (path: string): string => readFileSync(join(ROOT, path), 'utf8');

function section(md: string, heading: RegExp): string {
  const lines = md.split('\n');
  const start = lines.findIndex((l) => heading.test(l));
  if (start < 0) return '';
  const rest = lines.slice(start + 1);
  const end = rest.findIndex((l) => /^## /.test(l));
  return (end < 0 ? rest : rest.slice(0, end)).join('\n');
}

describe('PRIVACY.md §4 names every network path', () => {
  const s4 = section(read('docs/PRIVACY.md'), /^## 4\. /);

  it('lists outbound connections to user-configured remote bridge targets', () => {
    expect(s4).toMatch(/remote bridge target/i);
    expect(s4).toMatch(/wss:\/\//);
    expect(s4).toMatch(/off by default|none (are|is) configured by default|only if you add/i);
  });

  it('says what the relay operator can see', () => {
    expect(s4).toMatch(/pair code/i);
    expect(s4).toMatch(/mcpId|MCP identifier/i);
  });

  it('no longer claims the extension makes no outbound connections at all', () => {
    expect(s4).not.toMatch(/makes no outbound network connections of its own\./);
  });
});
