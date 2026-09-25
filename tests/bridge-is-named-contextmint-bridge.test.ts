import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

// The browser extension left this repo for nullnet-app/contextmint-bridge and
// ships as **ContextMint Bridge**. Its old sideload name, "Transporter", was
// printed by @fetchproxy/server and @fetchproxy/cli in pair prompts, scope
// errors and version refusals — the exact sentences a person reads when the
// bridge needs something from them. A name they cannot find in their browser's
// extension list is a dead end, so the published sources and package READMEs
// must never say it again.
const ROOT = join(import.meta.dirname, '..');

function filesUnder(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? filesUnder(path) : [path];
  });
}

const GUARDED = [
  ...filesUnder(join(ROOT, 'packages/server/src')),
  ...filesUnder(join(ROOT, 'packages/cli/src')),
  ...['protocol', 'server', 'bootstrap', 'cli', 'test-helpers']
    .map((p) => join(ROOT, 'packages', p, 'README.md'))
    .filter((f) => existsSync(f)),
];

describe('user-facing bridge name', () => {
  it.each(GUARDED.map((f) => relative(ROOT, f)))('%s never says "Transporter"', (file) => {
    const text = readFileSync(join(ROOT, file), 'utf8');
    const hits = text.split('\n').flatMap((line, i) => (line.includes('Transporter') ? [`${i + 1}: ${line.trim()}`] : []));
    expect(hits).toEqual([]);
  });
});
