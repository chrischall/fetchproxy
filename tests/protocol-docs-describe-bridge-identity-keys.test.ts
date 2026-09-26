import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * PROTOCOL.md's note on the extension's long-term identity points readers at
 * SECURITY.md §T-fake-extension. Since nullnet-app/contextmint-bridge #21 the
 * bridge keeps no X25519 private key: its identity is the X25519 PUBLIC key
 * (a handle) plus an Ed25519 signing key, and only that one private key is a
 * non-extractable WebCrypto key. The note said "private halves" (plural) after
 * #419 fixed SECURITY.md (#420); keep the two documents saying the same thing.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const proto = readFileSync(join(ROOT, 'docs/PROTOCOL.md'), 'utf8');

describe("PROTOCOL.md describes the extension's identity keys as SECURITY.md does", () => {
  const start = proto.indexOf('(0.4.0 gave the extension a long-term identity of its own; it authenticates');
  const note = proto.slice(start, proto.indexOf('\n\n', start));

  it('finds the note', () => {
    expect(start).toBeGreaterThanOrEqual(0);
    expect(note).toMatch(/SECURITY\.md §T-fake-extension/);
  });

  it('no longer says the extension keeps plural private halves', () => {
    expect(note).not.toMatch(/private halves/i);
  });

  it('says the only private key is the Ed25519 signing key, non-extractable', () => {
    expect(note).toMatch(/Ed25519 signing key[^.]*non-extractable/i);
    expect(note).toMatch(/no X25519 private key/i);
    expect(note).toMatch(/contextmint-bridge` #21/);
  });
});
