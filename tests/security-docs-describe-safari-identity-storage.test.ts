import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * §T-fake-extension says the extension's private keys are non-extractable
 * `CryptoKey`s persisted by structured clone. On Safari that is not what the
 * bridge does: WebKit IndexedDB silently stores an X25519 `CryptoKey` as
 * `null` (macOS spike, 2026-09-25), so nullnet-app/contextmint-bridge
 * packages/extension-core/src/identity-storage.ts probes the vault and keeps
 * that one key wrapped under an AES-GCM key — or, where even that is nulled,
 * as PKCS#8 bytes. A threat model that still claimed "non-extractable at rest"
 * for every browser would be a claim the code contradicts, so the section must
 * say which forms exist, what the fallback weakens, and what is still
 * unverified on Safari.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const sec = readFileSync(join(ROOT, 'docs/SECURITY.md'), 'utf8');

/** The §T-fake-extension section, up to the next `###`/`##` heading. */
function section(heading: string): string {
  const start = sec.indexOf(heading);
  expect(start, `${heading} not found`).toBeGreaterThanOrEqual(0);
  const rest = sec.slice(start + heading.length);
  const end = rest.search(/\n#{2,3} /);
  return end === -1 ? rest : rest.slice(0, end);
}

describe('SECURITY.md says how the Safari bridge stores its identity keys', () => {
  const tfe = section('### T-fake-extension');

  it('names the WebKit X25519 nulling and that the form is probed, not sniffed', () => {
    expect(tfe).toMatch(/Safari/);
    expect(tfe).toMatch(/WebKit/);
    expect(tfe).toMatch(/X25519 `CryptoKey`[^.]*`null`/);
    expect(tfe).toMatch(/probe/i);
    expect(tfe).toMatch(/never (by )?(a )?(sniffing the )?user[- ]agent|never a UA sniff/i);
  });

  it('describes the wrapped form and the PKCS#8 fallback, and what the fallback weakens', () => {
    expect(tfe).toMatch(/wrapped/);
    expect(tfe).toMatch(/non-extractable AES-GCM/);
    expect(tfe).toMatch(/PKCS#8/);
    expect(tfe).toMatch(/extractable at rest/i);
    expect(tfe).toMatch(/not websites or content scripts|no website or content script/i);
  });

  it('bounds the exposure: X25519 has no caller in protocol 4, Ed25519 is unaffected', () => {
    expect(tfe).toMatch(/no caller in protocol 4/i);
    expect(tfe).toMatch(/Ed25519[^.]*unaffected/i);
  });

  it('links the bridge code that implements it', () => {
    expect(tfe).toMatch(
      /https:\/\/github\.com\/nullnet-app\/contextmint-bridge\/blob\/main\/packages\/extension-core\/src\/identity-storage\.ts/,
    );
  });

  it('does not claim a live Safari result nobody has recorded yet', () => {
    expect(tfe).toMatch(/expected `wrapped`, pending the live check/);
  });

  it('flags storage.session on Safari as unverified in Defense 4', () => {
    const t3 = section('### T3');
    expect(t3).toMatch(/`storage\.session`[^.]*unverified on Safari/i);
  });
});
