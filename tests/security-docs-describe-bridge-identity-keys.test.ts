import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * §T-fake-extension says what the extension keeps at rest. #415 described how
 * the Safari bridge stored its long-term X25519 private key, because WebKit
 * IndexedDB silently stores an X25519 `CryptoKey` as `null` (macOS spike,
 * 2026-09-25) — wrapped under AES-GCM, or as PKCS#8 bytes. That key had no
 * caller in protocol 4 (session ECDH is ephemeral × ephemeral), so
 * nullnet-app/contextmint-bridge #21 stopped generating and storing it at all, on
 * every browser: the identity is the X25519 PUBLIC key (a handle) plus an
 * Ed25519 signing key. A threat model still describing storage forms for a
 * key that no longer exists would be a claim the code contradicts, and one
 * that still said "private halves" would overstate what a vault read yields.
 */

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const sec = readFileSync(join(ROOT, 'docs/SECURITY.md'), 'utf8');

/** The section starting at `heading`, up to the next `###`/`##` heading. */
function section(heading: string): string {
  const start = sec.indexOf(heading);
  expect(start, `${heading} not found`).toBeGreaterThanOrEqual(0);
  const rest = sec.slice(start + heading.length);
  const end = rest.search(/\n#{2,3} /);
  return end === -1 ? rest : rest.slice(0, end);
}

describe('SECURITY.md says the bridge keeps no X25519 private key', () => {
  const tfe = section('### T-fake-extension');

  it('says the bridge no longer keeps a long-term X25519 private key, on any browser', () => {
    expect(tfe).toMatch(/no longer (generates|keeps|holds)[^.]*X25519 private key/i);
    expect(tfe).toMatch(/every browser/i);
    expect(tfe).toMatch(/no caller in protocol 4/i);
  });

  it('says what the identity is now: the X25519 public key as a handle plus an Ed25519 signing key', () => {
    expect(tfe).toMatch(/X25519 public key[^.]*(identity )?handle/i);
    expect(tfe).toMatch(/Ed25519 signing key/);
    expect(tfe).toMatch(/Ed25519[^.]*non-extractable `CryptoKey`/);
  });

  it('keeps the WebKit finding as the reason, and says the storage forms are gone', () => {
    expect(tfe).toMatch(/WebKit/);
    expect(tfe).toMatch(/X25519 `CryptoKey`[^.]*`null`/);
    expect(tfe).toMatch(/wrapped/);
    expect(tfe).toMatch(/PKCS#8/);
    expect(tfe).toMatch(/discard/i);
  });

  it('says existing pairings survive because the public key is kept', () => {
    expect(tfe).toMatch(/(keeps|kept)[^.]*public key/i);
    expect(tfe).toMatch(/nobody re-pairs|no MCP (sees|asks)|without a re-pair/i);
  });

  it('no longer claims a storage form is pending a live Safari check', () => {
    expect(tfe).not.toMatch(/expected `wrapped`, pending the live check/);
    expect(tfe).not.toMatch(/Which form real Safari takes/);
  });

  it('does not describe the vault as holding X25519 private halves', () => {
    expect(tfe).not.toMatch(/The private halves are now/);
  });

  it('links the merged bridge code that drops the key and migrates old vaults (contextmint-bridge #21)', () => {
    const base =
      'https://github.com/nullnet-app/contextmint-bridge/blob/main/packages/extension-core/src/';
    expect(tfe).toContain(`(${base}identity-keys.ts)`);
    expect(tfe).toContain(`(${base}identity-storage.ts)`);
    expect(tfe).toMatch(/contextmint-bridge` #21/);
  });

  it('flags storage.session on Safari as unverified in Defense 4', () => {
    const t3 = section('### T3');
    expect(t3).toMatch(/`storage\.session`[^.]*unverified on Safari/i);
  });
});
