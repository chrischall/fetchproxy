import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync, readdirSync, statSync, existsSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import {
  defaultTrustDir,
  fileExtensionTrust,
  resolveTrustDir,
  TRUST_DIR_ENV,
} from '../src/extension-trust.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { FetchproxyServer } from '../src/index.js';

/**
 * `FETCHPROXY_TRUST_DIR` — the extension pin gets a home of its own.
 *
 * The pin has always lived beside the identity, which is right on a laptop
 * and wrong the moment a host PROVISIONS the identity: mcp-host writes
 * `<identityDir>/<server-name>.json` for the child and mounts that directory
 * read-only, so the one file the MCP has to WRITE — the pin it takes on the
 * extension's identity after the ready signature verifies — cannot be
 * written. Nothing fails loudly: `host.ts` logs `could not persist the
 * extension pin` and carries on, so every boot is trust-on-first-use and the
 * pin closes nothing. Splitting the directories is what lets the identity
 * stay read-only and the pin still persist.
 *
 * Held to the same contract as `FETCHPROXY_IDENTITY_DIR`: absolute or
 * nothing, an explicit option beats the environment, and the default is
 * exactly where the pin has always been.
 */
const HOME_IDENTITY = join(homedir(), '.fetchproxy', 'identity');

const PIN = {
  identityX25519Pub: 'QUFB',
  identityEd25519Pub: 'QkJC',
  pinnedAt: 1_700_000_000_000,
};

describe('FETCHPROXY_TRUST_DIR', () => {
  afterEach(() => {
    delete process.env[TRUST_DIR_ENV];
    delete process.env.FETCHPROXY_IDENTITY_DIR;
    vi.restoreAllMocks();
  });

  it('is unset by default, and the pin stays beside the identity', () => {
    expect(defaultTrustDir()).toBe(HOME_IDENTITY);
    // …including when the identity itself has been moved: the pin follows it
    // unless someone says otherwise, which is the pre-2.12 behaviour whole.
    const idDir = mkdtempSync(join(tmpdir(), 'fp-trust-id-'));
    process.env.FETCHPROXY_IDENTITY_DIR = idDir;
    expect(defaultTrustDir()).toBe(idDir);
    expect(fileExtensionTrust({ serverName: 'opentable-mcp', allowNew: false }).location).toBe(
      join(idDir, 'opentable-mcp.extension-trust.json'),
    );
  });

  it('puts the pin under the trust dir and the identity under the identity dir', async () => {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-trust-idonly-'));
    const trustRoot = mkdtempSync(join(tmpdir(), 'fp-trust-'));
    // Not created yet: a host points this at a persistent volume and the
    // directory itself is ours to make.
    const trustDir = join(trustRoot, 'pins');
    process.env.FETCHPROXY_IDENTITY_DIR = idDir;
    process.env[TRUST_DIR_ENV] = trustDir;

    await loadOrCreateIdentity('opentable-mcp');
    const port = fileExtensionTrust({ serverName: 'opentable-mcp', allowNew: false });
    await port.write(PIN);

    expect(readdirSync(idDir)).toEqual(['opentable-mcp.json']);
    expect(readdirSync(trustDir)).toEqual(['opentable-mcp.extension-trust.json']);
    expect(port.location).toBe(join(trustDir, 'opentable-mcp.extension-trust.json'));
    expect(await port.read()).toEqual(PIN);
    // 0700 on the directory we created, 0600 on the pin: it is a trust
    // record sitting on a volume the host also mounts elsewhere.
    expect(statSync(trustDir).mode & 0o777).toBe(0o700);
    expect(statSync(port.location!).mode & 0o777).toBe(0o600);
  });

  it('ignores a relative path, and says so rather than failing to persist in silence', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    for (const bad of ['', '   ', '.fetchproxy/pins', './pins', '../pins', 'pins']) {
      process.env[TRUST_DIR_ENV] = bad;
      expect(defaultTrustDir(), JSON.stringify(bad)).toBe(HOME_IDENTITY);
      expect(isAbsolute(defaultTrustDir())).toBe(true);
    }
    expect(warn).toHaveBeenCalled();
    expect(warn.mock.calls.map((c) => String(c[0])).join('\n')).toContain(TRUST_DIR_ENV);
  });

  it('loses to an explicit trustDir, and beats the identity dir', () => {
    const env = mkdtempSync(join(tmpdir(), 'fp-trust-env-'));
    const explicit = mkdtempSync(join(tmpdir(), 'fp-trust-opt-'));
    const idDir = mkdtempSync(join(tmpdir(), 'fp-trust-idarg-'));
    process.env[TRUST_DIR_ENV] = env;
    // opt → env → identityDir, the order `identityDir` itself already keeps.
    expect(resolveTrustDir(explicit, idDir)).toBe(explicit);
    expect(resolveTrustDir(undefined, idDir)).toBe(env);
    delete process.env[TRUST_DIR_ENV];
    expect(resolveTrustDir(undefined, idDir)).toBe(idDir);
  });

  it('is what FetchproxyServer pins through', async () => {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-trust-srv-id-'));
    const trustDir = mkdtempSync(join(tmpdir(), 'fp-trust-srv-'));
    const srv = new FetchproxyServer({
      port: 0,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      identityDir: idDir,
      trustDir,
    });
    try {
      const port = (
        srv as unknown as { extensionTrust(): { location?: string } }
      ).extensionTrust();
      expect(port.location).toBe(join(trustDir, 'opentable-mcp.extension-trust.json'));
      expect(existsSync(join(idDir, 'opentable-mcp.extension-trust.json'))).toBe(false);
    } finally {
      await srv.close();
    }
  });
});
