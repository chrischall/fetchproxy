import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join, isAbsolute } from 'node:path';
import { defaultIdentityDir, loadOrCreateIdentity } from '../src/identity.js';

/**
 * `FETCHPROXY_IDENTITY_DIR` (#316).
 *
 * The identity answers "which MCP is the browser talking to" — a property of
 * the SERVER — but it is stored under `$HOME`, which on a host that runs one
 * child per CALLER is per-process. Each caller therefore got its own identity,
 * and an extension whose trust store is keyed by the sha256 of that identity
 * asked to pair with every one of them. `identityDir` already existed as a code
 * option, and a hosted MCP is third-party code that calls `serve()` itself, so
 * the host had no way to reach it.
 *
 * These tests hold the variable to the same contract `envWsPort` and
 * `envWsHost` keep: anything unusable falls through to the default rather than
 * to a directory nobody chose.
 */
const HOME_DEFAULT = join(homedir(), '.fetchproxy', 'identity');

describe('FETCHPROXY_IDENTITY_DIR', () => {
  afterEach(() => {
    delete process.env.FETCHPROXY_IDENTITY_DIR;
  });

  it('is unset by default, and nothing moves', () => {
    expect(defaultIdentityDir()).toBe(HOME_DEFAULT);
  });

  it('redirects the identity when it names an absolute path', () => {
    const dir = mkdtempSync(join(tmpdir(), 'fp-id-'));
    process.env.FETCHPROXY_IDENTITY_DIR = dir;
    expect(defaultIdentityDir()).toBe(dir);
  });

  /**
   * The whole point, driven end to end: two processes that share the variable
   * share the identity, which is what makes one pairing serve every caller.
   * Asserted on the KEY rather than on the path, because the extension's trust
   * record is keyed by the identity and not by where it was read from.
   */
  it('gives two callers the same identity, which is the bug it fixes', async () => {
    const shared = mkdtempSync(join(tmpdir(), 'fp-id-shared-'));
    process.env.FETCHPROXY_IDENTITY_DIR = shared;
    const first = await loadOrCreateIdentity('opentable-mcp');
    const second = await loadOrCreateIdentity('opentable-mcp');
    expect(Buffer.from(second.x25519Pub)).toEqual(Buffer.from(first.x25519Pub));
    expect(second.createdAt).toBe(first.createdAt);
    // One file, not one per caller.
    expect(readdirSync(shared)).toEqual(['opentable-mcp.json']);
  });

  /** Two DIFFERENT directories still mean two identities — the control. */
  it('does not make every server share one identity', async () => {
    const a = mkdtempSync(join(tmpdir(), 'fp-id-a-'));
    const b = mkdtempSync(join(tmpdir(), 'fp-id-b-'));
    process.env.FETCHPROXY_IDENTITY_DIR = a;
    const first = await loadOrCreateIdentity('opentable-mcp');
    process.env.FETCHPROXY_IDENTITY_DIR = b;
    const second = await loadOrCreateIdentity('opentable-mcp');
    expect(Buffer.from(second.x25519Pub)).not.toEqual(Buffer.from(first.x25519Pub));
  });

  /**
   * A RELATIVE path is ignored rather than resolved. It would land against the
   * child's working directory — not a place the operator wrote down, and one
   * that can differ between the process that minted the identity and the next
   * to look for it, which is this bug reintroduced by its own fix.
   */
  it('ignores anything that is not an absolute path', () => {
    for (const bad of ['', '   ', '.fetchproxy/identity', './id', '../id', 'id']) {
      process.env.FETCHPROXY_IDENTITY_DIR = bad;
      expect(defaultIdentityDir(), JSON.stringify(bad)).toBe(HOME_DEFAULT);
      expect(isAbsolute(defaultIdentityDir())).toBe(true);
    }
  });

  /** An explicit option beats an ambient one, as it does for host and port. */
  it('loses to an explicit dir argument', async () => {
    const env = mkdtempSync(join(tmpdir(), 'fp-id-env-'));
    const explicit = mkdtempSync(join(tmpdir(), 'fp-id-arg-'));
    process.env.FETCHPROXY_IDENTITY_DIR = env;
    await loadOrCreateIdentity('opentable-mcp', explicit);
    expect(readdirSync(explicit)).toEqual(['opentable-mcp.json']);
    expect(readdirSync(env)).toEqual([]);
  });
});
