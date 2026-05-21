import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtempSync, statSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadOrCreateIdentity } from '../src/identity.js';

describe('identity', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'fetchproxy-id-'));
  });

  it('creates a new keypair on first load', async () => {
    const id = await loadOrCreateIdentity('opentable-mcp', dir);
    expect(id.x25519Pub.byteLength).toBe(32);
    expect(id.x25519Priv.byteLength).toBe(32);
    expect(id.ed25519Pub.byteLength).toBe(32);
    expect(id.ed25519Priv.byteLength).toBe(32);
  });

  it('writes file with mode 0600', async () => {
    await loadOrCreateIdentity('opentable-mcp', dir);
    const path = join(dir, 'opentable-mcp.json');
    const mode = statSync(path).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('reuses existing keypair on second load', async () => {
    const a = await loadOrCreateIdentity('opentable-mcp', dir);
    const b = await loadOrCreateIdentity('opentable-mcp', dir);
    expect(Buffer.from(a.x25519Pub).equals(Buffer.from(b.x25519Pub))).toBe(true);
    expect(Buffer.from(a.ed25519Priv).equals(Buffer.from(b.ed25519Priv))).toBe(true);
  });

  it('separate server names get separate identities', async () => {
    const a = await loadOrCreateIdentity('opentable-mcp', dir);
    const b = await loadOrCreateIdentity('resy-mcp', dir);
    expect(Buffer.from(a.x25519Pub).equals(Buffer.from(b.x25519Pub))).toBe(false);
  });

  it('file contents are JSON with expected shape', async () => {
    await loadOrCreateIdentity('opentable-mcp', dir);
    const path = join(dir, 'opentable-mcp.json');
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    expect(typeof parsed.x25519Priv).toBe('string');
    expect(typeof parsed.x25519Pub).toBe('string');
    expect(typeof parsed.ed25519Priv).toBe('string');
    expect(typeof parsed.ed25519Pub).toBe('string');
    expect(typeof parsed.createdAt).toBe('number');
  });

  it('rejects server names with path separators or traversal', async () => {
    await expect(loadOrCreateIdentity('../etc/passwd', dir)).rejects.toThrow();
    await expect(loadOrCreateIdentity('a/b', dir)).rejects.toThrow();
    await expect(loadOrCreateIdentity('..', dir)).rejects.toThrow();
  });

  it('handles scoped package names by replacing / with _', async () => {
    // Some MCP packages are scoped (e.g. @fetchproxy/example-mcp) — the safe
    // serverName should still produce a valid file.
    const id = await loadOrCreateIdentity('@fetchproxy/example-mcp', dir);
    expect(id.x25519Pub.byteLength).toBe(32);
  });
});
