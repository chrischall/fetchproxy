import { describe, it, expect, afterEach } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FetchproxyServer } from '../src/index.js';

describe('FetchproxyServer (orchestrator)', () => {
  let servers: FetchproxyServer[] = [];

  afterEach(async () => {
    await Promise.all(servers.splice(0).map((s) => s.close()));
  });

  it('starts on a free port as host', async () => {
    const srv = new FetchproxyServer({
      port: 41050,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      identityDir: mkdtempSync(join(tmpdir(), 'fp-srv-')),
    });
    servers.push(srv);
    await srv.listen();
    expect(srv.role).toBe('host');
  });

  it('two servers on the same port: first is host, second is peer', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fp-srv-'));
    const a = new FetchproxyServer({
      port: 41051,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      identityDir: dir,
    });
    servers.push(a);
    await a.listen();
    expect(a.role).toBe('host');

    const b = new FetchproxyServer({
      port: 41051,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
      identityDir: dir,
    });
    servers.push(b);
    await b.listen();
    expect(b.role).toBe('peer');
  });

  it('throws on fetch before listen', async () => {
    const srv = new FetchproxyServer({
      port: 41052,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      identityDir: mkdtempSync(join(tmpdir(), 'fp-srv-')),
    });
    // Don't push to servers — never started, no close needed.
    await expect(
      srv.fetch({ url: 'https://x.com/y', method: 'GET', tabUrl: 'https://x.com/' }),
    ).rejects.toThrow(/not listening/);
  });

  it('close() returns role to null', async () => {
    const srv = new FetchproxyServer({
      port: 41053,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      identityDir: mkdtempSync(join(tmpdir(), 'fp-srv-')),
    });
    await srv.listen();
    expect(srv.role).toBe('host');
    await srv.close();
    expect(srv.role).toBe(null);
  });

  describe('readIndexedDb()', () => {
    it("throws if the MCP didn't declare 'read_indexed_db' capability", async () => {
      const srv = new FetchproxyServer({
        port: 41054,
        serverName: 'resy-mcp',
        version: '0.0.1',
        domains: ['resy.com'],
        identityDir: mkdtempSync(join(tmpdir(), 'fp-srv-')),
      });
      servers.push(srv);
      await srv.listen();
      await expect(
        srv.readIndexedDb({ database: 'resy', store: 'auth', keys: ['userToken'] }),
      ).rejects.toThrow(/read_indexed_db/);
    });

    it('throws if the requested (database, store) is not declared', async () => {
      const srv = new FetchproxyServer({
        port: 41055,
        serverName: 'resy-mcp',
        version: '0.0.1',
        domains: ['resy.com'],
        capabilities: ['fetch', 'read_indexed_db'],
        indexedDbScopes: [
          { origin: 'https://resy.com', database: 'resy', store: 'auth', keys: ['userToken'] },
        ],
        identityDir: mkdtempSync(join(tmpdir(), 'fp-srv-')),
      });
      servers.push(srv);
      await srv.listen();
      await expect(
        srv.readIndexedDb({ database: 'wrong', store: 'auth', keys: ['userToken'] }),
      ).rejects.toThrow(/not declared/);
    });

    it('throws if a requested key is outside the declared keys', async () => {
      const srv = new FetchproxyServer({
        port: 41056,
        serverName: 'resy-mcp',
        version: '0.0.1',
        domains: ['resy.com'],
        capabilities: ['fetch', 'read_indexed_db'],
        indexedDbScopes: [
          { origin: 'https://resy.com', database: 'resy', store: 'auth', keys: ['userToken'] },
        ],
        identityDir: mkdtempSync(join(tmpdir(), 'fp-srv-')),
      });
      servers.push(srv);
      await srv.listen();
      await expect(
        srv.readIndexedDb({ database: 'resy', store: 'auth', keys: ['notDeclared'] }),
      ).rejects.toThrow(/not in declared/);
    });
  });
});
