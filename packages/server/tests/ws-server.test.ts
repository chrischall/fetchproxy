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

  it('starts on a free port as host (after explicit connect)', async () => {
    const srv = new FetchproxyServer({
      port: 41050,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      identityDir: mkdtempSync(join(tmpdir(), 'fp-srv-')),
    });
    servers.push(srv);
    await srv.listen();
    // 0.5.3+: role is null until the first verb call (or an explicit
    // `connect()`). `listen()` only loads identity now.
    expect(srv.role).toBe(null);
    await srv.connect();
    expect(srv.role).toBe('host');
  });

  it('two servers on the same port: first is host, second is peer (after connect)', async () => {
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
    await a.connect();
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
    await b.connect();
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
    // 0.5.3+: the error wording is now about identity not being loaded
    // (ensureConnected's precondition) rather than "not listening" —
    // same intent, more accurate now that listen()'s only side-effect
    // is the identity load.
    await expect(
      srv.fetch({ url: 'https://x.com/y', method: 'GET', tabUrl: 'https://x.com/' }),
    ).rejects.toThrow(/before listen/);
  });

  it('0.5.3+: listen() does not bind the port — connection is deferred', async () => {
    const srv = new FetchproxyServer({
      port: 41057,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      identityDir: mkdtempSync(join(tmpdir(), 'fp-srv-')),
    });
    servers.push(srv);
    await srv.listen();
    expect(srv.role).toBe(null);

    // Port should still be free — another FetchproxyServer can bind
    // it. (Pre-0.5.3 this would have failed because srv.listen() had
    // already claimed 41057 as host.)
    const other = new FetchproxyServer({
      port: 41057,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
      identityDir: mkdtempSync(join(tmpdir(), 'fp-srv-')),
    });
    servers.push(other);
    await other.listen();
    await other.connect();
    expect(other.role).toBe('host');

    // Now srv connects — finds port already bound and dials as peer.
    await srv.connect();
    expect(srv.role).toBe('peer');
  });

  it('0.5.3+: concurrent first verb calls share one connection election', async () => {
    const srv = new FetchproxyServer({
      port: 41058,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      identityDir: mkdtempSync(join(tmpdir(), 'fp-srv-')),
    });
    servers.push(srv);
    await srv.listen();
    // Kick off two `connect()` calls in parallel before either resolves.
    // The internal `connectingPromise` mutex must ensure only one role
    // election runs — otherwise both would race the port bind and at
    // least one would fail with EADDRINUSE bubbling out of startHost.
    const [r1, r2] = await Promise.all([srv.connect(), srv.connect()]);
    expect(r1).toBeUndefined();
    expect(r2).toBeUndefined();
    expect(srv.role).toBe('host');
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
    await srv.connect();
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
