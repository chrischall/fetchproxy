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

  it('throws at construction when a declared captureHeaders urlPattern is a bare host', () => {
    // Regression guard: a misconfigured MCP that declares `urlPattern: 'host'`
    // (instead of a valid `https://host/path` match pattern) must fail loudly
    // at construction with an actionable message — NOT silently get its hello
    // rejected by the bridge host at runtime ("peer WS closed before ready").
    expect(
      () =>
        new FetchproxyServer({
          port: 41999,
          serverName: 'musescore-mcp',
          version: '0.0.1',
          domains: ['musescore.com'],
          capabilities: ['fetch', 'capture_request_header'],
          captureHeaders: [{ urlPattern: 'musescore.com', headerName: 'cookie' }],
        }),
    ).toThrow(/captureHeaders|https:\/\//i);
  });

  it('accepts a valid https captureHeaders match pattern at construction', () => {
    expect(
      () =>
        new FetchproxyServer({
          port: 41998,
          serverName: 'musescore-mcp',
          version: '0.0.1',
          domains: ['musescore.com'],
          capabilities: ['fetch', 'capture_request_header'],
          captureHeaders: [{ urlPattern: 'https://musescore.com/*', headerName: 'cookie' }],
        }),
    ).not.toThrow();
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

  it('0.5.3+: close() awaits an in-flight connect so no handle leaks', async () => {
    // Repro: trigger `doConnect` (via `connect()`) and `close()` in the
    // same microtask. Pre-fix, close() observed `hostHandle == null`,
    // returned without tearing down anything, and then doConnect()
    // wrote `this.hostHandle = <live handle>` after close() had
    // already exited — the handle's listener registration and WS state
    // survived close(), so the supposedly-closed instance still held
    // bridge resources. Post-fix, close() awaits `connectingPromise`
    // first, so doConnect()'s handle assignment happens before the
    // teardown logic runs and the handle gets closed.
    //
    // Test the invariant directly by inspecting the private handle
    // fields: post-close, both must be null regardless of how the
    // race resolved.
    const srv = new FetchproxyServer({
      port: 41059,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      identityDir: mkdtempSync(join(tmpdir(), 'fp-srv-')),
    });
    await srv.listen();
    const connectPromise = srv.connect();
    // Race close() against the in-flight connect.
    await Promise.all([connectPromise, srv.close()]);
    expect(srv.role).toBe(null);
    // No handle survives the race. Touch private state because
    // there's no public way to observe the leak otherwise.
    const internal = srv as unknown as {
      hostHandle: unknown;
      peerHandle: unknown;
      connectingPromise: unknown;
    };
    expect(internal.hostHandle).toBe(null);
    expect(internal.peerHandle).toBe(null);
    expect(internal.connectingPromise).toBe(null);
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
