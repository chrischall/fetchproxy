import { describe, it, expect, afterEach } from 'vitest';
import { createServer, Server as HttpServer } from 'node:http';
import { electRole } from '../src/election.js';

describe('election', () => {
  const cleanup: HttpServer[] = [];

  afterEach(async () => {
    await Promise.all(
      cleanup.splice(0).map(
        (s) => new Promise<void>((r) => s.close(() => r())),
      ),
    );
  });

  it('returns host when port is free', async () => {
    const port = 41999;
    const result = await electRole({ host: '127.0.0.1', port });
    expect(result.role).toBe('host');
    if (result.role === 'host') {
      expect(result.server.listening).toBe(true);
      cleanup.push(result.server);
    }
  });

  it('returns peer when port is taken', async () => {
    const port = 41998;
    const blocker = createServer().listen(port, '127.0.0.1');
    await new Promise<void>((r) => blocker.once('listening', () => r()));
    cleanup.push(blocker);
    const result = await electRole({ host: '127.0.0.1', port });
    expect(result.role).toBe('peer');
  });

  it('host role can be released and re-won', async () => {
    const port = 41997;
    const first = await electRole({ host: '127.0.0.1', port });
    expect(first.role).toBe('host');
    if (first.role === 'host') {
      await new Promise<void>((r) => first.server.close(() => r()));
    }
    const second = await electRole({ host: '127.0.0.1', port });
    expect(second.role).toBe('host');
    if (second.role === 'host') {
      cleanup.push(second.server);
    }
  });

  it('host server binds to the requested host (127.0.0.1, not 0.0.0.0)', async () => {
    const port = 41996;
    const result = await electRole({ host: '127.0.0.1', port });
    expect(result.role).toBe('host');
    if (result.role === 'host') {
      const addr = result.server.address();
      // node returns AddressInfo when listening on TCP
      if (addr && typeof addr === 'object') {
        expect(addr.address).toBe('127.0.0.1');
      }
      cleanup.push(result.server);
    }
  });

  it('propagates non-EADDRINUSE bind errors (e.g. invalid host)', async () => {
    // Hits the `else { reject(e); }` branch in election.ts — anything
    // other than EADDRINUSE (cannot-resolve, permission denied, etc.)
    // must surface to the caller rather than being silently treated as
    // "act as peer". Binding to a syntactically-invalid host produces
    // ENOTFOUND / EINVAL on macOS + Linux and is the simplest cross-
    // platform way to drive the non-EADDRINUSE path.
    await expect(
      electRole({ host: '0.0.0.0.0', port: 41995 }),
    ).rejects.toThrow();
  });

  it('does not reject on the bind timeout once listening succeeds', async () => {
    // Sanity: the timeout must be cleared on success so a slow-but-eventual
    // bind isn't poisoned by a late timer firing.
    const port = 41993;
    const result = await electRole({ host: '127.0.0.1', port, bindTimeoutMs: 50 });
    expect(result.role).toBe('host');
    if (result.role === 'host') {
      cleanup.push(result.server);
      // Wait past the timeout window; the server must still be listening.
      await new Promise((r) => setTimeout(r, 80));
      expect(result.server.listening).toBe(true);
    }
  });
});
