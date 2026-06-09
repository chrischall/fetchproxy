import { describe, it, expect, vi } from 'vitest';

// FP-B3: a port stuck in a bad state can leave `server.listen()` hanging
// forever — neither `listening` nor `error` ever fires — which wedges the
// first verb's `ensureConnected` indefinitely. `electRole` now races a bind
// timeout that rejects with a clear error.
//
// This file mocks `node:http` so `createServer().listen()` is a no-op that
// never emits either event, isolating the timeout path. It lives in its own
// file because the mock is module-wide; the happy-path / EADDRINUSE tests
// stay in election.test.ts against the real http module.
vi.mock('node:http', () => {
  class FakeServer {
    once(): this {
      return this;
    }
    removeListener(): this {
      return this;
    }
    // Never emits 'listening' or 'error'.
    listen(): this {
      return this;
    }
    close(): this {
      return this;
    }
  }
  const createServer = (): FakeServer => new FakeServer();
  return { createServer, Server: FakeServer, default: { createServer, Server: FakeServer } };
});

describe('election bind timeout (FP-B3)', () => {
  it('rejects with a clear error when listen() never fires', async () => {
    const { electRole } = await import('../src/election.js');
    await expect(
      electRole({ host: '127.0.0.1', port: 41994, bindTimeoutMs: 30 }),
    ).rejects.toThrow(/timed out/i);
  });

  it('disables the timeout when bindTimeoutMs is 0 (does not reject)', async () => {
    const { electRole } = await import('../src/election.js');
    let settled = false;
    const p = electRole({ host: '127.0.0.1', port: 41994, bindTimeoutMs: 0 }).then(
      () => {
        settled = true;
      },
      () => {
        settled = true;
      },
    );
    // Give it a tick; with the timeout disabled and listen() hanging, the
    // promise must remain pending.
    await new Promise((r) => setTimeout(r, 60));
    expect(settled).toBe(false);
    void p;
  });
});
