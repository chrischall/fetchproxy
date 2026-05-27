import { describe, it, expect, vi } from 'vitest';
import { bootstrap, type BootstrapServer } from '../src/index.js';
import type { FetchproxyServerOpts } from '@fetchproxy/server';

// (4) Bootstrap pass-through for the new 0.8.0 server options.
// ofw-mcp flagged this as a gap — bootstrap consumers can't tune
// bridgeReviveDelayMs or fetchTimeoutMs today.

describe('BootstrapOpts forwards bridgeReviveDelayMs + fetchTimeoutMs to FetchproxyServer', () => {
  function makeStubServer(): BootstrapServer {
    return {
      // eslint-disable-next-line @typescript-eslint/no-empty-function -- test stub
      listen: async () => {},
      // eslint-disable-next-line @typescript-eslint/no-empty-function -- test stub
      close: async () => {},
      readCookies: async () => '',
      readLocalStorage: async () => ({}),
      readSessionStorage: async () => ({}),
      captureRequestHeader: async () => '',
      readIndexedDb: async () => ({}),
    };
  }

  it('threads bridgeReviveDelayMs through to the server factory', async () => {
    const factorySpy = vi.fn((_opts: FetchproxyServerOpts) => makeStubServer());
    await bootstrap({
      serverName: 'test',
      version: '0.0.0',
      domains: ['example.com'],
      declare: {
        cookies: [],
        localStorage: [],
        sessionStorage: [],
        captureHeaders: [],
      },
      bridgeReviveDelayMs: 1234,
      _serverFactory: factorySpy,
    });
    expect(factorySpy).toHaveBeenCalledOnce();
    expect(factorySpy.mock.calls[0][0].bridgeReviveDelayMs).toBe(1234);
  });

  it('threads fetchTimeoutMs through to the server factory', async () => {
    const factorySpy = vi.fn((_opts: FetchproxyServerOpts) => makeStubServer());
    await bootstrap({
      serverName: 'test',
      version: '0.0.0',
      domains: ['example.com'],
      declare: {
        cookies: [],
        localStorage: [],
        sessionStorage: [],
        captureHeaders: [],
      },
      fetchTimeoutMs: 5678,
      _serverFactory: factorySpy,
    });
    expect(factorySpy.mock.calls[0][0].fetchTimeoutMs).toBe(5678);
  });

  it('omits both keys from server opts when caller omits them (server defaults apply)', async () => {
    const factorySpy = vi.fn((_opts: FetchproxyServerOpts) => makeStubServer());
    await bootstrap({
      serverName: 'test',
      version: '0.0.0',
      domains: ['example.com'],
      declare: {
        cookies: [],
        localStorage: [],
        sessionStorage: [],
        captureHeaders: [],
      },
      _serverFactory: factorySpy,
    });
    const opts = factorySpy.mock.calls[0][0];
    expect(opts.bridgeReviveDelayMs).toBeUndefined();
    expect(opts.fetchTimeoutMs).toBeUndefined();
  });
});
