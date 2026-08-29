import { describe, it, expect, afterEach } from 'vitest';
import { FetchproxyServer } from '../src/ws-server.js';

/**
 * `FETCHPROXY_WS_HOST` — the environment fallback for the concentrator's
 * bind address, parallel to `FETCHPROXY_WS_PORT`.
 *
 * It exists for exactly one topology: a hosted child (chrischall/mcp-host)
 * running inside a sandbox with its own network namespace, where 127.0.0.1
 * is a loopback nobody outside the sandbox can reach and the runner's relay
 * agent dials the child at the sandbox end of a veth pair instead. On a
 * laptop the default is the only correct answer, so the fallback is as
 * strict as the port one: only a literal IP address is honoured, and
 * anything else — a hostname, `localhost`, whitespace — is ignored so the
 * concentrator binds where it always has rather than on something the
 * operator did not write down.
 */
describe('FETCHPROXY_WS_HOST', () => {
  const originalHost = process.env.FETCHPROXY_WS_HOST;
  const originalPort = process.env.FETCHPROXY_WS_PORT;

  afterEach(() => {
    if (originalHost === undefined) delete process.env.FETCHPROXY_WS_HOST;
    else process.env.FETCHPROXY_WS_HOST = originalHost;
    if (originalPort === undefined) delete process.env.FETCHPROXY_WS_PORT;
    else process.env.FETCHPROXY_WS_PORT = originalPort;
  });

  const make = (host?: string) =>
    new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.0',
      domains: ['example.com'],
      ...(host === undefined ? {} : { host }),
    });

  it('defaults to 127.0.0.1 with no environment and no option', () => {
    delete process.env.FETCHPROXY_WS_HOST;
    expect(make().bridgeHealth().host).toBe('127.0.0.1');
  });

  it('takes the address from the environment when no option is given', () => {
    process.env.FETCHPROXY_WS_HOST = '10.200.3.2';
    expect(make().bridgeHealth().host).toBe('10.200.3.2');
  });

  it('lets an explicit option beat the environment', () => {
    process.env.FETCHPROXY_WS_HOST = '10.200.3.2';
    expect(make('127.0.0.2').bridgeHealth().host).toBe('127.0.0.2');
  });

  it('accepts an IPv6 literal', () => {
    process.env.FETCHPROXY_WS_HOST = '::1';
    expect(make().bridgeHealth().host).toBe('::1');
  });

  it('ignores a hostname rather than binding something it would have to resolve', () => {
    for (const bad of ['localhost', 'relay.internal', 'example.com']) {
      process.env.FETCHPROXY_WS_HOST = bad;
      expect(make().bridgeHealth().host, `for ${JSON.stringify(bad)}`).toBe('127.0.0.1');
    }
  });

  it('ignores an empty or whitespace value', () => {
    for (const bad of ['', '   ', '\n']) {
      process.env.FETCHPROXY_WS_HOST = bad;
      expect(make().bridgeHealth().host, `for ${JSON.stringify(bad)}`).toBe('127.0.0.1');
    }
  });

  it('is independent of FETCHPROXY_WS_PORT', () => {
    process.env.FETCHPROXY_WS_HOST = '10.200.3.2';
    delete process.env.FETCHPROXY_WS_PORT;
    let h = make().bridgeHealth();
    expect(h.host).toBe('10.200.3.2');
    expect(h.port).toBe(37149);

    delete process.env.FETCHPROXY_WS_HOST;
    process.env.FETCHPROXY_WS_PORT = '37150';
    h = make().bridgeHealth();
    expect(h.host).toBe('127.0.0.1');
    expect(h.port).toBe(37150);
  });
});
