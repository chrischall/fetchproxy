import { describe, it, expect, afterEach } from 'vitest';
import { FetchproxyServer } from '../src/ws-server.js';

/**
 * `FETCHPROXY_WS_PORT` — one spelling for the concentrator port.
 *
 * Every browser-bridge MCP in the fleet already takes its port from an
 * environment variable, but each names it itself (`ALLTRAILS_WS_PORT`,
 * `OT_WS_PORT`, …) because each wraps `FetchproxyServer` in its own
 * transport. The `@fetchproxy/bootstrap` path cannot: the server is
 * constructed inside the helper, so a consumer there has no port to pass and
 * no way to move off 37149. This fallback is the only route to that path.
 *
 * Precedence is deliberate and tested in both directions: an explicit
 * `opts.port` is a decision the caller made in code and wins over the
 * environment, which is what keeps the twelve MCPs that already resolve their
 * own variable behaving exactly as before.
 */
describe('FETCHPROXY_WS_PORT', () => {
  const original = process.env.FETCHPROXY_WS_PORT;

  afterEach(() => {
    if (original === undefined) delete process.env.FETCHPROXY_WS_PORT;
    else process.env.FETCHPROXY_WS_PORT = original;
  });

  const make = (port?: number) =>
    new FetchproxyServer({
      serverName: 'test-mcp',
      version: '0.0.0',
      domains: ['example.com'],
      ...(port === undefined ? {} : { port }),
    });

  it('defaults to 37149 with no environment and no option', () => {
    delete process.env.FETCHPROXY_WS_PORT;
    expect(make().bridgeHealth().port).toBe(37149);
  });

  it('takes the port from the environment when no option is given', () => {
    process.env.FETCHPROXY_WS_PORT = '37150';
    expect(make().bridgeHealth().port).toBe(37150);
  });

  it('lets an explicit option beat the environment', () => {
    process.env.FETCHPROXY_WS_PORT = '37150';
    expect(make(37151).bridgeHealth().port).toBe(37151);
  });

  it('ignores a value that is not a usable port rather than binding one', () => {
    for (const bad of ['', 'nope', '0', '-1', '65536', '3.5']) {
      process.env.FETCHPROXY_WS_PORT = bad;
      expect(make().bridgeHealth().port, `for ${JSON.stringify(bad)}`).toBe(37149);
    }
  });
});
