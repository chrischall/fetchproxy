import { createServer } from 'node:net';
import type { AddressInfo } from 'node:net';
import { WebSocketServer } from 'ws';

/** The address every client in these tests dials by name. */
const LOOPBACK = '127.0.0.1';

/**
 * Ask the OS for a free TCP port on 127.0.0.1 and hand it back as a plain
 * number. Used where a test needs to pass the SAME literal port to two or
 * more constructs that don't expose a "what did you actually bind to"
 * read-back (e.g. two `FetchproxyServer` instances racing host/peer
 * election, or a mock-extension `WebSocket` dialing a `FetchproxyServer`
 * by port number).
 *
 * This is a probe-then-release allocation: nothing else in this process
 * or test run is likely to grab the same ephemeral port before the
 * caller binds it, but unlike a hardcoded literal it can never collide
 * with another vitest test file running concurrently.
 */
export async function getEphemeralPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address() as AddressInfo;
      probe.close((err) => {
        if (err) reject(err);
        else resolve(port);
      });
    });
  });
}

/**
 * Bind a `ws` `WebSocketServer` to an OS-assigned ephemeral port (`port: 0`),
 * wait for it to actually be listening, and return the port it landed on.
 * Prefer this over a hardcoded port literal for any test-local
 * `WebSocketServer` — hardcoded ports collide across concurrently-run
 * test files.
 */
export async function listenEphemeral(wss: WebSocketServer): Promise<number> {
  await new Promise<void>((resolve) => wss.once('listening', () => resolve()));
  return (wss.address() as AddressInfo).port;
}

/**
 * A test-local `WebSocketServer` on an OS-assigned port of the LOOPBACK
 * address. Pair it with `listenEphemeral` to learn the port it landed on.
 *
 * The HOST is as load-bearing as the port. `new WebSocketServer({ port: 0 })`
 * binds the WILDCARD address, and macOS lets a later, more specific bind take
 * `127.0.0.1:<that port>` out from under it: the second bind succeeds and then
 * wins every loopback dial. Since everything here dials `127.0.0.1` by name, a
 * wildcard-bound test server can end up watching another test file's server
 * answer its own client — an HTTP server refuses the upgrade ('Unexpected
 * server response: 200') and a server that simply never replies hangs the case
 * until it times out. Both were seen in full-suite runs, in this package's
 * peer tests. Binding the loopback address makes the port genuinely taken on
 * the address the client uses, so the OS gives it to nobody else.
 */
export function loopbackWss(): WebSocketServer {
  return new WebSocketServer({ port: 0, host: LOOPBACK });
}
