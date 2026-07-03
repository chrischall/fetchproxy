import { createServer } from 'node:net';
import type { AddressInfo } from 'node:net';
import type { WebSocketServer } from 'ws';

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
