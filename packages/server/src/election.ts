import { createServer, Server as HttpServer } from 'node:http';

export interface ElectionOpts {
  host: string;
  port: number;
}

export type ElectionResult =
  | { role: 'host'; server: HttpServer }
  | { role: 'peer' };

/**
 * Try to bind the WS port. If it succeeds, we're the concentrator (host).
 * If EADDRINUSE, someone else won — we'll dial them as a peer instead.
 *
 * The HTTP server is returned because @fetchproxy/server's WS server attaches
 * to it directly (no second bind). The caller closes the server on shutdown.
 */
export async function electRole(opts: ElectionOpts): Promise<ElectionResult> {
  const server = createServer();
  return new Promise<ElectionResult>((resolve, reject) => {
    const onError = (e: NodeJS.ErrnoException): void => {
      server.removeListener('listening', onListening);
      if (e.code === 'EADDRINUSE') {
        // Clean up the unused server before resolving peer.
        try { server.close(); } catch { /* noop */ }
        resolve({ role: 'peer' });
      } else {
        reject(e);
      }
    };
    const onListening = (): void => {
      server.removeListener('error', onError);
      resolve({ role: 'host', server });
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(opts.port, opts.host);
  });
}
