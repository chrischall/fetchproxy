import { createServer, Server as HttpServer } from 'node:http';

export interface ElectionOpts {
  host: string;
  port: number;
  /**
   * FP-B3: max time to wait for `server.listen()` to emit either
   * `listening` or `error`. A port stuck in a bad state can leave
   * `listen()` hanging forever — neither event fires — which wedges the
   * first verb's `ensureConnected` indefinitely. When the timer fires
   * first we reject with a clear error so the caller can surface it
   * instead of hanging. Defaults to 5000ms. The fast EADDRINUSE path is
   * unaffected (it fires `error` synchronously-ish, well inside the
   * window). Set to `0` to disable the timeout.
   */
  bindTimeoutMs?: number;
}

export type ElectionResult =
  | { role: 'host'; server: HttpServer }
  | { role: 'peer' };

const DEFAULT_BIND_TIMEOUT_MS = 5000;

/**
 * Try to bind the WS port. If it succeeds, we're the concentrator (host).
 * If EADDRINUSE, someone else won — we'll dial them as a peer instead.
 *
 * The HTTP server is returned because @fetchproxy/server's WS server attaches
 * to it directly (no second bind). The caller closes the server on shutdown.
 */
export async function electRole(opts: ElectionOpts): Promise<ElectionResult> {
  const server = createServer();
  const bindTimeoutMs = opts.bindTimeoutMs ?? DEFAULT_BIND_TIMEOUT_MS;
  return new Promise<ElectionResult>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const clearBindTimer = (): void => {
      if (timer) {
        clearTimeout(timer);
        timer = undefined;
      }
    };
    const onError = (e: NodeJS.ErrnoException): void => {
      clearBindTimer();
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
      clearBindTimer();
      server.removeListener('error', onError);
      resolve({ role: 'host', server });
    };
    server.once('error', onError);
    server.once('listening', onListening);
    if (bindTimeoutMs > 0) {
      timer = setTimeout(() => {
        // listen() never fired either event — tear down listeners + the
        // half-bound server and surface a clear, actionable error.
        server.removeListener('error', onError);
        server.removeListener('listening', onListening);
        try { server.close(); } catch { /* noop */ }
        reject(
          new Error(
            `fetchproxy: bind to ${opts.host}:${opts.port} timed out after ${bindTimeoutMs}ms (port may be in a bad state)`,
          ),
        );
      }, bindTimeoutMs);
      // Don't keep the event loop alive solely for this timer.
      if (typeof timer.unref === 'function') timer.unref();
    }
    server.listen(opts.port, opts.host);
  });
}
