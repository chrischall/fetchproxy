/**
 * FetchproxyServer: the localhost WebSocket bridge an MCP server uses
 * to relay fetches through the user's signed-in browser. Domain-agnostic
 * port of opentable-mcp's OpenTableWsServer.
 *
 * One extension at a time. Connect-timeout for "extension offline"
 * detection (default 15s). Per-request timeout (default 30s).
 * 20s ping to keep the MV3 service worker warm.
 */
import { WebSocketServer, WebSocket } from 'ws';
import { validateFrame, type Frame, type FetchInit, type FetchResponse } from '@fetchproxy/protocol';

const PING_INTERVAL_MS = 20_000;
const MAX_RESPONSE_BODY_BYTES = 5 * 1024 * 1024; // 5 MB
const PUBLIC_ORIGIN_REGEX = /^https?:\/\/(?!(127\.0\.0\.1|localhost)(:|$))/i;

export interface FetchproxyServerOptions {
  port: number;
  /** MCP server name announced in `hello`. */
  server: string;
  /** MCP server version (semver). */
  version: string;
  /** Allowed domain for fetch destinations. The extension enforces this. */
  domain: string;
}

export interface FetchResult {
  status: number;
  body: string;
  url: string;
}

interface PendingRequest {
  resolve: (v: FetchResult) => void;
  reject: (e: Error) => void;
  timer: NodeJS.Timeout;
}

export class FetchproxyServer {
  private readonly opts: FetchproxyServerOptions;
  private wss: WebSocketServer | null = null;
  private active: WebSocket | null = null;
  private nextId = 1;
  private pending = new Map<number, PendingRequest>();
  private pingTimer: NodeJS.Timeout | null = null;
  private connectTimeoutMs = 15_000;
  private requestTimeoutMs = 30_000;
  private readyResolvers: Array<() => void> = [];

  constructor(opts: FetchproxyServerOptions) {
    this.opts = opts;
  }

  setConnectTimeoutMs(ms: number): void {
    this.connectTimeoutMs = ms;
  }

  setRequestTimeoutMs(ms: number): void {
    this.requestTimeoutMs = ms;
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve, reject) => {
      this.wss = new WebSocketServer({
        host: '127.0.0.1',
        port: this.opts.port,
        verifyClient: (info, cb) => {
          // Reject upgrades from public web origins (defense T2).
          const origin = info.req.headers.origin;
          if (origin && PUBLIC_ORIGIN_REGEX.test(origin)) {
            cb(false, 403, 'Forbidden origin');
            return;
          }
          cb(true);
        },
      });
      this.wss.on('listening', () => resolve());
      this.wss.on('error', reject);
      this.wss.on('connection', (ws) => this.handleConnection(ws));
    });
    this.pingTimer = setInterval(() => this.ping(), PING_INTERVAL_MS);
  }

  async close(): Promise<void> {
    if (this.pingTimer) clearInterval(this.pingTimer);
    this.pingTimer = null;
    for (const [, p] of this.pending) {
      clearTimeout(p.timer);
      p.reject(new Error('Server closing'));
    }
    this.pending.clear();
    if (this.active) this.active.close();
    this.active = null;
    await new Promise<void>((r) => {
      if (!this.wss) return r();
      this.wss.close(() => r());
    });
    this.wss = null;
  }

  /** Proxy a fetch through the extension. */
  async fetch(init: FetchInit): Promise<FetchResult> {
    await this.waitForConnection();
    if (!this.active) {
      throw new Error(`fetchproxy extension offline — install it and open a ${this.opts.domain} tab`);
    }
    const id = this.nextId++;
    return new Promise<FetchResult>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`fetchproxy request timed out after ${this.requestTimeoutMs}ms`));
      }, this.requestTimeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.active!.send(JSON.stringify({ type: 'request', id, op: 'fetch', init }));
    });
  }

  private handleConnection(ws: WebSocket): void {
    if (this.active && this.active.readyState === WebSocket.OPEN) {
      ws.close(1000, 'Another extension already connected');
      return;
    }
    this.active = ws;

    // Send our hello immediately.
    ws.send(JSON.stringify({
      type: 'hello',
      role: 'server',
      server: this.opts.server,
      version: this.opts.version,
      domain: this.opts.domain,
    }));

    ws.on('message', (raw) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(String(raw));
      } catch {
        ws.close(1002, 'invalid JSON');
        return;
      }
      let frame: Frame;
      try {
        frame = validateFrame(parsed);
      } catch (e) {
        ws.close(1002, `protocol error: ${(e as Error).message}`);
        return;
      }
      this.handleFrame(frame, ws);
    });

    ws.on('close', () => {
      if (this.active === ws) this.active = null;
      for (const [, p] of this.pending) {
        clearTimeout(p.timer);
        p.reject(new Error('Extension disconnected during request'));
      }
      this.pending.clear();
    });
  }

  private handleFrame(frame: Frame, ws: WebSocket): void {
    switch (frame.type) {
      case 'hello':
        // Just an introduction; nothing to do server-side.
        return;
      case 'ready': {
        const waiters = this.readyResolvers.splice(0);
        for (const r of waiters) r();
        return;
      }
      case 'ping':
        ws.send(JSON.stringify({ type: 'pong' }));
        return;
      case 'pong':
        return;
      case 'response': {
        const pending = this.pending.get(frame.id);
        if (!pending) return;
        clearTimeout(pending.timer);
        this.pending.delete(frame.id);
        if (frame.ok) {
          if (frame.body.length > MAX_RESPONSE_BODY_BYTES) {
            pending.reject(new Error(`response body too large: ${frame.body.length} bytes`));
            return;
          }
          pending.resolve({ status: frame.status, body: frame.body, url: frame.url });
        } else {
          pending.reject(new Error(frame.error));
        }
        return;
      }
    }
  }

  private ping(): void {
    if (this.active && this.active.readyState === WebSocket.OPEN) {
      this.active.send(JSON.stringify({ type: 'ping' }));
    }
  }

  private waitForConnection(): Promise<void> {
    if (this.active && this.active.readyState === WebSocket.OPEN) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.readyResolvers.indexOf(resolve);
        if (idx >= 0) this.readyResolvers.splice(idx, 1);
        reject(new Error(`fetchproxy extension offline — install it and open a ${this.opts.domain} tab`));
      }, this.connectTimeoutMs);
      this.readyResolvers.push(() => {
        clearTimeout(timer);
        resolve();
      });
    });
  }
}
