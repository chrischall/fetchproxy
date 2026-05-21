import { generateMcpId } from '@fetchproxy/protocol';
import type { InnerFrame, FetchInit } from '@fetchproxy/protocol';
import { electRole } from './election.js';
import { startHost, type HostHandle } from './host.js';
import { startPeer, type PeerHandle } from './peer.js';
import { loadOrCreateIdentity, type Identity } from './identity.js';

export interface FetchproxyServerOpts {
  port?: number;
  host?: string;
  serverName: string;
  version: string;
  domain: string;
  identityDir?: string;
}

export interface FetchResult {
  ok: true;
  status: number;
  url: string;
  body: string;
}

export interface FetchResultError {
  ok: false;
  error: string;
}

interface ResolvedOpts {
  port: number;
  host: string;
  serverName: string;
  version: string;
  domain: string;
  identityDir?: string;
}

export class FetchproxyServer {
  public role: 'host' | 'peer' | null = null;

  private opts: ResolvedOpts;
  private hostHandle: HostHandle | null = null;
  private peerHandle: PeerHandle | null = null;
  private nextRequestId = 1;
  private pending = new Map<number, (r: FetchResult | FetchResultError) => void>();
  private mcpId: string | null = null;
  private identity: Identity | null = null;

  constructor(opts: FetchproxyServerOpts) {
    this.opts = {
      port: opts.port ?? 37149,
      host: opts.host ?? '127.0.0.1',
      serverName: opts.serverName,
      version: opts.version,
      domain: opts.domain,
      identityDir: opts.identityDir,
    };
  }

  async listen(): Promise<void> {
    this.identity = await loadOrCreateIdentity(this.opts.serverName, this.opts.identityDir);
    this.mcpId = generateMcpId(this.opts.serverName, this.opts.version);
    const el = await electRole({ host: this.opts.host, port: this.opts.port });
    if (el.role === 'host') {
      this.role = 'host';
      this.hostHandle = await startHost({
        httpServer: el.server,
        ownIdentity: this.identity,
        ownMcpId: this.mcpId,
        ownServerName: this.opts.serverName,
        ownVersion: this.opts.version,
        ownDomain: this.opts.domain,
      });
      this.hostHandle.onOwnInner((inner) => this.onInner(inner));
    } else {
      this.role = 'peer';
      this.peerHandle = await startPeer({
        host: this.opts.host,
        port: this.opts.port,
        identity: this.identity,
        mcpId: this.mcpId,
        serverName: this.opts.serverName,
        version: this.opts.version,
        domain: this.opts.domain,
      });
      this.peerHandle.onInner((inner) => this.onInner(inner));
    }
  }

  async fetch(init: FetchInit): Promise<FetchResult | FetchResultError> {
    if (!this.hostHandle && !this.peerHandle) {
      throw new Error('FetchproxyServer.fetch called before listen() — not listening');
    }
    const id = this.nextRequestId++;
    const inner: InnerFrame = { type: 'request', id, op: 'fetch', init };
    const pending = new Promise<FetchResult | FetchResultError>((resolve) => {
      this.pending.set(id, resolve);
    });
    if (this.hostHandle) {
      await this.hostHandle.sendOwnInner(inner);
    } else if (this.peerHandle) {
      await this.peerHandle.sendInner(inner);
    }
    return pending;
  }

  private onInner(inner: InnerFrame): void {
    if (inner.type !== 'response') return;
    const cb = this.pending.get(inner.id);
    if (!cb) return;
    this.pending.delete(inner.id);
    if (inner.ok) {
      cb({ ok: true, status: inner.status, url: inner.url, body: inner.body });
    } else {
      cb({ ok: false, error: inner.error });
    }
  }

  async close(): Promise<void> {
    if (this.hostHandle) await this.hostHandle.close();
    if (this.peerHandle) this.peerHandle.close();
    this.hostHandle = null;
    this.peerHandle = null;
    this.role = null;
  }
}
