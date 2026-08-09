import { describe, it, expect, beforeEach } from 'vitest';
import {
  LOCAL_LINK_ID,
  anyLinkOpen,
  bindMcpToLink,
  linkForMcp,
  linkStatuses,
  links,
  localLink,
  mcpIdsForLink,
  remoteLink,
  sendOnLink,
  unbindAll,
  unbindLink,
  type Link,
} from '../src/background/links.js';
import { bridgeSubprotocols } from '../src/remote-targets.js';

class FakeSocket {
  static readonly OPEN = 1;
  readyState = 1;
  sent: string[] = [];
  send(data: string): void {
    this.sent.push(data);
  }
}

// The module reads `WebSocket.OPEN` off the global; the service worker has one
// and vitest's node environment does not.
(globalThis as { WebSocket?: unknown }).WebSocket ??= FakeSocket;

const open = (link: Link): FakeSocket => {
  const ws = new FakeSocket();
  link.ws = ws as unknown as WebSocket;
  return ws;
};

describe('links', () => {
  let local: Link;
  let remote: Link;

  beforeEach(() => {
    unbindAll();
    links.clear();
    local = localLink();
    remote = remoteLink(
      { id: 'host1', url: 'wss://mcp.nullnet.app/bridge', token: 'mcpb_x', enabled: true },
      bridgeSubprotocols('mcpb_x'),
    );
    links.set(local.id, local);
    links.set(remote.id, remote);
  });

  it('names the local link so the popup and the logs agree on it', () => {
    expect(local.id).toBe(LOCAL_LINK_ID);
    expect(local.url).toBe('ws://127.0.0.1:37149');
    expect(local.protocols).toEqual([]);
    expect(remote.id).toBe('remote:host1');
    expect(remote.protocols).toEqual(bridgeSubprotocols('mcpb_x'));
  });

  it('binds an mcpId to the link its hello arrived on', () => {
    expect(bindMcpToLink('alltrails-mcp:2.1.3:aabb', local)).toBe(true);
    expect(linkForMcp('alltrails-mcp:2.1.3:aabb')).toBe(local);
    expect(linkForMcp('unknown')).toBeNull();
  });

  it('lets the same link re-bind an id — an MCP re-handshakes on reconnect', () => {
    bindMcpToLink('m1', local);
    expect(bindMcpToLink('m1', local)).toBe(true);
    expect(linkForMcp('m1')).toBe(local);
  });

  it('REFUSES a second link claiming an id another link already holds', () => {
    bindMcpToLink('m1', local);
    expect(bindMcpToLink('m1', remote)).toBe(false);
    // The binding is unchanged: a refused claim must not re-point routing,
    // or a relay could have this extension answer for a local MCP.
    expect(linkForMcp('m1')).toBe(local);
  });

  it('tears one link down without touching another', () => {
    bindMcpToLink('m1', local);
    bindMcpToLink('m2', remote);
    bindMcpToLink('m3', remote);

    expect(mcpIdsForLink(remote).sort()).toEqual(['m2', 'm3']);
    expect(unbindLink(remote).sort()).toEqual(['m2', 'm3']);

    expect(linkForMcp('m1')).toBe(local);
    expect(linkForMcp('m2')).toBeNull();
    expect(mcpIdsForLink(remote)).toEqual([]);
  });

  it('frees an id once its link is gone, so the other link may take it', () => {
    bindMcpToLink('m1', local);
    unbindLink(local);
    expect(bindMcpToLink('m1', remote)).toBe(true);
    expect(linkForMcp('m1')).toBe(remote);
  });

  it('reports a link as open only while its socket is', () => {
    expect(anyLinkOpen()).toBe(false);
    const ws = open(remote);
    expect(anyLinkOpen()).toBe(true);
    ws.readyState = 3;
    expect(anyLinkOpen()).toBe(false);
  });

  it('sends only on an open socket, and says whether it did', () => {
    expect(sendOnLink(local, 'frame')).toBe(false);
    const ws = open(local);
    expect(sendOnLink(local, 'frame')).toBe(true);
    expect(ws.sent).toEqual(['frame']);
    ws.readyState = 2;
    expect(sendOnLink(local, 'later')).toBe(false);
    expect(ws.sent).toEqual(['frame']);
  });
});

describe('linkStatuses', () => {
  it('reports each link separately, local first', () => {
    unbindAll();
    links.clear();
    const local = localLink();
    const remote = remoteLink(
      { id: 'host1', url: 'wss://mcp.nullnet.app/bridge', token: 'mcpb_x', label: 'mcp-host', enabled: true },
      bridgeSubprotocols('mcpb_x'),
    );
    links.set(local.id, local);
    links.set(remote.id, remote);
    open(remote);
    bindMcpToLink('m1', remote);

    const statuses = linkStatuses();
    expect(statuses.map((s) => s.id)).toEqual(['local', 'remote:host1']);
    // One state per link, which is the whole point: a dead loopback link is
    // invisible behind any single "connected" flag.
    expect(statuses[0]).toMatchObject({ kind: 'local', connected: false, sessions: 0 });
    expect(statuses[1]).toMatchObject({ kind: 'remote', connected: true, sessions: 1, label: 'mcp-host' });
  });

  it('never carries the credential', () => {
    unbindAll();
    links.clear();
    const remote = remoteLink(
      { id: 'host1', url: 'wss://h/b', token: 'mcpb_secret', enabled: true },
      bridgeSubprotocols('mcpb_secret'),
    );
    links.set(remote.id, remote);
    expect(JSON.stringify(linkStatuses())).not.toContain('mcpb_secret');
  });
});
