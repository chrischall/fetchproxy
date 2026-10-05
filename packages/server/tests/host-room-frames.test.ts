import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  BRIDGE_ROLE_FRAME,
  BRIDGE_SERVE_FRAME,
  ROOM_PING_FRAME,
  ROOM_PING_TEXT,
  ROOM_PONG_FRAME,
  ROOM_PONG_TEXT,
  type BridgeRoleFrame,
  type HelloFrameFromExtension,
} from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { buildTestPeerHello } from './helpers/peer-hello.js';
import type { ExtensionPin, ExtensionTrustPort } from '../src/extension-trust.js';

function blankTrust(): ExtensionTrustPort {
  let pin: ExtensionPin | null = null;
  return {
    allowNew: false,
    read: async () => pin,
    write: async (next) => {
      pin = next;
    },
  };
}

const PEER_MCP_ID = 'resy-mcp:0.0.1:abc1234567890de2';
const ROOM_ACCEPTS = [BRIDGE_ROLE_FRAME, BRIDGE_SERVE_FRAME, ROOM_PING_FRAME];
const ROOM_TYPES = [BRIDGE_ROLE_FRAME, BRIDGE_SERVE_FRAME, ROOM_PING_FRAME, ROOM_PONG_FRAME];

const ROLE: BridgeRoleFrame = {
  type: BRIDGE_ROLE_FRAME,
  role: 'standby',
  canServe: true,
  serving: { label: 'Chrome', since: 1791196800000 },
};
const ROOM_TEXTS = [
  JSON.stringify(ROLE),
  JSON.stringify({ type: BRIDGE_SERVE_FRAME }),
  ROOM_PING_TEXT,
  ROOM_PONG_TEXT,
];

/**
 * The room frames (bridge-role, bridge-serve, room-ping, room-pong) belong to
 * a HOSTED relay's account room. The loopback concentrator has one extension
 * and no room: it must not answer a room-ping with a room-pong (that would
 * tell an extension a relay judged it live), and must not relay any of the
 * four between a peer and the extension in either direction. The host has no
 * dispatch branch for any of them; this pins that, with both ends advertising
 * the types.
 */
describe('host: room frames are never answered or relayed on loopback', () => {
  let host: HostHandle | null = null;
  afterEach(async () => {
    if (host) await host.close();
    host = null;
  });

  it('drops them from a peer and from the extension, answers no ping, and keeps both sockets up', async () => {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-room-'));
    const ownId = await loadOrCreateIdentity('opentable-mcp', idDir);
    const peerId = await loadOrCreateIdentity('resy-mcp', idDir);

    host = await startHost({
      httpServer: el.server,
      ownIdentity: ownId,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890de1',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });

    const open = (ws: WebSocket) => new Promise<void>((r) => ws.once('open', () => r()));
    const framesOf = (ws: WebSocket): string[] => {
      const seen: string[] = [];
      ws.on('message', (data: Buffer) => seen.push(JSON.parse(data.toString()).type));
      return seen;
    };

    const peer = new WebSocket(`ws://127.0.0.1:${port}`);
    await open(peer);
    const peerSeen = framesOf(peer);
    peer.send(
      JSON.stringify(
        await buildTestPeerHello({
          identity: peerId,
          mcpId: PEER_MCP_ID,
          serverName: 'resy-mcp',
          version: '0.0.1',
          domains: ['resy.com'],
          accepts: ['hello-rejected', ...ROOM_ACCEPTS],
        }),
      ),
    );

    const ext = new WebSocket(`ws://127.0.0.1:${port}`);
    await open(ext);
    const extSeen = framesOf(ext);
    ext.send(
      JSON.stringify({
        type: 'hello',
        protocolVersion: 4,
        role: 'extension',
        platform: 'chrome',
        extensionId: 'fetchproxy',
        version: '0.4.0',
        identityX25519Pub: 'AAAA',
        identityEd25519Pub: 'AAAA',
        sessionNonce: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
        accepts: ['peer-gone', ...ROOM_ACCEPTS],
      } satisfies HelloFrameFromExtension),
    );
    await vi.waitFor(() => expect(peerSeen).toContain('hello'));
    await vi.waitFor(() => expect(extSeen).toContain('hello'));

    // A peer posing as a room, and the extension (or anything posing as it)
    // pinging or asking to serve toward an MCP.
    for (const text of ROOM_TEXTS) {
      peer.send(text);
      ext.send(text);
    }

    await new Promise((r) => setTimeout(r, 100));
    for (const seen of [peerSeen, extSeen]) {
      for (const t of ROOM_TYPES) expect(seen).not.toContain(t);
    }
    expect(peer.readyState).toBe(WebSocket.OPEN);
    expect(ext.readyState).toBe(WebSocket.OPEN);

    peer.close();
    ext.close();
  });
});
