import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { WebSocket } from 'ws';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { MAX_PAYLOAD_BYTES } from '../src/host.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import {
  memoryTrust,
  startFakeConcentrator,
  type FakeConcentrator,
} from './helpers/concentrator.js';

/**
 * The peer caps what the HOST may send it, at the same number the host caps
 * what a peer may send.
 *
 * host.ts has always handed `maxPayload` to its `WebSocketServer`, so
 * peer→host was bounded at the protocol's frame budget; the peer's client
 * socket was built bare and so sat at `ws`'s 100 MiB default. That is 100 MiB
 * of this MCP's memory whatever holds port 37149 can make it buffer before a
 * byte is validated — and whatever holds that port is simply whoever bound it
 * first, not something this peer has authenticated.
 */

async function bootPeer(maxPayloadBytes?: number): Promise<{
  peer: InternalPeerHandle;
  rig: FakeConcentrator;
  hostSide: WebSocket;
}> {
  const rig = await startFakeConcentrator();
  const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-payload-'));
  const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
  const peer = await startPeer({
    host: '127.0.0.1',
    port: rig.port,
    identity,
    mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
    serverName: 'opentable-mcp',
    version: '0.9.1',
    domains: ['opentable.com'],
    extensionTrust: memoryTrust(),
    maxPayloadBytes,
  });
  await rig.waitForHello();
  return { peer, rig, hostSide: await rig.socket() };
}

/** Resolve with the close code the host side sees, or `null` if `ms` elapsed. */
function closeCodeWithin(ws: WebSocket, ms: number): Promise<number | null> {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(null), ms);
    ws.once('close', (code) => {
      clearTimeout(t);
      resolve(code);
    });
  });
}

/** Byte lengths of every message the peer's socket delivers from here on. */
function delivered(peer: InternalPeerHandle): number[] {
  const sizes: number[] = [];
  peer.ws.on('message', (data: Buffer) => sizes.push(data.length));
  return sizes;
}

describe("a peer caps inbound frames at the host's own payload cap", () => {
  let peer: InternalPeerHandle | null = null;
  let rig: FakeConcentrator | null = null;

  afterEach(async () => {
    vi.restoreAllMocks();
    if (peer) peer.close();
    peer = null;
    if (rig) {
      await rig.close();
      rig = null;
    }
  });

  // A small cap, injected, as handshake-timeout.test.ts does for the host: the
  // behaviour under test is the close, not the size of the constant.
  const CAP = 64 * 1024;

  it('closes with 1009 on a host→peer frame one byte over the cap, delivering nothing', async () => {
    // `ws` emits WS_ERR_UNSUPPORTED_MESSAGE_LENGTH before the close; the
    // peer's persistent listener warns about it.
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const booted = await bootPeer(CAP);
    ({ peer, rig } = booted);
    const sizes = delivered(peer);

    const closed = closeCodeWithin(booted.hostSide, 5000);
    booted.hostSide.send('a'.repeat(CAP + 1));
    // 1009 = "message too big", sent by the peer: the cap bit.
    expect(await closed).toBe(1009);
    expect(sizes).toEqual([]);
  });

  it('control: a frame exactly at the cap is delivered and the socket stays up', async () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const booted = await bootPeer(CAP);
    ({ peer, rig } = booted);
    const sizes = delivered(peer);

    const closed = closeCodeWithin(booted.hostSide, 500);
    booted.hostSide.send('a'.repeat(CAP));
    expect(await closed).toBeNull();
    expect(sizes).toEqual([CAP]);
  });

  it('defaults to MAX_PAYLOAD_BYTES, not ws’s 100 MiB', async () => {
    // The one test that pushes the real number: an injected cap cannot catch
    // the defect this file exists for, which is the default never being
    // passed at all. `ws` refuses on the frame HEADER's length, so the peer
    // closes without buffering the body.
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    const booted = await bootPeer();
    ({ peer, rig } = booted);
    const sizes = delivered(peer);

    const closed = closeCodeWithin(booted.hostSide, 10_000);
    booted.hostSide.send(Buffer.alloc(MAX_PAYLOAD_BYTES + 1, 0x61));
    expect(await closed).toBe(1009);
    expect(sizes).toEqual([]);
  }, 20_000);
});
