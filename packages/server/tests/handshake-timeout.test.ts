import { describe, it, expect, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MAX_FRAME_BYTES, type HelloFrameFromExtension } from '@fetchproxy/protocol';
import {
  startHost,
  HANDSHAKE_TIMEOUT_MS,
  MAX_PAYLOAD_BYTES,
  type HostHandle,
} from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
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

async function bootHost(
  handshakeTimeoutMs?: number,
  maxPayloadBytes?: number,
): Promise<{
  handle: HostHandle;
  port: number;
}> {
  const el = await electRole({ host: '127.0.0.1', port: 0 });
  if (el.role !== 'host') throw new Error('expected host');
  const port = (el.server.address() as AddressInfo).port;
  const idDir = mkdtempSync(join(tmpdir(), 'fp-handshake-'));
  const id = await loadOrCreateIdentity('opentable-mcp', idDir);
  const handle = await startHost({
    httpServer: el.server,
    ownIdentity: id,
    ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
    ownServerName: 'opentable-mcp',
    ownVersion: '0.9.1',
    ownDomains: ['opentable.com'],
    extensionTrust: blankTrust(),
    handshakeTimeoutMs,
    maxPayloadBytes,
  });
  return { handle, port };
}

function opened(ws: WebSocket): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });
}

/** Resolve with the close code, or `null` if `ms` elapsed with the socket alive. */
function closeCodeWithin(ws: WebSocket, ms: number): Promise<number | null> {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(null), ms);
    ws.once('close', (code) => {
      clearTimeout(t);
      resolve(code);
    });
  });
}

const extHello: HelloFrameFromExtension = {
  type: 'hello',
  protocolVersion: 3,
  role: 'extension',
  platform: 'chrome',
  extensionId: 'fetchproxy',
  version: '2.6.0',
  identityX25519Pub: 'AAAA',
  identityEd25519Pub: 'AAAA',
  sessionNonce: 'AAAA',
};

describe('host handshake timeout (docs/SECURITY.md §T2 defense 3)', () => {
  let host: HostHandle | null = null;
  const sockets: WebSocket[] = [];

  afterEach(async () => {
    for (const ws of sockets.splice(0)) {
      try {
        ws.terminate();
      } catch {
        /* already gone */
      }
    }
    if (host) await host.close();
    host = null;
  });

  it('is the 15 s the security doc promises', () => {
    expect(HANDSHAKE_TIMEOUT_MS).toBe(15_000);
  });

  it('closes a socket that connects and never says hello', async () => {
    const booted = await bootHost(150);
    host = booted.handle;
    const ws = new WebSocket(`ws://127.0.0.1:${booted.port}`);
    sockets.push(ws);
    await opened(ws);

    // Say nothing at all — the drive-by port scanner.
    expect(await closeCodeWithin(ws, 2000)).toBe(1008);
  });

  it('leaves a socket that completed its hello inside the window alone', async () => {
    const booted = await bootHost(150);
    host = booted.handle;
    const ws = new WebSocket(`ws://127.0.0.1:${booted.port}`);
    sockets.push(ws);
    await opened(ws);
    ws.send(JSON.stringify(extHello));

    // Well past the deadline: the hello landed, so nothing may reap it.
    expect(await closeCodeWithin(ws, 1000)).toBeNull();
    expect(ws.readyState).toBe(WebSocket.OPEN);
  });

  it("caps the frame a peer may send at the protocol's own frame budget", () => {
    // Not a number of its own. `MAX_FRAME_BYTES` is derived from the largest
    // legitimate frame (seal.ts carries the arithmetic), and the extension
    // measures against the SAME constant before it seals — so a conforming
    // sender fails one request rather than reaching the 1009 below, which on
    // the extension's socket would drop every MCP on this concentrator.
    expect(MAX_PAYLOAD_BYTES).toBe(MAX_FRAME_BYTES);
  });

  it('closes a socket that sends a frame over the cap', async () => {
    // A small cap, injected: the behaviour under test is the close, not the
    // size of the constant, and pushing 42 MiB over loopback to watch it
    // would test the latter slowly.
    const booted = await bootHost(undefined, 64 * 1024);
    host = booted.handle;
    const ws = new WebSocket(`ws://127.0.0.1:${booted.port}`, {
      maxPayload: 64 * 1024 * 1024,
    });
    sockets.push(ws);
    await opened(ws);

    ws.send(JSON.stringify({ type: 'hello', pad: 'a'.repeat(128 * 1024) }));
    // 1009 = "message too big" — the cap bit, not the frame validator.
    expect(await closeCodeWithin(ws, 5000)).toBe(1009);
  });

  it('control: a frame under the cap reaches the validator instead', async () => {
    const booted = await bootHost(undefined, 64 * 1024);
    host = booted.handle;
    const ws = new WebSocket(`ws://127.0.0.1:${booted.port}`, {
      maxPayload: 64 * 1024 * 1024,
    });
    sockets.push(ws);
    await opened(ws);

    ws.send(JSON.stringify({ type: 'hello', pad: 'a'.repeat(1024) }));
    // 1002 = protocol error from validateFrame, so the control proves the
    // 1009 above came from the size cap and not from the same rejection.
    expect(await closeCodeWithin(ws, 5000)).toBe(1002);
  });
});
