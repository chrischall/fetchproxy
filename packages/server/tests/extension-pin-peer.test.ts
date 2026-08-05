import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ed25519Sign,
  generateEd25519,
  generateX25519,
  validateFrame,
  type HelloFrameFromExtension,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { listenEphemeral } from './helpers/ephemeral-port.js';
import type { ExtensionPin, ExtensionTrustPort } from '../src/extension-trust.js';

/**
 * #208, peer path — which turns out to be more than a missing pin.
 *
 * A peer derives its session key from `ready.extensionSessionPub` and verifies
 * NOTHING: not a signature, not an identity. So a concentrator could put its
 * own ephemeral public key in that frame, derive the same shared secret with
 * the peer, and read and rewrite everything the peer thought was end-to-end
 * encrypted — the exact attack `T-host-MITM` in docs/SECURITY.md says is closed.
 * It is closed for the HOST's own session (0.4.0 mutual auth) and was never
 * closed here.
 *
 * The fix is the same material in both places: the host forwards the
 * extension's hello, and the peer verifies `Ed25519Sign(extPriv,
 * ownHelloNonce || extHelloNonce)` against it before deriving, then pins.
 */

const MCP_ID = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';
const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');

interface MemoryTrust extends ExtensionTrustPort {
  writes: ExtensionPin[];
}

function memoryTrust(initial: ExtensionPin | null = null, allowNew = false): MemoryTrust {
  let pin = initial;
  const writes: ExtensionPin[] = [];
  return {
    allowNew,
    writes,
    read: async () => pin,
    write: async (next) => {
      pin = next;
      writes.push(next);
    },
  };
}

/** A host stand-in that can forward an extension hello — or decline to. */
async function fakeHost(): Promise<{
  port: number;
  wss: WebSocketServer;
  /** Resolves with the peer's hello once it arrives. */
  peerHello: Promise<HelloFrameFromServer>;
  send(frame: unknown): void;
}> {
  const wss = new WebSocketServer({ port: 0 });
  const port = await listenEphemeral(wss);
  let socket: WebSocket | null = null;
  const peerHello = new Promise<HelloFrameFromServer>((resolve) => {
    wss.on('connection', (ws: WebSocket) => {
      socket = ws;
      ws.on('message', (data) => {
        const frame = validateFrame(JSON.parse(data.toString()));
        if (frame.type === 'hello' && frame.role === 'server') resolve(frame);
      });
    });
  });
  return { port, wss, peerHello, send: (frame) => socket?.send(JSON.stringify(frame)) };
}

async function extensionIdentity(): Promise<{
  hello: HelloFrameFromExtension;
  nonce: Uint8Array;
  edPriv: Uint8Array;
  pin: ExtensionPin;
}> {
  const x = await generateX25519();
  const ed = await generateEd25519();
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);
  const hello: HelloFrameFromExtension = {
    type: 'hello',
    protocolVersion: 2,
    role: 'extension',
    platform: 'chrome',
    extensionId: 'fetchproxy',
    version: '1.11.0',
    identityX25519Pub: b64(x.publicKey),
    identityEd25519Pub: b64(ed.publicKey),
    sessionNonce: b64(nonce),
  };
  return {
    hello,
    nonce,
    edPriv: ed.privateKey,
    pin: {
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
      pinnedAt: 1_700_000_000_000,
    },
  };
}

async function readyFor(
  peerHello: HelloFrameFromServer,
  ext: Awaited<ReturnType<typeof extensionIdentity>>,
  opts: { forge?: boolean } = {},
): Promise<unknown> {
  const mcpNonce = new Uint8Array(Buffer.from(peerHello.sessionNonce, 'base64'));
  const payload = new Uint8Array(mcpNonce.length + ext.nonce.length);
  payload.set(mcpNonce, 0);
  payload.set(ext.nonce, mcpNonce.length);
  const sig = opts.forge ? new Uint8Array(64).fill(3) : await ed25519Sign(ext.edPriv, payload);
  const eph = await generateX25519();
  return {
    type: 'ready',
    mcpId: MCP_ID,
    extensionSessionPub: b64(eph.publicKey),
    sessionSig: b64(sig),
  };
}

describe('a peer authenticates the extension behind the host', () => {
  let peer: InternalPeerHandle | null = null;
  let host: Awaited<ReturnType<typeof fakeHost>> | null = null;

  afterEach(async () => {
    if (peer) peer.close();
    peer = null;
    if (host) {
      await new Promise<void>((r) => host!.wss.close(() => r()));
      host = null;
    }
    vi.restoreAllMocks();
  });

  async function startTestPeer(trust: ExtensionTrustPort, requirePin = false): Promise<void> {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peerpin-'));
    peer = await startPeer({
      host: '127.0.0.1',
      port: host!.port,
      identity: await loadOrCreateIdentity('opentable-mcp', idDir),
      mcpId: MCP_ID,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      extensionTrust: trust,
      requireExtensionIdentity: requirePin,
    });
  }

  it('derives a session when the forwarded hello signs the ready, and pins it', async () => {
    host = await fakeHost();
    const trust = memoryTrust();
    await startTestPeer(trust);
    const ext = await extensionIdentity();
    const hello = await host.peerHello;

    host.send(ext.hello);
    host.send(await readyFor(hello, ext));

    await expect(peer!.session).resolves.toBeDefined();
    expect(trust.writes).toHaveLength(1);
    expect(trust.writes[0]).toMatchObject({
      identityX25519Pub: ext.hello.identityX25519Pub,
    });
  });

  it('refuses a ready whose signature does not verify — the MITM case', async () => {
    // A concentrator substituting its own ephemeral pub cannot produce this
    // signature, because it does not hold the extension's Ed25519 key.
    host = await fakeHost();
    const trust = memoryTrust();
    await startTestPeer(trust);
    const ext = await extensionIdentity();
    const hello = await host.peerHello;

    host.send(ext.hello);
    host.send(await readyFor(hello, ext, { forge: true }));

    await expect(peer!.session).rejects.toThrow();
    expect(trust.writes).toEqual([]);
  });

  it('refuses an extension identity that is not the pinned one', async () => {
    host = await fakeHost();
    const stranger = await extensionIdentity();
    const trust = memoryTrust(stranger.pin);
    await startTestPeer(trust);
    const ext = await extensionIdentity();
    const hello = await host.peerHello;

    host.send(ext.hello);
    host.send(await readyFor(hello, ext));

    await expect(peer!.session).rejects.toThrow();
    expect(trust.writes).toEqual([]);
  });

  it('warns, but still works, behind a host too old to forward the hello', async () => {
    // Mixed-version local fleets are normal: whichever MCP wins the port
    // election is arbitrary, so a new peer regularly finds an old host. It
    // says so rather than pretending the guarantee holds.
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    host = await fakeHost();
    const trust = memoryTrust();
    await startTestPeer(trust);
    const ext = await extensionIdentity();
    const hello = await host.peerHello;

    host.send(await readyFor(hello, ext));

    await expect(peer!.session).resolves.toBeDefined();
    expect(warn.mock.calls.flat().join(' ')).toMatch(/does not forward|cannot verify/i);
    expect(trust.writes).toEqual([]);
  });

  it('refuses that same case when the caller requires the identity', async () => {
    host = await fakeHost();
    const trust = memoryTrust();
    await startTestPeer(trust, true);
    const ext = await extensionIdentity();
    const hello = await host.peerHello;

    host.send(await readyFor(hello, ext));

    await expect(peer!.session).rejects.toThrow();
  });
});
