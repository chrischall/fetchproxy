import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ecdhX25519,
  ed25519Sign,
  fromB64,
  generateEd25519,
  generateX25519,
  readySignaturePayload,
  hkdfSha256,
  validateFrame,
  HKDF_SESSION_INFO,
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
 * A peer derived its session key from `ready.extensionSessionPub` while
 * verifying NOTHING: not a signature, not an identity. Anything that could
 * reach it could therefore BE the extension as far as it was concerned, with
 * no key material of its own — while `T-host-MITM` in docs/SECURITY.md said
 * peer traffic was end-to-end encrypted. The host's own session got mutual auth
 * in 0.4.0; the peer path never did.
 *
 * The fix is the same material in both places: the host forwards the
 * extension's hello, and the peer verifies `Ed25519Sign(extPriv,
 * ownHelloNonce || extHelloNonce)` against it before deriving, then pins.
 *
 * 2.0.0 finishes it: the signature covers `extensionSessionPub` as well as the
 * two nonces, so a relay cannot forward genuine frames and swap in an ephemeral
 * key of its own. The last test here is the one that used to record that gap as
 * a known residual; it now asserts the refusal.
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
    protocolVersion: 3,
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
  const eph = await generateX25519();
  const payload = readySignaturePayload(mcpNonce, ext.nonce, eph.publicKey);
  const sig = opts.forge ? new Uint8Array(64).fill(3) : await ed25519Sign(ext.edPriv, payload);
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

  it('refuses a ready whose signature does not verify', async () => {
    // Nothing that lacks the extension's Ed25519 key can produce this — which
    // is what stops a concentrator inventing an extension outright. It is NOT
    // what stops one relaying a real extension's signature; see the last test.
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

  it('refuses a relay that forwards a genuine signature but swaps the ephemeral key', async () => {
    // This test used to assert the opposite, under the name KNOWN RESIDUAL,
    // with a comment saying it should start failing the day the signature
    // covered the ephemeral key. It did, and this is that day: `sessionSig`
    // now signs (mcpNonce || extNonce || extensionSessionPub), so forwarding a
    // real hello and a real signature is no longer enough — the relay would
    // have to sign its own key with the extension's Ed25519 private key.
    host = await fakeHost();
    const trust = memoryTrust();
    await startTestPeer(trust);
    const ext = await extensionIdentity();
    const hello = await host.peerHello;

    const genuine = (await readyFor(hello, ext)) as {
      type: string;
      mcpId: string;
      extensionSessionPub: string;
      sessionSig: string;
    };
    const relayKey = await generateX25519();
    host.send(ext.hello);
    host.send({ ...genuine, extensionSessionPub: b64(relayKey.publicKey) });

    await expect(peer!.session).rejects.toThrow(/identity refused/);
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
