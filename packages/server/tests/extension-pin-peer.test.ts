import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ed25519Sign,
  fromB64,
  generateEd25519,
  generateX25519,
  readySignaturePayload,
  validateFrame,
  type HelloFrameFromExtension,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { listenEphemeral, loopbackWss } from './helpers/ephemeral-port.js';
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
 *
 * 3.0.0 (protocol 4) changes the SHAPE of every case below, because a peer now
 * has two keypairs. The hello it sends at dial carries a BOOTSTRAP ephemeral
 * and answers no extension session; the hello a `ready` may answer is the one
 * it mints when the relayed extension hello arrives. So each test here relays
 * the extension hello FIRST and answers the SECOND peer hello — and the test
 * that used to assert a peer warns-and-proceeds behind a host that relays
 * nothing now asserts a refusal, because the HKDF salt contains the
 * extension's nonce and a peer without it cannot compute a key at all.
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

/**
 * A host stand-in that can forward an extension hello — or decline to.
 *
 * 3.0.0: it keeps EVERY peer hello rather than the first, because a v4 peer
 * sends two — the registration hello at dial and a fresh one per extension
 * session — and which of them a `ready` answers is the whole subject of §1a.
 */
async function fakeHost(): Promise<{
  port: number;
  wss: WebSocketServer;
  /** Wait for peer hello number `nth` (0 = the registration hello). */
  peerHello(nth?: number): Promise<HelloFrameFromServer>;
  /** How many peer hellos have arrived so far. */
  helloCount(): number;
  send(frame: unknown): void;
}> {
  const wss = loopbackWss();
  const port = await listenEphemeral(wss);
  let socket: WebSocket | null = null;
  const hellos: HelloFrameFromServer[] = [];
  const waiters: (() => void)[] = [];
  wss.on('connection', (ws: WebSocket) => {
    socket = ws;
    ws.on('message', (data) => {
      const frame = validateFrame(JSON.parse(data.toString()));
      if (frame.type === 'hello' && frame.role === 'server') {
        hellos.push(frame);
        for (const wake of waiters.splice(0)) wake();
      }
    });
  });
  const peerHello = async (nth = 0): Promise<HelloFrameFromServer> => {
    for (;;) {
      if (hellos.length > nth) return hellos[nth]!;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`no peer hello #${nth}`)), 5_000);
        waiters.push(() => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
  };
  return {
    port,
    wss,
    peerHello,
    helloCount: () => hellos.length,
    send: (frame) => socket?.send(JSON.stringify(frame)),
  };
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
    protocolVersion: 4,
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
  const mcpNonce = fromB64(peerHello.sessionNonce);
  const mcpSessionPub = fromB64(peerHello.sessionPub);
  const eph = await generateX25519();
  // 3.0.0: four fields, and the `mcpSessionPub` on the wire is what lets the
  // peer tell a STALE ready (discard) from a forged one (1008).
  const payload = readySignaturePayload(mcpNonce, ext.nonce, eph.publicKey, mcpSessionPub);
  const sig = opts.forge ? new Uint8Array(64).fill(3) : await ed25519Sign(ext.edPriv, payload);
  return {
    type: 'ready',
    mcpId: MCP_ID,
    extensionSessionPub: b64(eph.publicKey),
    mcpSessionPub: peerHello.sessionPub,
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
    await host.peerHello(0);

    host.send(ext.hello);
    // The hello the peer mints in answer to that relay is the one a session
    // can be opened from; its predecessor named the bootstrap ephemeral.
    const hello = await host.peerHello(1);
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
    await host.peerHello(0);

    host.send(ext.hello);
    const hello = await host.peerHello(1);
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
    await host.peerHello(0);

    host.send(ext.hello);
    const hello = await host.peerHello(1);
    host.send(await readyFor(hello, ext));

    await expect(peer!.session).rejects.toThrow();
    expect(trust.writes).toEqual([]);
  });

  it('refuses, rather than warning, behind a host too old to forward the hello', async () => {
    // Mixed-version local fleets are normal: whichever MCP wins the port
    // election is arbitrary, so a new peer regularly finds an old host. Under
    // v3 it warned and proceeded, which was a real if unverifiable bridge.
    //
    // 3.0.0 cannot make that trade: the HKDF salt is a transcript containing
    // the EXTENSION's hello nonce, which arrives only on the relayed hello,
    // so there is no key to derive rather than an unverified one. A `ready`
    // here names the peer's BOOTSTRAP ephemeral — the only pub such a host
    // could have shown the extension — and §1a's Rule C discards it, because
    // the bootstrap half is never a session candidate.
    host = await fakeHost();
    const trust = memoryTrust();
    await startTestPeer(trust);
    const ext = await extensionIdentity();
    const registration = await host.peerHello(0);

    host.send(await readyFor(registration, ext));

    await new Promise((r) => setTimeout(r, 80));
    expect(peer!.sessionLinked()).toBe(false);
    expect(trust.writes).toEqual([]);
    // And no second hello was minted: nothing triggered one.
    expect(host.helloCount()).toBe(1);
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
    await host.peerHello(0);

    const relayKey = await generateX25519();
    host.send(ext.hello);
    const hello = await host.peerHello(1);
    const genuine = (await readyFor(hello, ext)) as {
      type: string;
      mcpId: string;
      extensionSessionPub: string;
      mcpSessionPub: string;
      sessionSig: string;
    };
    host.send({ ...genuine, extensionSessionPub: b64(relayKey.publicKey) });

    await expect(peer!.session).rejects.toThrow(/identity refused/);
    expect(trust.writes).toEqual([]);
  });

  it('refuses a host that relays nothing whether or not requireExtensionIdentity is set', async () => {
    // The option is INERT since 3.0.0 and kept only so the cohort's
    // constructors compile: the refusal above does not depend on it, and this
    // is the assertion that says so rather than leaving a flag that looks
    // like it still decides something.
    host = await fakeHost();
    const trust = memoryTrust();
    await startTestPeer(trust, true);
    const ext = await extensionIdentity();
    const registration = await host.peerHello(0);

    host.send(await readyFor(registration, ext));

    await new Promise((r) => setTimeout(r, 80));
    expect(peer!.sessionLinked()).toBe(false);
    expect(trust.writes).toEqual([]);
  });
});
