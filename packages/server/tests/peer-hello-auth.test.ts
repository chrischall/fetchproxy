import { describe, it, expect, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  answersNoExtSession,
  openEncryptedFrame,
  toB64,
  type EncryptedFrame,
  type HelloFrameFromExtension,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import type { AddressInfo } from 'node:net';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { buildTestPeerHello } from './helpers/peer-hello.js';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { connectMockExtension, newExtensionIdentity } from './helpers/mock-extension.js';
import { memoryTrust } from './helpers/concentrator.js';
import type { ExtensionPin, ExtensionTrustPort } from '../src/extension-trust.js';

/**
 * FP-C: peer (role:'server') registration was unauthenticated — any local
 * process could `peers.set` a foreign mcpId, overwriting a legit peer's
 * routing slot (cross-server DoS / mcpId squatting). The peer hello already
 * carries an Ed25519 identity + signature over `mcpId || sessionNonce`; the
 * host now (a) verifies that signature BEFORE `peers.set`, and (b) refuses a
 * second live connection that claims an already-mapped mcpId with a DIFFERENT
 * identity. A same-identity re-dial (legitimate reconnect) is still allowed.
 */
/** #208: startHost now requires a trust store; these tests want a blank one. */
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

describe('authenticated peer hello (FP-C)', () => {
  let host: HostHandle | null = null;

  afterEach(async () => {
    if (host) await host.close();
    host = null;
  });

  const extHello: HelloFrameFromExtension = {
    type: 'hello',
    protocolVersion: 4,
    role: 'extension',
    platform: 'chrome',
    extensionId: 'fetchproxy',
    version: '0.4.0',
    identityX25519Pub: 'AAAA',
    identityEd25519Pub: 'AAAA',
    sessionNonce: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
  };

  async function startTestHost(): Promise<{ idDir: string; port: number }> {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const ownId = await loadOrCreateIdentity('opentable-mcp', idDir);
    host = await startHost({
      httpServer: el.server,
      ownIdentity: ownId,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890de1',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });
    return { idDir, port };
  }

  function openWs(port: number): Promise<WebSocket> {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    return new Promise((resolve, reject) => {
      ws.once('open', () => resolve(ws));
      ws.once('error', reject);
    });
  }

  it('forwards a peer hello with a valid signature to the extension', async () => {
    // Regression guard: legitimate peers (real, correctly-signed hello) must
    // still register + be announced to the extension.
    //
    // 3.0.0: the hello that gets ANNOUNCED is the one that answers the live
    // extension session — a registration hello is withheld by §1a's Rule B,
    // which the gate test in host.test.ts asserts in both directions. This
    // case is about the SIGNATURE, so it uses the shape that is forwarded.
    const { idDir, port } = await startTestHost();
    const peerId = await loadOrCreateIdentity('resy-mcp', idDir);
    const peerMcpId = 'resy-mcp:0.0.1:abc1234567890de2';
    const peerHello = await buildTestPeerHello({
      identity: peerId,
      mcpId: peerMcpId,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
      answersExtNonce: extHello.sessionNonce,
    });

    const ext = await openWs(port);
    ext.send(JSON.stringify(extHello));
    const peerHelloSeen = new Promise<void>((resolve) => {
      ext.on('message', (data: Buffer) => {
        const parsed = JSON.parse(data.toString());
        if (parsed.type === 'hello' && parsed.role === 'server' && parsed.mcpId === peerMcpId) {
          resolve();
        }
      });
    });
    await new Promise((r) => setTimeout(r, 30));

    const peer = await openWs(port);
    peer.send(JSON.stringify(peerHello));
    await peerHelloSeen; // must arrive — valid signature
    ext.close();
    peer.close();
  });

  it('refuses (closes) a peer hello whose signature does not verify', async () => {
    const { idDir, port } = await startTestHost();
    const peerId = await loadOrCreateIdentity('resy-mcp', idDir);
    const peerMcpId = 'resy-mcp:0.0.1:abc1234567890de2';
    const peerHello = await buildTestPeerHello({
      identity: peerId,
      mcpId: peerMcpId,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
    });
    // Tamper: corrupt the signature so it cannot verify against the identity.
    const forged: HelloFrameFromServer = {
      ...peerHello,
      sessionSig: Buffer.from(new Uint8Array(64).fill(9)).toString('base64'),
    };

    const ext = await openWs(port);
    ext.send(JSON.stringify(extHello));
    // The extension must NEVER see the forged peer's hello.
    let sawForged = false;
    ext.on('message', (data: Buffer) => {
      const parsed = JSON.parse(data.toString());
      if (parsed.type === 'hello' && parsed.role === 'server' && parsed.mcpId === peerMcpId) {
        sawForged = true;
      }
    });
    await new Promise((r) => setTimeout(r, 30));

    const peer = await openWs(port);
    const closed = new Promise<number>((resolve) => {
      peer.once('close', (code: number) => resolve(code));
    });
    peer.on('error', () => {
      /* expected: host closes the socket */
    });
    peer.send(JSON.stringify(forged));
    const code = await closed;
    expect(code).toBe(1008); // policy violation — auth failed
    expect(sawForged).toBe(false);
    ext.close();
  });

  it('refuses a second connection squatting a mapped mcpId with a different identity', async () => {
    const { idDir, port } = await startTestHost();
    const peerId = await loadOrCreateIdentity('resy-mcp', idDir);
    const attackerId = await loadOrCreateIdentity('attacker-mcp', idDir);
    const peerMcpId = 'resy-mcp:0.0.1:abc1234567890de2';

    const legitHello = await buildTestPeerHello({
      identity: peerId,
      mcpId: peerMcpId,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
    });
    // Attacker signs a hello for the SAME mcpId with its OWN identity. The
    // signature self-verifies (attacker holds its own key) but the identity
    // differs from the mapped slot's.
    const squatHello = await buildTestPeerHello({
      identity: attackerId,
      mcpId: peerMcpId,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
    });

    // Legit peer registers first.
    const legit = await openWs(port);
    legit.send(JSON.stringify(legitHello));
    await new Promise((r) => setTimeout(r, 30));

    // Attacker dials in claiming the same mcpId.
    const attacker = await openWs(port);
    const closed = new Promise<number>((resolve) => {
      attacker.once('close', (code: number) => resolve(code));
    });
    attacker.on('error', () => {
      /* expected */
    });
    attacker.send(JSON.stringify(squatHello));
    const code = await closed;
    expect(code).toBe(1008); // refused: mcpId already mapped to another identity
    legit.close();
  });

  it('allows a same-identity re-dial (legitimate reconnect) to take over the slot', async () => {
    const { idDir, port } = await startTestHost();
    const peerId = await loadOrCreateIdentity('resy-mcp', idDir);
    const peerMcpId = 'resy-mcp:0.0.1:abc1234567890de2';

    // First connection registers.
    const helloA = await buildTestPeerHello({
      identity: peerId,
      mcpId: peerMcpId,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
    });
    const a = await openWs(port);
    a.send(JSON.stringify(helloA));
    await new Promise((r) => setTimeout(r, 30));

    // Same identity, fresh hello/nonce (a reconnect after a flaky drop) —
    // must be accepted and take over the slot, not refused.
    //
    // 3.0.0: it echoes the live extension nonce, because a same-socket,
    // same-identity re-hello IS now the only way a peer's session hello
    // reaches the extension — which is what makes this overwrite
    // load-bearing rather than incidental.
    const helloB = await buildTestPeerHello({
      identity: peerId,
      mcpId: peerMcpId,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
      answersExtNonce: extHello.sessionNonce,
    });
    const ext = await openWs(port);
    ext.send(JSON.stringify(extHello));
    const reHelloSeen = new Promise<boolean>((resolve) => {
      ext.on('message', (data: Buffer) => {
        const parsed = JSON.parse(data.toString());
        if (parsed.type === 'hello' && parsed.role === 'server' && parsed.mcpId === peerMcpId) {
          resolve(true);
        }
      });
    });
    await new Promise((r) => setTimeout(r, 30));

    const b = await openWs(port);
    let bClosed = false;
    b.once('close', () => {
      bClosed = true;
    });
    b.send(JSON.stringify(helloB));
    // The re-dial is announced to the extension and the socket stays open.
    const seen = await Promise.race([
      reHelloSeen,
      new Promise<boolean>((r) => setTimeout(() => r(false), 500)),
    ]);
    expect(seen).toBe(true);
    expect(bClosed).toBe(false);
    a.close();
    b.close();
    ext.close();
  });
});

/**
 * Task 2.2 — the host's side of the peer path under protocol v4 (§1a).
 *
 * Four facts, none of which the compiler can hold anyone to: the cached-peer
 * hello replay is GONE, a hello with no `sessionPub` is refused at
 * registration, a hello minted for a superseded extension session is not
 * forwarded however the sends interleave, and the two relays are mutually
 * exclusive per (peer, extension session) so the exchange SETTLES.
 */
describe('host: the peer path under v4 (§1a Rule B)', () => {
  let host: HostHandle | null = null;
  const OWN_ID = 'opentable-mcp:0.9.1:abc1234567890de1';
  const PEER_ID = 'resy-mcp:0.0.1:abc1234567890de2';
  const extHello: HelloFrameFromExtension = {
    type: 'hello',
    protocolVersion: 4,
    role: 'extension',
    platform: 'chrome',
    extensionId: 'fetchproxy',
    version: '3.0.0',
    identityX25519Pub: 'AAAA',
    identityEd25519Pub: 'AAAA',
    sessionNonce: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
  };

  afterEach(async () => {
    if (host) await host.close();
    host = null;
  });

  async function startTestHost(): Promise<{ idDir: string; port: number }> {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-v4-'));
    const ownId = await loadOrCreateIdentity('opentable-mcp', idDir);
    host = await startHost({
      httpServer: el.server,
      ownIdentity: ownId,
      ownMcpId: OWN_ID,
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });
    return { idDir, port };
  }

  function openWs(port: number): Promise<WebSocket> {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    return new Promise((resolve, reject) => {
      ws.once('open', () => resolve(ws));
      ws.once('error', reject);
    });
  }

  /** Everything a socket receives, as parsed objects. */
  function framesOf(ws: WebSocket): Record<string, unknown>[] {
    const seen: Record<string, unknown>[] = [];
    ws.on('message', (data: Buffer) => {
      try {
        seen.push(JSON.parse(data.toString()) as Record<string, unknown>);
      } catch {
        /* ignore */
      }
    });
    return seen;
  }

  it('does not replay a cached peer hello to a newly connected extension', async () => {
    // Under v4 the cached frame is stale by construction: the private half it
    // names is gone or about to be, so the extension would derive against a
    // key nobody holds. The relay of the EXTENSION hello to each peer is what
    // prompts a fresh one, and the host forwards those as they arrive.
    const { idDir, port } = await startTestHost();
    const peerId = await loadOrCreateIdentity('resy-mcp', idDir);

    const peer = await openWs(port);
    const relayedToPeer = framesOf(peer);
    peer.send(
      JSON.stringify(
        await buildTestPeerHello({
          identity: peerId,
          mcpId: PEER_ID,
          serverName: 'resy-mcp',
          version: '0.0.1',
          domains: ['resy.com'],
        }),
      ),
    );
    await new Promise((r) => setTimeout(r, 40));
    // No extension yet, so neither relay fires for this peer.
    expect(relayedToPeer.length).toBe(0);

    const ext = await openWs(port);
    const seenByExt = framesOf(ext);
    ext.send(JSON.stringify(extHello));
    await new Promise((r) => setTimeout(r, 60));

    // The extension hears about the HOST and nothing about the peer — until
    // the peer, now told an extension is attached, hellos again.
    expect(seenByExt.filter((f) => f.mcpId === OWN_ID).length).toBe(1);
    expect(seenByExt.filter((f) => f.mcpId === PEER_ID).length).toBe(0);
    expect(
      relayedToPeer.filter((f) => f.type === 'hello' && f.role === 'extension').length,
    ).toBe(1);

    ext.close();
    peer.close();
  });

  it('refuses a peer hello that omits sessionPub', async () => {
    const { idDir, port } = await startTestHost();
    const peerId = await loadOrCreateIdentity('resy-mcp', idDir);
    const full = await buildTestPeerHello({
      identity: peerId,
      mcpId: PEER_ID,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
    });
    const { sessionPub: _dropped, ...withoutSessionPub } = full;

    const peer = await openWs(port);
    peer.on('error', () => {
      /* expected — the host closes the socket */
    });
    const closed = new Promise<number>((resolve) => {
      peer.once('close', (code: number) => resolve(code));
    });
    peer.send(JSON.stringify(withoutSessionPub));
    // The validator refuses the frame, so the host closes 1002 rather than
    // mapping a slot for a peer no session could ever be opened with.
    expect(await closed).toBe(1002);
  });

  it('does not forward a peer hello minted for a superseded extension session', async () => {
    // The RACE a per-peer mark passes and a frame gate cannot: the host's
    // peer-hello branch awaits `ed25519Verify`, and the extension-hello
    // handler re-points every peer's view of "which extension is attached"
    // inside that window. Withholding the frame on the wire and releasing it
    // after the next extension has connected reproduces exactly that, and the
    // assertion is on what the extension RECEIVES — so an implementation that
    // gates by some other sound means still passes.
    const { idDir, port } = await startTestHost();
    const peerId = await loadOrCreateIdentity('resy-mcp', idDir);

    const ext1 = await openWs(port);
    const seenByExt1 = framesOf(ext1);
    ext1.send(JSON.stringify(extHello));
    await new Promise((r) => setTimeout(r, 40));
    expect(seenByExt1.filter((f) => f.mcpId === OWN_ID).length).toBe(1);

    // The peer's hello for E1 — minted, signed, and simply not sent yet.
    const heldHello = await buildTestPeerHello({
      identity: peerId,
      mcpId: PEER_ID,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
      answersExtNonce: extHello.sessionNonce,
    });

    // Control first, on a host of its own: with E1 still attached, that very
    // hello IS forwarded. Without this the test would pass against a host
    // that forwards nothing.
    const control = await openWs(port);
    control.send(JSON.stringify(heldHello));
    await new Promise((r) => setTimeout(r, 60));
    expect(seenByExt1.filter((f) => f.mcpId === PEER_ID).length).toBe(1);
    control.close();
    ext1.close();
    await new Promise((r) => setTimeout(r, 50));

    // Now E2 connects, so the live extension session is a different one.
    const ext2 = await openWs(port);
    const seenByExt2 = framesOf(ext2);
    const ext2Hello = { ...extHello, sessionNonce: toB64(new Uint8Array(32).fill(9)) };
    ext2.send(JSON.stringify(ext2Hello));
    await new Promise((r) => setTimeout(r, 60));

    const peer = await openWs(port);
    const relayedToPeer = framesOf(peer);
    peer.send(JSON.stringify(heldHello));
    await new Promise((r) => setTimeout(r, 60));
    // Not forwarded: the echo names E1, and E1 is gone.
    expect(seenByExt2.filter((f) => f.mcpId === PEER_ID).length).toBe(0);
    // Nor is it a registration hello, so it draws nothing back either — the
    // peer learns about E2 from the fan-out on E2's connect instead.
    expect(
      relayedToPeer.filter((f) => f.type === 'hello' && f.role === 'extension').length,
    ).toBe(0);

    // And the hello it mints off E2's relay IS forwarded.
    peer.send(
      JSON.stringify(
        await buildTestPeerHello({
          identity: peerId,
          mcpId: PEER_ID,
          serverName: 'resy-mcp',
          version: '0.0.1',
          domains: ['resy.com'],
          answersExtNonce: ext2Hello.sessionNonce,
        }),
      ),
    );
    await new Promise((r) => setTimeout(r, 60));
    expect(seenByExt2.filter((f) => f.mcpId === PEER_ID).length).toBe(1);

    ext2.close();
    peer.close();
  });

  it('settles: one server hello per peer per extension session, on both trigger paths', async () => {
    // The property itself, end to end, against a PEER THAT REALLY MINTS —
    // driven to QUIESCENCE rather than for a fixed number of turns, because
    // the bug's signature is an exchange that never settles and a rig that
    // takes its counts after N turns records a clean number on looping code.
    const { idDir, port } = await startTestHost();
    const peerId = await loadOrCreateIdentity('resy-mcp', idDir);

    const peer = await openWs(port);
    // A minimal peer: on every relayed extension hello it mints once and
    // hellos back, which is Rule A. If the host answers that re-hello with
    // the cached extension hello, this loops for ever.
    let mints = 0;
    peer.on('message', (data: Buffer) => {
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(data.toString()) as Record<string, unknown>;
      } catch {
        return;
      }
      if (parsed.type !== 'hello' || parsed.role !== 'extension') return;
      mints++;
      void buildTestPeerHello({
        identity: peerId,
        mcpId: PEER_ID,
        serverName: 'resy-mcp',
        version: '0.0.1',
        domains: ['resy.com'],
        answersExtNonce: parsed.sessionNonce as string,
      }).then((h) => {
        if (peer.readyState === WebSocket.OPEN) peer.send(JSON.stringify(h));
      });
    });

    // Trigger path 1 — the peer DIALS into a live extension, so it is not in
    // the map for the fan-out and is triggered by the tail send instead.
    const ext1 = await openWs(port);
    const seenByExt1 = framesOf(ext1);
    ext1.send(JSON.stringify(extHello));
    await new Promise((r) => setTimeout(r, 40));
    peer.send(
      JSON.stringify(
        await buildTestPeerHello({
          identity: peerId,
          mcpId: PEER_ID,
          serverName: 'resy-mcp',
          version: '0.0.1',
          domains: ['resy.com'],
        }),
      ),
    );
    // Quiescence: wait until nothing has moved for two consecutive samples.
    const quiesce = async (): Promise<void> => {
      let last = -1;
      for (let i = 0; i < 40; i++) {
        await new Promise((r) => setTimeout(r, 25));
        const now = mints + seenByExt1.length;
        if (now === last) return;
        last = now;
      }
      throw new Error('the peer/host exchange never settled');
    };
    await quiesce();
    expect(mints).toBe(1);
    expect(seenByExt1.filter((f) => f.mcpId === PEER_ID).length).toBe(1);

    // Trigger path 2 — an extension RECONNECT, where the peer is already in
    // the map and the fan-out is what triggers it.
    ext1.close();
    await new Promise((r) => setTimeout(r, 50));
    const ext2 = await openWs(port);
    const seenByExt2 = framesOf(ext2);
    ext2.send(
      JSON.stringify({ ...extHello, sessionNonce: toB64(new Uint8Array(32).fill(5)) }),
    );
    let last = -1;
    for (let i = 0; i < 40; i++) {
      await new Promise((r) => setTimeout(r, 25));
      const now = mints + seenByExt2.length;
      if (now === last) break;
      last = now;
    }
    expect(mints).toBe(2);
    expect(seenByExt2.filter((f) => f.mcpId === PEER_ID).length).toBe(1);

    ext2.close();
    peer.close();
  });
});

/**
 * The dial path, end to end, with a REAL peer process: `startPeer` against
 * `startHost` with a mock extension already attached.
 *
 * The halves of this are covered apart — the host's gates in the describe
 * above, the peer's two keypairs in `peer.test.ts` — and this is the case
 * §1a's invariant is meant to be checkable against, so it is worth one test
 * that spans both processes: a peer that joins a live extension must end up
 * with the extension holding a key the peer still has, having sent exactly
 * one hello to the extension and never the registration one.
 */
describe('a peer dialling into a host with an extension already attached', () => {
  let host: HostHandle | null = null;
  let peer: InternalPeerHandle | null = null;
  const OWN_ID = 'opentable-mcp:0.9.1:abc1234567890de1';
  const PEER_ID = 'resy-mcp:0.0.1:abc1234567890de2';

  afterEach(async () => {
    if (peer) peer.close();
    peer = null;
    if (host) await host.close();
    host = null;
  });

  it('is announced once, with the hello it minted, and shares a key with the browser', async () => {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-dial-'));
    const ownId = await loadOrCreateIdentity('opentable-mcp', idDir);
    host = await startHost({
      httpServer: el.server,
      ownIdentity: ownId,
      ownMcpId: OWN_ID,
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });

    const browser = await newExtensionIdentity();
    const ext = await connectMockExtension(port, browser);
    await ext.waitForServerHello(OWN_ID);
    await ext.completeHandshake(OWN_ID);
    expect(ext.framesFor(PEER_ID)).toHaveLength(0);

    // Now the peer dials in. Its registration hello answers no extension
    // session, so the host withholds it and hands the peer the cached
    // extension hello instead; the peer mints, hellos again, and THAT is
    // what reaches the browser.
    const peerId = await loadOrCreateIdentity('resy-mcp', idDir);
    peer = await startPeer({
      host: '127.0.0.1',
      port,
      identity: peerId,
      mcpId: PEER_ID,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
      extensionTrust: memoryTrust(),
    });

    const seen = await ext.waitForServerHello(PEER_ID);
    await new Promise((r) => setTimeout(r, 60));
    // Exactly one, and it is the post-relay one: a registration hello answers
    // 32 zero bytes, and this one answers the live extension nonce.
    expect(ext.serverHellosFor(PEER_ID)).toHaveLength(1);
    expect(seen.answersExtNonce).toBe(ext.hello.sessionNonce);
    expect(answersNoExtSession(seen.answersExtNonce)).toBe(false);

    // The key the browser derives from that hello is the key the peer holds:
    // a frame the peer seals opens under it.
    const key = await ext.answerReady(seen);
    await peer.sendInner({ type: 'ping' });
    const sealed = await new Promise<Record<string, unknown>>((resolve) => {
      ext.ws.on('message', (data: Buffer) => {
        const parsed = JSON.parse(data.toString());
        if (parsed.type === 'frame' && parsed.mcpId === PEER_ID) resolve(parsed);
      });
    });
    expect((await openEncryptedFrame(key, sealed as unknown as EncryptedFrame, 's2e')).type).toBe(
      'ping',
    );
    ext.close();
  });
});
