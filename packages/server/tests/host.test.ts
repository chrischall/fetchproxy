import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateFrame,
  type HelloFrameFromExtension,
} from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { buildServerHello } from '../src/build-server-hello.js';
import type { ExtensionPin, ExtensionTrustPort } from '../src/extension-trust.js';

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

describe('host (concentrator)', () => {
  let host: HostHandle | null = null;

  afterEach(async () => {
    if (host) await host.close();
    host = null;
  });

  it('accepts extension WS and forwards its own hello after extension says hi', async () => {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    expect(el.role).toBe('host');
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);

    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });

    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((resolve, reject) => {
      ws.once('open', () => resolve());
      ws.once('error', reject);
    });

    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: 3,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AAAA',
    };
    ws.send(JSON.stringify(extHello));

    const ownHelloPromise = new Promise<Record<string, unknown>>((resolve) => {
      ws.on('message', (data) => {
        const parsed = JSON.parse(data.toString());
        if (
          parsed.type === 'hello' &&
          parsed.role === 'server' &&
          parsed.mcpId === 'opentable-mcp:0.9.1:abc1234567890def'
        ) {
          resolve(parsed);
        }
      });
    });
    const ownHello = await ownHelloPromise;
    expect(ownHello.serverName).toBe('opentable-mcp');
    expect(ownHello.domains).toEqual(['opentable.com']);
    expect(() => validateFrame(ownHello)).not.toThrow();

    // 2.5.0: the handle reports the extension link for bridgeHealth().session
    // — attached (its hello landed), but no session until a ready arrives.
    expect(host.extensionConnected()).toBe(true);
    expect(host.sessionLinked()).toBe(false);

    ws.close();
    await new Promise<void>((r) => ws.once('close', () => r()));
    await vi.waitFor(() => expect(host!.extensionConnected()).toBe(false));
  });

  it('relays extension-disconnected to peers that accept it, and only to those (2.5.0)', async () => {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const ownId = await loadOrCreateIdentity('opentable-mcp', idDir);
    const newPeerId = await loadOrCreateIdentity('resy-mcp', idDir);
    const oldPeerId = await loadOrCreateIdentity('tock-mcp', idDir);

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

    // A 2.5.0 peer advertises the frame; a pre-2.5 peer does not.
    const newPeer = new WebSocket(`ws://127.0.0.1:${port}`);
    await open(newPeer);
    const newPeerSeen = framesOf(newPeer);
    newPeer.send(
      JSON.stringify(
        await buildServerHello({
          identity: newPeerId,
          mcpId: 'resy-mcp:0.0.1:abc1234567890de2',
          serverName: 'resy-mcp',
          version: '0.0.1',
          domains: ['resy.com'],
          accepts: ['extension-disconnected'],
        }),
      ),
    );
    const oldPeer = new WebSocket(`ws://127.0.0.1:${port}`);
    await open(oldPeer);
    const oldPeerSeen = framesOf(oldPeer);
    oldPeer.send(
      JSON.stringify(
        await buildServerHello({
          identity: oldPeerId,
          mcpId: 'tock-mcp:0.0.1:abc1234567890de3',
          serverName: 'tock-mcp',
          version: '0.0.1',
          domains: ['exploretock.com'],
        }),
      ),
    );

    // Extension attaches (both peers get its hello relayed), then leaves.
    const ext = new WebSocket(`ws://127.0.0.1:${port}`);
    await open(ext);
    ext.send(
      JSON.stringify({
        type: 'hello',
        protocolVersion: 3,
        role: 'extension',
        platform: 'chrome',
        extensionId: 'fetchproxy',
        version: '0.4.0',
        identityX25519Pub: 'AAAA',
        identityEd25519Pub: 'AAAA',
        sessionNonce: 'AAAA',
      } satisfies HelloFrameFromExtension),
    );
    await vi.waitFor(() => expect(newPeerSeen).toContain('hello'));
    await vi.waitFor(() => expect(oldPeerSeen).toContain('hello'));
    expect(host.extensionConnected()).toBe(true);

    ext.close();
    await vi.waitFor(() => expect(newPeerSeen).toContain('extension-disconnected'));
    expect(host.extensionConnected()).toBe(false);
    // Give the host a beat: the old peer must NOT have been sent the frame.
    await new Promise((r) => setTimeout(r, 50));
    expect(oldPeerSeen).not.toContain('extension-disconnected');

    newPeer.close();
    oldPeer.close();
  });

  it('reports the extension link as unattached before any extension dials in', async () => {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);
    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });
    expect(host.extensionConnected()).toBe(false);
    expect(host.sessionLinked()).toBe(false);
  });

  it('rejects WS upgrades with public Origin header', async () => {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);

    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });

    // Connect with an Origin header that simulates a public webpage.
    const ws = new WebSocket(`ws://127.0.0.1:${port}`, {
      headers: { Origin: 'https://evil.com' },
    });
    const closedWithError = await new Promise<boolean>((resolve) => {
      ws.once('error', () => resolve(true));
      ws.once('open', () => resolve(false));
    });
    expect(closedWithError).toBe(true);
  });

  it('sendOwnInner rejects if the extension disconnects before sending ready', async () => {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);

    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });

    // Mock extension: open the WS, send hello, then disconnect without ready.
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => ws.once('open', () => r()));
    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: 3,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AAAA',
    };
    ws.send(JSON.stringify(extHello));
    await new Promise((r) => setTimeout(r, 30));  // let host record the connection
    ws.close();

    await expect(host.sendOwnInner({ type: 'ping' })).rejects.toThrow(
      /extension disconnected before ready/,
    );
  });

  it('closes WS with 1011 (internal error) when crypto unwinds during ready', async () => {
    // host.ts:189-190 — the outer catch around the message handler.
    // If the extension's ready frame survives validateFrame (i.e. it's
    // valid base64 of any length) but ecdhX25519 / hkdfSha256 throw on
    // the resulting bytes, the host must terminate the WS with 1011 so
    // an external observer can distinguish a protocol-shape failure
    // (1002) from a crypto / handler crash (1011). Without this branch
    // the rejection escapes into an unhandled promise.
    //
    // 0.4.0: with mutual auth in place, we have to first produce a
    // valid ed25519 signature on the ReadyFrame so the host doesn't
    // close with 1008. Only THEN do we hand it an undersized X25519
    // session pub to provoke the ecdhX25519 throw — which still
    // routes through the same outer-catch path and still produces
    // 1011.
    const {
      generateX25519: genX,
      generateEd25519: genEd,
      ed25519Sign,
      readySignaturePayload,
      validateFrame: vf,
    } = await import('@fetchproxy/protocol');

    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);

    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });

    // Pretend to be the extension. Generate a real identity so the
    // signature on the ReadyFrame verifies (the host's pre-crypto
    // gate runs before the ECDH).
    const extX = await genX();
    const extEd = await genEd();
    const extSessionNonce = new Uint8Array(32).fill(7);
    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: 3,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: Buffer.from(extX.publicKey).toString('base64'),
      identityEd25519Pub: Buffer.from(extEd.publicKey).toString('base64'),
      sessionNonce: Buffer.from(extSessionNonce).toString('base64'),
    };
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => ws.once('open', () => r()));
    // Capture the host's hello so we can extract its sessionNonce
    // (required for the ReadyFrame signature payload).
    const helloPromise = new Promise<{ sessionNonce: string }>((resolve) => {
      ws.on('message', (data) => {
        try {
          const parsed = vf(JSON.parse(data.toString()));
          if (parsed.type === 'hello' && parsed.role === 'server') {
            resolve({ sessionNonce: parsed.sessionNonce });
          }
        } catch {
          // ignore
        }
      });
    });
    ws.send(JSON.stringify(extHello));
    const { sessionNonce: mcpNonceB64 } = await helloPromise;
    // Silence unhandled-error noise from the host-side ws.close before the
    // test-side ws sees a clean close: the host writes a 1011 close frame
    // then terminates, and ws.on('error') would otherwise fire on EPIPE.
    ws.on('error', () => {
      /* expected */
    });
    const closed = new Promise<{ code: number; reason: string }>((resolve) => {
      ws.once('close', (code: number, reason: Buffer) =>
        resolve({ code, reason: reason.toString() }),
      );
    });
    const mcpNonce = new Uint8Array(Buffer.from(mcpNonceB64, 'base64'));
    // 8 bytes instead of 32 — a legal base64 field that ECDH will reject. The
    // signature has to cover THIS value (2.0.0+), or the host closes 1008 for a
    // bad signature before it ever reaches the crypto path under test.
    const shortPub = new Uint8Array(8);
    const sigPayload = readySignaturePayload(mcpNonce, extSessionNonce, shortPub);
    const sig = await ed25519Sign(extEd.privateKey, sigPayload);
    const badReady = {
      type: 'ready',
      mcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      extensionSessionPub: Buffer.from(shortPub).toString('base64'),
      sessionSig: Buffer.from(sig).toString('base64'),
    };
    ws.send(JSON.stringify(badReady));
    const { code } = await closed;
    expect(code).toBe(1011);
  });

  it('closes WS with 1002 (protocol error) on malformed JSON or invalid frame', async () => {
    // host.ts:114-115 — JSON.parse fails or validateFrame throws. The
    // host MUST tear the connection down (1002 = protocol error in the
    // RFC 6455 codes) rather than ignoring the message: a misbehaving
    // peer should not be able to occupy the slot indefinitely.
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);

    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });

    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => ws.once('open', () => r()));
    const closed = new Promise<{ code: number; reason: string }>((resolve) => {
      ws.once('close', (code: number, reason: Buffer) =>
        resolve({ code, reason: reason.toString() }),
      );
    });
    ws.send('not-json-at-all');
    const { code, reason } = await closed;
    expect(code).toBe(1002);
    expect(reason).toBe('protocol error');
  });

  it('forwards a peer hello to the already-connected extension', async () => {
    // host.ts:138 — when a peer's `hello` arrives after the extension
    // is already attached, host forwards the peer hello to the
    // extension verbatim. This is the path that makes multi-MCP
    // setups work (peer arrives second; the host announces it to the
    // extension so it can pair the new identity).
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
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

    // Attach extension first.
    const ext = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => ext.once('open', () => r()));
    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: 3,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AAAA',
    };
    ext.send(JSON.stringify(extHello));

    // Capture every server-hello the extension sees, so we can prove
    // BOTH the host's own hello AND the peer's hello reach it.
    const seenHellos: string[] = [];
    const peerHelloSeen = new Promise<void>((resolve) => {
      ext.on('message', (data: Buffer) => {
        const parsed = JSON.parse(data.toString());
        if (parsed.type === 'hello' && parsed.role === 'server') {
          seenHellos.push(parsed.mcpId);
          if (parsed.mcpId === 'resy-mcp:0.0.1:abc1234567890de2') resolve();
        }
      });
    });

    // Wait briefly for extension's hello to be processed.
    await new Promise((r) => setTimeout(r, 50));

    // Now connect a "peer" — synthesise its hello with the resy identity.
    const peerHello = await buildServerHello({
      identity: peerId,
      mcpId: 'resy-mcp:0.0.1:abc1234567890de2',
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
    });
    const peer = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => peer.once('open', () => r()));
    peer.send(JSON.stringify(peerHello));

    await peerHelloSeen;
    expect(seenHellos).toContain('opentable-mcp:0.9.1:abc1234567890de1');
    expect(seenHellos).toContain('resy-mcp:0.0.1:abc1234567890de2');

    ext.close();
    peer.close();
  });

  it('stale peer socket close does not evict the re-registered live slot (FP-B1)', async () => {
    // A peer whose WS drops re-dials with the SAME mcpId. The new
    // connection runs peers.set(X, newSlot). When the OLD socket's close
    // finally fires it must NOT peers.delete(X) — that would strand the
    // live (new) peer until its next reconnect. The delete is now guarded:
    // only delete if the mapped slot's ws is still the closing socket.
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
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

    // Attach the extension so peer→extension frame forwarding is live.
    const ext = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => ext.once('open', () => r()));
    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: 3,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AAAA',
    };
    ext.send(JSON.stringify(extHello));
    await new Promise((r) => setTimeout(r, 30));

    const peerMcpId = 'resy-mcp:0.0.1:abc1234567890de2';
    const peerHello = await buildServerHello({
      identity: peerId,
      mcpId: peerMcpId,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
    });

    // Peer connection A — the original, soon-to-be-stale socket.
    const peerA = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => peerA.once('open', () => r()));
    peerA.send(JSON.stringify(peerHello));
    await new Promise((r) => setTimeout(r, 30));

    // Peer connection B — same mcpId, the live re-registration.
    const peerB = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => peerB.once('open', () => r()));
    // The extension is now seeing peer hellos; capture frames routed to B.
    const bGotFrame = new Promise<boolean>((resolve) => {
      peerB.on('message', (data: Buffer) => {
        const parsed = JSON.parse(data.toString());
        if (parsed.type === 'frame' && parsed.mcpId === peerMcpId) resolve(true);
      });
    });
    peerB.send(JSON.stringify(peerHello));
    await new Promise((r) => setTimeout(r, 30));

    // Now the OLD socket A closes (the late, stale close).
    peerA.close();
    await new Promise((r) => setTimeout(r, 50));

    // The extension routes a frame for the peer's mcpId. With the race
    // fixed it must reach B (the live slot). With the bug, slot X was
    // deleted by A's close and the frame is dropped.
    const extToPeerFrame = {
      type: 'frame',
      mcpId: peerMcpId,
      seq: 1,
      iv: 'AAAAAAAAAAAAAAAA',
      ciphertext: 'AAAA',
    };
    ext.send(JSON.stringify(extToPeerFrame));

    const delivered = await Promise.race([
      bGotFrame,
      new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 500)),
    ]);
    expect(delivered).toBe(true);

    ext.close();
    peerB.close();
  });

  it('refuses a second extension connection', async () => {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);

    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });

    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: 3,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AAAA',
    };

    const a = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => a.once('open', () => r()));
    a.send(JSON.stringify(extHello));
    await new Promise((r) => setTimeout(r, 50));  // let host process

    const b = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => b.once('open', () => r()));
    b.send(JSON.stringify(extHello));
    const bClosed = await new Promise<boolean>((resolve) => {
      b.once('close', () => resolve(true));
      setTimeout(() => resolve(false), 500);
    });
    expect(bClosed).toBe(true);

    a.close();
  });
});
