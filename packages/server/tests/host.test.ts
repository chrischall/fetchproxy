import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateFrame,
  pairTranscript,
  ed25519Verify,
  concatBytes,
  fromB64,
  toB64,
  generateX25519,
  helloSignaturePayload,
  openEncryptedFrame,
  type EncryptedFrame,
  type HelloFrameFromExtension,
} from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { buildTestPeerHello } from './helpers/peer-hello.js';
import type { ExtensionPin, ExtensionTrustPort } from '../src/extension-trust.js';
import { connectMockExtension, newExtensionIdentity } from './helpers/mock-extension.js';

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
      protocolVersion: 4,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
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
        await buildTestPeerHello({
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
        await buildTestPeerHello({
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
        protocolVersion: 4,
        role: 'extension',
        platform: 'chrome',
        extensionId: 'fetchproxy',
        version: '0.4.0',
        identityX25519Pub: 'AAAA',
        identityEd25519Pub: 'AAAA',
        sessionNonce: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
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

  // Same gate as the sibling frame above, one hop further along. #303 shipped
  // the extension-side gate and forgot this one — an ungated relay would have
  // an older peer refuse the type in its validator and close the socket,
  // turning a diagnosable refusal into a dropped connection. That is the exact
  // failure the gate exists to prevent.
  it('relays hello-rejected only to peers that accept it (2.6.0)', async () => {
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

    const newPeer = new WebSocket(`ws://127.0.0.1:${port}`);
    await open(newPeer);
    const newPeerSeen = framesOf(newPeer);
    newPeer.send(
      JSON.stringify(
        await buildTestPeerHello({
          identity: newPeerId,
          mcpId: 'resy-mcp:0.0.1:abc1234567890de2',
          serverName: 'resy-mcp',
          version: '0.0.1',
          domains: ['resy.com'],
          accepts: ['hello-rejected'],
        }),
      ),
    );
    const oldPeer = new WebSocket(`ws://127.0.0.1:${port}`);
    await open(oldPeer);
    const oldPeerSeen = framesOf(oldPeer);
    oldPeer.send(
      JSON.stringify(
        await buildTestPeerHello({
          identity: oldPeerId,
          mcpId: 'tock-mcp:0.0.1:abc1234567890de3',
          serverName: 'tock-mcp',
          version: '0.0.1',
          domains: ['exploretock.com'],
        }),
      ),
    );

    const ext = new WebSocket(`ws://127.0.0.1:${port}`);
    await open(ext);
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
      } satisfies HelloFrameFromExtension),
    );
    await vi.waitFor(() => expect(newPeerSeen).toContain('hello'));
    await vi.waitFor(() => expect(oldPeerSeen).toContain('hello'));

    const reject = (mcpId: string): string =>
      JSON.stringify({ type: 'hello-rejected', mcpId, reason: 'sessionSig invalid' });
    ext.send(reject('resy-mcp:0.0.1:abc1234567890de2'));
    ext.send(reject('tock-mcp:0.0.1:abc1234567890de3'));

    await vi.waitFor(() => expect(newPeerSeen).toContain('hello-rejected'));
    // A beat, then the peer that never advertised it must still not have one.
    await new Promise((r) => setTimeout(r, 50));
    expect(oldPeerSeen).not.toContain('hello-rejected');
    // …and its socket is still up, which is the whole point of gating.
    expect(oldPeer.readyState).toBe(WebSocket.OPEN);

    newPeer.close();
    oldPeer.close();
  });

  it('forgets an unapproved pair code when the extension closes (#283)', async () => {
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
    // 3.0.0 (protocol 4): the pair code commits to the hello this host mints
    // for THIS extension session, so the test has to read that hello rather
    // than derive from the two identity pubs alone.
    const serverHellos: { sessionNonce: string; sessionPub: string }[] = [];
    ws.on('message', (d) => {
      const f = JSON.parse(d.toString()) as { type?: string; role?: string } & Record<string, string>;
      if (f.type === 'hello' && f.role === 'server') {
        serverHellos.push({ sessionNonce: f.sessionNonce!, sessionPub: f.sessionPub! });
      }
    });
    const extNonceB64 = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=';
    ws.send(
      JSON.stringify({
        type: 'hello',
        protocolVersion: 4,
        role: 'extension',
        platform: 'chrome',
        extensionId: 'fetchproxy',
        version: '0.4.0',
        identityX25519Pub: 'AAAA',
        identityEd25519Pub: 'AAAA',
        sessionNonce: extNonceB64,
      } satisfies HelloFrameFromExtension),
    );
    await vi.waitFor(() => expect(host!.extensionConnected()).toBe(true));
    await vi.waitFor(() => expect(serverHellos).toHaveLength(1));
    // M1: the host judges the frame's code against the one it derives itself,
    // so a code the extension made up would be an alarm and a closed socket
    // rather than a pending pair.
    const b = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64'));
    const code = await pairTranscript(
      id.x25519Pub,
      b('AAAA'),
      b(serverHellos[0]!.sessionNonce),
      b(extNonceB64),
      b(serverHellos[0]!.sessionPub),
    );
    ws.send(
      JSON.stringify({
        type: 'pair-pending',
        mcpId: 'opentable-mcp:0.9.1:abc1234567890def',
        pairCode: code,
      }),
    );
    await vi.waitFor(() => expect(host!.pendingPairCode()).toBe(code));

    ws.close();
    await vi.waitFor(() => expect(host!.extensionConnected()).toBe(false));
    // The popup that showed the code is gone with the browser; reporting
    // "approve <code>" now would send the user to a prompt that no longer
    // exists, when the remedy is to reopen the browser.
    expect(host.pendingPairCode()).toBeNull();
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
      protocolVersion: 4,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
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
      protocolVersion: 4,
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
    const helloPromise = new Promise<{ sessionNonce: string; sessionPub: string }>(
      (resolve) => {
        ws.on('message', (data) => {
          try {
            const parsed = vf(JSON.parse(data.toString()));
            if (parsed.type === 'hello' && parsed.role === 'server') {
              resolve({ sessionNonce: parsed.sessionNonce, sessionPub: parsed.sessionPub });
            }
          } catch {
            // ignore
          }
        });
      },
    );
    ws.send(JSON.stringify(extHello));
    const { sessionNonce: mcpNonceB64, sessionPub: mcpSessionPubB64 } = await helloPromise;
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
    // 3.0.0: the ready has to name the MCP ephemeral it answers, or §1a's
    // Rule C DISCARDS it before any crypto runs — which would be the correct
    // v4 behaviour and the wrong test.
    const mcpSessionPub = new Uint8Array(Buffer.from(mcpSessionPubB64, 'base64'));
    const sigPayload = readySignaturePayload(
      mcpNonce,
      extSessionNonce,
      shortPub,
      mcpSessionPub,
    );
    const sig = await ed25519Sign(extEd.privateKey, sigPayload);
    const badReady = {
      type: 'ready',
      mcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      extensionSessionPub: Buffer.from(shortPub).toString('base64'),
      mcpSessionPub: mcpSessionPubB64,
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

  it('withholds a registration hello and forwards the re-hello that answers the live session (§1a Rule B, both directions)', async () => {
    // Under v3 this test asserted that a peer's hello reaches an
    // already-connected extension verbatim. Under v4 that is exactly the
    // hello that must NOT be forwarded: a registration hello names the
    // peer's BOOTSTRAP ephemeral, which no `ready` may ever be derived
    // against. What makes the multi-MCP path still work is the mirror —
    // the peer is handed the cached extension hello in answer to it, mints,
    // and re-hellos, and THAT hello is forwarded.
    //
    // Two assertions on one gate, one per direction, so deleting it either
    // way fails.
    //
    // A test that only asserted the withholding would pass against a host
    // that forwards nothing at all, and the extension would then never hear
    // about the peer; a test that only asserted the forwarding would pass
    // against the un-gated v3 code.
    //
    // Both hellos leave on ONE socket, which is also what pins the overwrite
    // the dial path now rests on: a same-socket, same-identity re-hello must
    // REPLACE the slot rather than be refused as a squatter, because it is
    // the only route a peer's session hello takes to the extension. So the
    // forwarding assertion is on the re-hello's OWN ephemeral rather than on
    // its mcpId — a host that answered by re-sending the slot's cached
    // registration frame would satisfy an mcpId-only check while handing the
    // extension the bootstrap pub again — and the socket is asserted open.
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
      protocolVersion: 4,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
    };
    ext.send(JSON.stringify(extHello));

    // Capture every server-hello the extension sees, so we can prove which
    // of the peer's two hellos reached it — the whole frame, because which
    // ephemeral it names is the point.
    const seenServerHellos: Record<string, unknown>[] = [];
    const seenHellos: string[] = [];
    ext.on('message', (data: Buffer) => {
      const parsed = JSON.parse(data.toString());
      if (parsed.type === 'hello' && parsed.role === 'server') {
        seenServerHellos.push(parsed as Record<string, unknown>);
        seenHellos.push(parsed.mcpId);
      }
    });

    // Wait briefly for extension's hello to be processed.
    await new Promise((r) => setTimeout(r, 50));
    expect(seenHellos).toContain('opentable-mcp:0.9.1:abc1234567890de1');

    // The peer dials in and registers. Its hello answers NO extension
    // session, which is what the mirror gate keys on.
    const peer = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => peer.once('open', () => r()));
    const relayedToPeer: Record<string, unknown>[] = [];
    peer.on('message', (data: Buffer) => {
      relayedToPeer.push(JSON.parse(data.toString()));
    });
    let peerClosed = false;
    peer.once('close', () => {
      peerClosed = true;
    });
    const registration = await buildTestPeerHello({
      identity: peerId,
      mcpId: 'resy-mcp:0.0.1:abc1234567890de2',
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
    });
    peer.send(JSON.stringify(registration));
    await new Promise((r) => setTimeout(r, 60));
    // Direction 1: withheld from the extension, and the cached extension
    // hello came back — which is the peer's Rule A trigger and the reason
    // this send is gated rather than deleted.
    expect(seenHellos).not.toContain('resy-mcp:0.0.1:abc1234567890de2');
    expect(
      relayedToPeer.filter((f) => f.type === 'hello' && f.role === 'extension').length,
    ).toBe(1);

    // Direction 2: the re-hello the peer now mints echoes the live extension
    // nonce, so it IS forwarded — and draws NOTHING back, which is what
    // stops the exchange from looping.
    const reHello = await buildTestPeerHello({
      identity: peerId,
      mcpId: 'resy-mcp:0.0.1:abc1234567890de2',
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
      answersExtNonce: extHello.sessionNonce,
    });
    expect(reHello.sessionPub).not.toBe(registration.sessionPub);
    peer.send(JSON.stringify(reHello));
    await new Promise((r) => setTimeout(r, 60));
    const forwarded = seenServerHellos.filter(
      (f) => f.mcpId === 'resy-mcp:0.0.1:abc1234567890de2',
    );
    expect(forwarded).toHaveLength(1);
    // The slot was REPLACED, not refused: what the extension holds is the
    // re-hello's session ephemeral, and the socket that sent it is still up.
    expect(forwarded[0].sessionPub).toBe(reHello.sessionPub);
    expect(peerClosed).toBe(false);
    expect(
      relayedToPeer.filter((f) => f.type === 'hello' && f.role === 'extension').length,
    ).toBe(1);

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
      protocolVersion: 4,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
    };
    ext.send(JSON.stringify(extHello));
    await new Promise((r) => setTimeout(r, 30));

    const peerMcpId = 'resy-mcp:0.0.1:abc1234567890de2';
    const peerHello = await buildTestPeerHello({
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
      protocolVersion: 4,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
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

/**
 * Task 2.1 — the host's per-connection session ephemeral (protocol v4, §1a).
 *
 * These are the assertions the compiler cannot make. Adding `sessionPub` and
 * `answersExtNonce` to the hello satisfies `tsc` whether or not the signature
 * covers them and whether or not the HKDF salt is the transcript, so each of
 * those facts is pinned by a test that fails if the call reverts to the v3
 * shape.
 */
describe('host: a session ephemeral per extension connection (v4)', () => {
  let host: HostHandle | null = null;
  const MCP_ID = 'opentable-mcp:0.9.1:abc1234567890de1';

  afterEach(async () => {
    if (host) await host.close();
    host = null;
  });

  async function startTestHost(
    extra: Partial<Parameters<typeof startHost>[0]> = {},
  ): Promise<number> {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-v4-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);
    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: MCP_ID,
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
      ...extra,
    });
    return port;
  }

  /** Whether `p` is still pending after the event loop has had a real turn. */
  async function stillPending(p: Promise<unknown>): Promise<boolean> {
    const marker = Symbol('pending');
    const settled = await Promise.race([
      p.then(
        () => 'resolved',
        () => 'rejected',
      ),
      new Promise((r) => setTimeout(() => r(marker), 150)),
    ]);
    return settled === marker;
  }

  it('mints a fresh ephemeral per connection and echoes the nonce it answers', async () => {
    const port = await startTestHost();
    const browser = await newExtensionIdentity();

    const ext1 = await connectMockExtension(port, browser);
    const hello1 = await ext1.waitForServerHello(MCP_ID);
    // The echo is what Rule B's gate reads, and it is inside the signed
    // payload — so a hello that named the wrong extension session could not
    // be re-pointed by a relay.
    expect(hello1.answersExtNonce).toBe(ext1.hello.sessionNonce);
    const key1 = await ext1.completeHandshake(MCP_ID);

    // The key the extension derived against `sessionPub` is the key the host
    // holds: if the host still salted with its own nonce, or still put its
    // identity key in the ECDH, this frame would not open.
    const sealed1 = new Promise<Record<string, unknown>>((resolve) => {
      ext1.ws.on('message', (data: Buffer) => {
        const parsed = JSON.parse(data.toString());
        if (parsed.type === 'frame' && parsed.mcpId === MCP_ID) resolve(parsed);
      });
    });
    void host!.sendOwnInner({ type: 'ping' });
    const frame1 = await sealed1;
    expect(
      (await openEncryptedFrame(key1, frame1 as unknown as EncryptedFrame, 's2e')).type,
    ).toBe('ping');

    ext1.close();
    await ext1.closed();
    await new Promise((r) => setTimeout(r, 50));

    const ext2 = await connectMockExtension(port, browser);
    const hello2 = await ext2.waitForServerHello(MCP_ID);
    // A per-PROCESS ephemeral would bound forward secrecy at the process
    // lifetime, which is exactly what v4 refuses to call forward secrecy.
    expect(toB64(hello2.sessionPub)).not.toBe(toB64(hello1.sessionPub));
    expect(toB64(hello2.sessionNonce)).not.toBe(toB64(hello1.sessionNonce));
    expect(hello2.answersExtNonce).toBe(ext2.hello.sessionNonce);
    expect(hello2.answersExtNonce).not.toBe(ext1.hello.sessionNonce);

    const key2 = await ext2.completeHandshake(MCP_ID);
    expect(toB64(key2)).not.toBe(toB64(key1));
    const sealed2 = new Promise<Record<string, unknown>>((resolve) => {
      ext2.ws.on('message', (data: Buffer) => {
        const parsed = JSON.parse(data.toString());
        if (parsed.type === 'frame' && parsed.mcpId === MCP_ID) resolve(parsed);
      });
    });
    void host!.sendOwnInner({ type: 'ping' });
    const frame2 = await sealed2;
    expect(
      (await openEncryptedFrame(key2, frame2 as unknown as EncryptedFrame, 's2e')).type,
    ).toBe('ping');
    ext2.close();
  });

  it('signs the hello over the ephemeral it mints', async () => {
    // The producer half of hazard (a): the host must build its `sessionSig`
    // through `helloSignaturePayload`, not the v3 `mcpId || sessionNonce`
    // concatenation. Verified here the way the extension verifies it.
    const port = await startTestHost();
    const ext = await connectMockExtension(port);
    const seen = await ext.waitForServerHello(MCP_ID);
    const ok = await ed25519Verify(
      fromB64(seen.frame.identityEd25519Pub),
      helloSignaturePayload(
        MCP_ID,
        seen.sessionNonce,
        seen.sessionPub,
        fromB64(seen.answersExtNonce),
      ),
      fromB64(seen.frame.sessionSig),
    );
    expect(ok).toBe(true);
    // And the v3 payload must NOT verify, or the widening is decorative.
    const v3 = await ed25519Verify(
      fromB64(seen.frame.identityEd25519Pub),
      concatBytes(new TextEncoder().encode(MCP_ID), seen.sessionNonce),
      fromB64(seen.frame.sessionSig),
    );
    expect(v3).toBe(false);
    ext.close();
  });

  it('refuses a ready whose signature does not cover the MCP ephemeral', async () => {
    const port = await startTestHost();
    const ext = await connectMockExtension(port);
    const seen = await ext.waitForServerHello(MCP_ID);
    await ext.answerReady(seen, { omitMcpSessionPubFromSignature: true });
    const closed = await ext.closed();
    expect(closed.code).toBe(1008);
    expect(closed.reason).toContain('signature');
    expect(host!.sessionLinked()).toBe(false);
  });

  it('zeroes the session private half when the extension socket closes', async () => {
    // Asserted through an INJECTED generator rather than an accessor that
    // exists only for the test: the test holds the very buffer the host was
    // handed, so "no readable copy" is a property of that buffer.
    const minted: { publicKey: Uint8Array; privateKey: Uint8Array }[] = [];
    const port = await startTestHost({
      generateSessionKeypair: async () => {
        const kp = await generateX25519();
        minted.push(kp);
        return kp;
      },
    });
    const ext = await connectMockExtension(port);
    await ext.completeHandshake(MCP_ID);
    expect(minted.length).toBe(1);
    expect(minted[0]!.privateKey.some((b) => b !== 0)).toBe(true);

    ext.close();
    await ext.closed();
    await new Promise((r) => setTimeout(r, 50));
    // Forward secrecy is the property that an identity holder cannot open a
    // PAST session; it is false if the process keeps every ephemeral private
    // key it ever minted.
    expect(minted[0]!.privateKey.every((b) => b === 0)).toBe(true);
  });

  it('discards a ready for a superseded ephemeral, and still refuses a bad signature for the current one (Rule C)', async () => {
    // The two outcomes must be asserted APART. A test that only says "the
    // stale one does not establish a session" passes against v3's 1008 and
    // so proves nothing; the point of Rule C is that a stale `ready` costs
    // nothing and a forged one still closes.
    const port = await startTestHost();
    const browser = await newExtensionIdentity();

    const ext1 = await connectMockExtension(port, browser);
    const staleHello = await ext1.waitForServerHello(MCP_ID);
    ext1.close();
    await ext1.closed();
    await new Promise((r) => setTimeout(r, 50));

    const ext2 = await connectMockExtension(port, browser);
    const liveHello = await ext2.waitForServerHello(MCP_ID);
    // A `ready` for the hello E1 was given: genuinely signed, genuinely from
    // the pinned browser, and naming an ephemeral this host no longer holds.
    const sending = host!.sendOwnInner({ type: 'ping' });
    await ext2.answerReady(staleHello);
    await new Promise((r) => setTimeout(r, 50));
    expect(ext2.ws.readyState).toBe(WebSocket.OPEN);
    expect(host!.sessionLinked()).toBe(false);
    // Nothing was rejected: the pending send is still waiting, not failed.
    expect(await stillPending(sending)).toBe(true);

    // And a genuine ready arriving afterwards still establishes the session.
    const key = await ext2.answerReady(liveHello);
    const frame = await new Promise<Record<string, unknown>>((resolve) => {
      ext2.ws.on('message', (data: Buffer) => {
        const parsed = JSON.parse(data.toString());
        if (parsed.type === 'frame' && parsed.mcpId === MCP_ID) resolve(parsed);
      });
    });
    await sending;
    expect(
      (await openEncryptedFrame(key, frame as unknown as EncryptedFrame, 's2e')).type,
    ).toBe('ping');
    expect(host!.sessionLinked()).toBe(true);

    // The other outcome, on the same host: a ready naming the CURRENT
    // ephemeral whose signature does not verify still closes 1008.
    await ext2.answerReady(liveHello, { forgeSignature: true });
    const closed = await ext2.closed();
    expect(closed.code).toBe(1008);
  });

  it('lets the newer mint win when an older one resolves late (Rule D)', async () => {
    // Two mints INSIDE one process, which neither test above can reach: they
    // drive one at a time. The load-bearing assertion is that E2's session
    // OPENS — without Rule D, mint 1 lands last, Rule C discards E2's
    // legitimate `ready` and the failure is a hang rather than an error.
    const minted: { publicKey: Uint8Array; privateKey: Uint8Array }[] = [];
    let releaseFirst: (() => void) | null = null;
    const firstHeld = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let calls = 0;
    const port = await startTestHost({
      generateSessionKeypair: async () => {
        const kp = await generateX25519();
        minted.push(kp);
        if (++calls === 1) await firstHeld;
        return kp;
      },
    });
    const browser = await newExtensionIdentity();

    const ext1 = await connectMockExtension(port, browser);
    // Give the host time to reach the held mint.
    await new Promise((r) => setTimeout(r, 50));
    expect(minted.length).toBe(1);
    ext1.close();
    await ext1.closed();
    await new Promise((r) => setTimeout(r, 50));

    const ext2 = await connectMockExtension(port, browser);
    const liveHello = await ext2.waitForServerHello(MCP_ID);
    expect(minted.length).toBe(2);

    // Release E1's mint. It must zero its own half, install nothing and send
    // nothing — E2's session is the one that exists.
    releaseFirst!();
    await new Promise((r) => setTimeout(r, 100));
    expect(minted[0]!.privateKey.every((b) => b === 0)).toBe(true);
    expect(ext2.serverHellosFor(MCP_ID).length).toBe(1);
    expect(ext2.framesFor(MCP_ID).length).toBe(1);

    const key = await ext2.answerReady(liveHello);
    const frame = new Promise<Record<string, unknown>>((resolve) => {
      ext2.ws.on('message', (data: Buffer) => {
        const parsed = JSON.parse(data.toString());
        if (parsed.type === 'frame' && parsed.mcpId === MCP_ID) resolve(parsed);
      });
    });
    void host!.sendOwnInner({ type: 'ping' });
    expect(
      (await openEncryptedFrame(key, (await frame) as unknown as EncryptedFrame, 's2e')).type,
    ).toBe('ping');
    expect(host!.sessionLinked()).toBe(true);
    ext2.close();
  });
});

/**
 * Task 4.2 — a v4 MCP refuses a v3 extension, out loud.
 *
 * Measured on this branch before the fix: a v3 extension meeting a v4 MCP did
 * not get refused, it HUNG. `validateFrame` threw, the host closed
 * `1002 'protocol error'` — three words that say nothing about a version — and
 * left `ownSessionReady` pending, so the next `sendOwnInner` waited out
 * `SESSION_READY_TIMEOUT_MS` (30 s) and then blamed a signed-out session or a
 * changed scope. These tests are about the two halves of that: the reason on
 * the wire, and the immediate rejection.
 */
describe('host: a v3 extension is refused at the hello, naming both versions (v4)', () => {
  let host: HostHandle | null = null;
  const MCP_ID = 'opentable-mcp:0.9.1:abc1234567890de2';

  afterEach(async () => {
    if (host) await host.close();
    host = null;
  });

  async function startTestHost(trust: ExtensionTrustPort = blankTrust()): Promise<number> {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-v3-'));
    host = await startHost({
      httpServer: el.server,
      ownIdentity: await loadOrCreateIdentity('opentable-mcp', idDir),
      ownMcpId: MCP_ID,
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: trust,
    });
    return port;
  }

  /** A protocol-3 extension hello: valid v3 bytes, refused by a v4 validator. */
  function v3ExtensionHello(): Record<string, unknown> {
    return {
      type: 'hello',
      protocolVersion: 3,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '2.11.3',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
    };
  }

  async function openSocket(port: number): Promise<{
    ws: WebSocket;
    closed: Promise<{ code: number; reason: string }>;
  }> {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((resolve, reject) => {
      ws.once('open', () => resolve());
      ws.once('error', reject);
    });
    ws.on('error', () => {
      /* expected: the host closes this socket under us */
    });
    const closed = new Promise<{ code: number; reason: string }>((resolve) => {
      ws.once('close', (code: number, reason: Buffer) =>
        resolve({ code, reason: reason.toString() }),
      );
    });
    return { ws, closed };
  }

  /** Whether `p` is still pending after the event loop has had a real turn. */
  async function stillPending(p: Promise<unknown>): Promise<boolean> {
    const marker = Symbol('pending');
    const settled = await Promise.race([
      p.then(
        () => 'resolved',
        () => 'rejected',
      ),
      new Promise((r) => setTimeout(() => r(marker), 150)),
    ]);
    return settled === marker;
  }

  it('closes 1002 with a reason naming BOTH versions', async () => {
    const port = await startTestHost();
    const { ws, closed } = await openSocket(port);
    ws.send(JSON.stringify(v3ExtensionHello()));
    const { code, reason } = await closed;
    // 1002 is the code already there and the right one: RFC 6455's protocol
    // error, which a version mismatch exactly is. 1008 in this file is spent
    // on identity and authorization refusals.
    expect(code).toBe(1002);
    expect(reason).not.toBe('protocol error');
    expect(reason).toContain('4');
    expect(reason).toContain('3');
    expect(reason).toMatch(/protocol version mismatch/);
    // The close reason is capped at 123 bytes by RFC 6455 (and `ws` throws
    // above it), which is why the sentence a person reads is the ERROR's and
    // not this one.
    expect(Buffer.byteLength(reason, 'utf8')).toBeLessThanOrEqual(123);
  });

  it('rejects the pending session IMMEDIATELY, with the version and the remedy', async () => {
    const port = await startTestHost();
    // Someone is already waiting — this is the `request()` that would have
    // hung for thirty seconds.
    const pending = host!.sendOwnInner({ type: 'ping' });
    const waiting = pending.catch((e: unknown) => e);
    expect(await stillPending(waiting.then(() => undefined))).toBe(true);

    const started = Date.now();
    const { ws } = await openSocket(port);
    ws.send(JSON.stringify(v3ExtensionHello()));

    // Promptness asserted as a RACE this test owns, rather than as an elapsed
    // number: `SESSION_READY_TIMEOUT_MS` is 30_000, so a bare `await` on the
    // un-refused code settles at vitest's own 5 s wall and any elapsed
    // assertion below it reads that wall rather than this refusal. Racing a
    // timer of our own means the failure is the assertion, and the 5 s is the
    // threshold the test chose. The generous per-test timeout is what keeps
    // vitest from becoming the instrument again.
    const TIMED_OUT = Symbol('timed out');
    const settled = await Promise.race([
      waiting,
      new Promise((r) => setTimeout(() => r(TIMED_OUT), 5_000)),
    ]);
    expect(settled).not.toBe(TIMED_OUT);
    const err = settled as Error;
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(err.name).toBe('FetchproxyProtocolVersionError');
    expect(err.message).toBe(
      'protocol version mismatch: this MCP speaks fetchproxy protocol 4, the attached ' +
        'browser extension speaks 3 — update Transporter (the fetchproxy extension) to ' +
        '3.0.0 or later',
    );
    ws.close();
  }, 20_000);

  it('fails a request issued AFTERWARDS with the same message', async () => {
    const port = await startTestHost();
    const { ws, closed } = await openSocket(port);
    ws.send(JSON.stringify(v3ExtensionHello()));
    await closed;

    // The refusal outlives the socket it was made on: the extension is v3 and
    // reconnecting on its backoff, so every call until it is upgraded must say
    // so rather than wait out the timeout afresh.
    const started = Date.now();
    await expect(host!.sendOwnInner({ type: 'ping' })).rejects.toThrow(
      /protocol version mismatch: this MCP speaks fetchproxy protocol 4/,
    );
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it('recovers when a v4 extension attaches, so an upgrade does not need a restart', async () => {
    const port = await startTestHost();
    const { ws, closed } = await openSocket(port);
    ws.send(JSON.stringify(v3ExtensionHello()));
    await closed;
    await expect(host!.sendOwnInner({ type: 'ping' })).rejects.toThrow(/version mismatch/);

    const ext = await connectMockExtension(port);
    await ext.completeHandshake(MCP_ID);
    await host!.sendOwnInner({ type: 'ping' });
    expect(host!.sessionLinked()).toBe(true);
    ext.close();
  });

  it('never fails a LIVE v4 session — the refusal is for a host with nothing attached', async () => {
    // The regression this pins: the refusal is made in the `validateFrame`
    // catch, which runs BEFORE the `extension already connected` guard, so a
    // v3 hello arrives on any socket at any time — including while a v4
    // extension holds the slot with a derived session. Resetting and
    // rejecting `ownSessionReady` there destroys a WORKING bridge and wedges
    // it permanently: nothing clears the refusal but an accepted extension
    // hello, the attached extension will not send another, and a new socket
    // is refused 1008 'extension already connected'. Meanwhile
    // `sessionLinked()` and `extensionConnected()` both still report true, so
    // the bridge looks healthy while every call fails with a version sentence
    // about a version nothing attached speaks.
    //
    // Reachability is the rollout itself, not an adversary: an old Transporter
    // in a second Chrome profile dials the same localhost port and reconnects
    // on its backoff every few seconds.
    const port = await startTestHost();
    const ext = await connectMockExtension(port);
    await ext.completeHandshake(MCP_ID);
    await host!.sendOwnInner({ type: 'ping' });

    const { ws, closed } = await openSocket(port);
    ws.send(JSON.stringify(v3ExtensionHello()));
    // The stranger is still refused, out loud and with both versions...
    const { code, reason } = await closed;
    expect(code).toBe(1002);
    expect(reason).toMatch(/protocol version mismatch/);

    // ...and the session it arrived beside is untouched.
    await host!.sendOwnInner({ type: 'ping' });
    expect(host!.sessionLinked()).toBe(true);
    expect(host!.extensionConnected()).toBe(true);
    ext.close();
  });

  it('never fails a v4 extension still being VETTED, either', async () => {
    // The same regression one window earlier, and the reason "is an extension
    // attached?" is not one variable: between a v4 hello arriving and the slot
    // being taken there is an awaited pin read, during which `extensionWs` is
    // still null and only `extensionClaim` says a better connection is in
    // flight. A v3 hello landing in that window must not reject the promise
    // the handshake about to finish will resolve.
    let releasePin: () => void = () => {};
    const held = new Promise<void>((r) => {
      releasePin = r;
    });
    let firstRead = true;
    const slowTrust: ExtensionTrustPort = {
      allowNew: false,
      read: async () => {
        if (firstRead) {
          firstRead = false;
          await held;
        }
        return null;
      },
      write: async () => {},
    };

    const port = await startTestHost(slowTrust);
    // The caller who is already waiting. Under the bug this is the promise the
    // refusal reaches: it is the one the arriving v4 extension is about to
    // resolve, and rejecting it hands a version sentence to a request the
    // working bridge was seconds away from serving.
    const pending = host!.sendOwnInner({ type: 'ping' });
    const waiting = pending.then(
      () => 'sent',
      (e: unknown) => (e as Error).message,
    );

    const ext = await connectMockExtension(port);
    const handshake = ext.completeHandshake(MCP_ID);
    // The claim is taken synchronously with the hello; the pin read is now
    // parked, so the host is mid-vetting.
    await new Promise((r) => setTimeout(r, 50));

    const { ws, closed } = await openSocket(port);
    ws.send(JSON.stringify(v3ExtensionHello()));
    const { code, reason } = await closed;
    expect(code).toBe(1002);
    expect(reason).toMatch(/protocol version mismatch/);

    releasePin();
    await handshake;
    expect(await waiting).toBe('sent');
    await host!.sendOwnInner({ type: 'ping' });
    expect(host!.sessionLinked()).toBe(true);
    ext.close();
  });

  it('never fails a v4 extension that has the SLOT but not yet a session', async () => {
    // The third window, and the reason the predicate names `extensionWs` too:
    // between the hello being accepted and the `ready` deriving the key, the
    // slot is taken and `ownSession` is still null. A v3 hello landing there
    // must not reject the promise the ready is about to resolve.
    const port = await startTestHost();
    const pending = host!.sendOwnInner({ type: 'ping' });
    const waiting = pending.then(
      () => 'sent',
      (e: unknown) => (e as Error).message,
    );

    const ext = await connectMockExtension(port);
    const seen = await ext.waitForServerHello(MCP_ID);

    const { ws, closed } = await openSocket(port);
    ws.send(JSON.stringify(v3ExtensionHello()));
    const { code, reason } = await closed;
    expect(code).toBe(1002);
    expect(reason).toMatch(/protocol version mismatch/);

    await ext.answerReady(seen);
    expect(await waiting).toBe('sent');
    expect(host!.sessionLinked()).toBe(true);
    ext.close();
  });

  it('leaves a frame malformed for any OTHER reason on the generic path', async () => {
    const port = await startTestHost();
    const pending = host!.sendOwnInner({ type: 'ping' });
    const waiting = pending.catch((e: unknown) => e);

    const { ws, closed } = await openSocket(port);
    // A CURRENT-version hello with a field missing: `validateFrame` refuses it,
    // `peekHelloVersion` reads version 4, and 4 is not a mismatch.
    const broken = v3ExtensionHello();
    broken.protocolVersion = 4;
    delete broken.sessionNonce;
    ws.send(JSON.stringify(broken));

    const { code, reason } = await closed;
    expect(code).toBe(1002);
    expect(reason).toBe('protocol error');
    // ...and the pending session is untouched: the mismatch is the only case
    // that gets the new treatment.
    expect(await stillPending(waiting.then(() => undefined))).toBe(true);
  });

  it('does not fail our own session for a REGISTERED peer whose hello names no mcpId', async () => {
    // The same route as the test below, one step further in: this socket is
    // already a registered peer, so the frame it sends next is a sibling MCP's
    // whatever it says. A hello with no `mcpId` peeks as 'extension' — that is
    // what the peek is FOR, telling a browser's hello from a sibling's — so
    // without judging the socket as well as the frame, a stale v3 sibling
    // could fail the session we hold with the browser by sending one frame.
    const port = await startTestHost();
    const pending = host!.sendOwnInner({ type: 'ping' });
    const waiting = pending.catch((e: unknown) => e);

    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((resolve, reject) => {
      ws.once('open', () => resolve());
      ws.once('error', reject);
    });
    ws.on('error', () => {
      /* expected: the host closes this socket under us */
    });
    const closed = new Promise<{ code: number; reason: string }>((resolve) => {
      ws.once('close', (code: number, reason: Buffer) =>
        resolve({ code, reason: reason.toString() }),
      );
    });
    ws.send(
      JSON.stringify(
        await buildTestPeerHello({
          identity: await loadOrCreateIdentity(
            'resy-mcp',
            mkdtempSync(join(tmpdir(), 'fp-host-v3-peer-')),
          ),
          mcpId: 'resy-mcp:1.0.0:abc1234567890def',
          serverName: 'resy-mcp',
          version: '1.0.0',
          domains: ['resy.com'],
        }),
      ),
    );
    // Registered. Now the v3 frame, shaped like a browser's.
    await new Promise((r) => setTimeout(r, 50));
    ws.send(JSON.stringify(v3ExtensionHello()));

    const { code, reason } = await closed;
    expect(code).toBe(1002);
    expect(reason).toMatch(/protocol version mismatch/);
    expect(await stillPending(waiting.then(() => undefined))).toBe(true);
  });

  it('does not fail our own session for a v3 PEER dialing in', async () => {
    const port = await startTestHost();
    const pending = host!.sendOwnInner({ type: 'ping' });
    const waiting = pending.catch((e: unknown) => e);

    const { ws, closed } = await openSocket(port);
    // A v3 sibling MCP registering on the concentrator. It is refused with a
    // reason of its own — but our session is with the EXTENSION, and a stale
    // sibling must not be able to fail it.
    ws.send(
      JSON.stringify({
        type: 'hello',
        protocolVersion: 3,
        role: 'server',
        mcpId: 'resy-mcp:1.0.0:abc1234567890def',
        serverName: 'resy-mcp',
        version: '1.0.0',
        domains: ['resy.com'],
        capabilities: [],
        identityX25519Pub: 'AAAA',
        identityEd25519Pub: 'AAAA',
        sessionNonce: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=',
        sessionSig: 'AAAA',
        accepts: ['hello-rejected'],
      }),
    );
    const { code, reason } = await closed;
    expect(code).toBe(1002);
    expect(reason).toMatch(/protocol version mismatch/);
    expect(await stillPending(waiting.then(() => undefined))).toBe(true);
  });
});
