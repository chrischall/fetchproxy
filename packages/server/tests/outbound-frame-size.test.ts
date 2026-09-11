import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ecdhX25519,
  generateX25519,
  hkdfSha256,
  openEncryptedFrame,
  sealedFrameWireBytes,
  validateFrame,
  HKDF_SESSION_INFO,
  MAX_FRAME_BYTES,
  type EncryptedFrame,
  type InnerFrame,
  type ReadyFrame,
} from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { connectMockExtension } from './helpers/mock-extension.js';
import { listenEphemeral, loopbackWss } from './helpers/ephemeral-port.js';
import type { ExtensionPin, ExtensionTrustPort } from '../src/extension-trust.js';

/**
 * The MCP side caps the frame it SENDS, the way the extension caps the frame
 * it sends — and for the same reason, which the outbound direction was left
 * out of.
 *
 * `ws` answers a payload over its `maxPayload` by CLOSING the socket with
 * 1009. The host's socket to the extension is the one every MCP on the
 * concentrator shares, and a peer's is its only link to the bridge, so an
 * oversize request leaving this end would report "that one call was too big"
 * by taking the bridge down. It is now a per-request throw: the caller's own
 * `await` fails, the socket is untouched, and the seq is not spent.
 */

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

/** A fetch request whose wire form lands `over` bytes past the cap. */
function requestOfWireSize(mcpId: string, over: number): InnerFrame {
  const probe: InnerFrame = {
    type: 'request',
    id: 7,
    op: 'fetch',
    init: {
      url: 'https://opentable.com/x',
      method: 'POST',
      body: '',
      tabUrl: 'https://opentable.com/',
    },
  };
  const overhead = sealedFrameWireBytes(mcpId, Number.MAX_SAFE_INTEGER, probe);
  // ASCII, so one character is one plaintext byte and four base64 characters
  // cover three of them.
  const bodyBytes = Math.ceil(((MAX_FRAME_BYTES + over - overhead) * 3) / 4);
  return {
    type: 'request',
    id: 7,
    op: 'fetch',
    init: {
      url: 'https://opentable.com/x',
      method: 'POST',
      body: 'x'.repeat(bodyBytes),
      tabUrl: 'https://opentable.com/',
    },
  };
}

/**
 * A case that actually SEALS a frame at the cap moves ~42 MiB through
 * JSON.stringify, AES-GCM and base64. That is 1-2 s of CPU on its own and
 * several times that with the rest of the suite's 129 workers competing for
 * the machine, where vitest's default 5 s budget — sized for a test that is
 * WAITING, not one that is WORKING — turns a correct test into a flake.
 * This case was measured at 5837 ms under the full suite against that 5 s
 * default, so it carries a budget of its own rather than the whole suite
 * being given one — a 5 s test everywhere else still means something is
 * wrong, and that is worth keeping.
 */
const CAP_SIZED_TIMEOUT_MS = 30_000;

describe('the MCP side caps the frame it sends', () => {
  let host: HostHandle | null = null;
  let peer: InternalPeerHandle | null = null;
  let wss: WebSocketServer | null = null;

  afterEach(async () => {
    vi.restoreAllMocks();
    if (host) await host.close();
    host = null;
    if (peer) peer.close();
    peer = null;
    if (wss) {
      await new Promise<void>((r) => wss!.close(() => r()));
      wss = null;
    }
  });

  it('host: an oversize frame fails the call and leaves the shared socket up', async () => {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-out-size-host-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
    const mcpId = 'opentable-mcp:0.9.1:abc1234567890def';

    host = await startHost({
      httpServer: el.server,
      ownIdentity: identity,
      ownMcpId: mcpId,
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });

    const ext = await connectMockExtension(port);
    const sessionKey = await ext.completeHandshake(mcpId);
    await vi.waitFor(() => expect(host!.sessionLinked()).toBe(true));

    const got: EncryptedFrame[] = [];
    ext.ws.on('message', (d) => {
      const f = validateFrame(JSON.parse(d.toString()));
      if (f.type === 'frame') got.push(f);
    });

    await expect(host.sendOwnInner(requestOfWireSize(mcpId, 1024))).rejects.toThrow(
      String(MAX_FRAME_BYTES),
    );

    // Nothing went out, the socket every MCP on this concentrator shares is
    // still up — and the refused frame spent no seq, so the next call is 1.
    expect(got).toHaveLength(0);
    expect(host.sessionLinked()).toBe(true);
    expect(ext.ws.readyState).toBe(WebSocket.OPEN);

    await host.sendOwnInner({ type: 'ping' });
    await vi.waitFor(() => expect(got).toHaveLength(1));
    expect(got[0]!.seq).toBe(1);
    expect((await openEncryptedFrame(sessionKey, got[0]!)).type).toBe('ping');
    ext.close();
  });

  it('peer: an oversize frame fails the call and leaves the link up', async () => {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-out-size-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
    const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';

    wss = loopbackWss();
    const port = await listenEphemeral(wss);

    let sessionKey: Uint8Array | null = null;
    const got: EncryptedFrame[] = [];
    const enc = new TextEncoder();

    wss.on('connection', (ws: WebSocket) => {
      ws.on('message', async (data) => {
        const frame = validateFrame(JSON.parse(data.toString()));
        if (frame.type === 'frame') {
          got.push(frame);
          return;
        }
        if (frame.type !== 'hello' || frame.role !== 'server') return;
        const identityX25519Pub = new Uint8Array(Buffer.from(frame.identityX25519Pub, 'base64'));
        const peerNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));
        const ephemeral = await generateX25519();
        const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
        sessionKey = await hkdfSha256(shared, peerNonce, enc.encode(HKDF_SESSION_INFO), 32);
        const ready: ReadyFrame = {
          type: 'ready',
          mcpId: frame.mcpId,
          extensionSessionPub: Buffer.from(ephemeral.publicKey).toString('base64'),
          sessionSig: Buffer.from('placeholder-sig').toString('base64'),
        };
        ws.send(JSON.stringify(ready));
      });
    });

    peer = await startPeer({
      host: '127.0.0.1',
      port,
      identity,
      mcpId,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
    });

    await expect(peer.sendInner(requestOfWireSize(mcpId, 1024))).rejects.toThrow(
      String(MAX_FRAME_BYTES),
    );
    expect(got).toHaveLength(0);
    expect(peer.ws.readyState).toBe(WebSocket.OPEN);

    await peer.sendInner({ type: 'ping' });
    await vi.waitFor(() => expect(got).toHaveLength(1));
    expect(got[0]!.seq).toBe(1);
    expect(sessionKey).not.toBeNull();
    expect((await openEncryptedFrame(sessionKey!, got[0]!)).type).toBe('ping');
  });

  it(
    'a frame one byte under the cap still goes out',
    async () => {
      // The producer allows EXACTLY the cap; the refusal must not creep down
      // onto a frame the receiver would have taken.
      const el = await electRole({ host: '127.0.0.1', port: 0 });
      if (el.role !== 'host') throw new Error('expected host');
      const port = (el.server.address() as AddressInfo).port;
      const idDir = mkdtempSync(join(tmpdir(), 'fp-out-size-edge-'));
      const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
      const mcpId = 'opentable-mcp:0.9.1:abc1234567890def';

      host = await startHost({
        httpServer: el.server,
        ownIdentity: identity,
        ownMcpId: mcpId,
        ownServerName: 'opentable-mcp',
        ownVersion: '0.9.1',
        ownDomains: ['opentable.com'],
        extensionTrust: blankTrust(),
      });

      const ext = await connectMockExtension(port);
      await ext.completeHandshake(mcpId);
      await vi.waitFor(() => expect(host!.sessionLinked()).toBe(true));

      const got: EncryptedFrame[] = [];
      ext.ws.on('message', (d) => {
        const f = validateFrame(JSON.parse(d.toString()));
        if (f.type === 'frame') got.push(f);
      });

      const fits = requestOfWireSize(mcpId, -1024);
      expect(sealedFrameWireBytes(mcpId, Number.MAX_SAFE_INTEGER, fits)).toBeLessThanOrEqual(
        MAX_FRAME_BYTES,
      );
      await host.sendOwnInner(fits);
      // Same reasoning as the case's own timeout: the extension end parses and
      // validates ~56 MiB of JSON before this resolves.
      await vi.waitFor(() => expect(got).toHaveLength(1), { timeout: CAP_SIZED_TIMEOUT_MS });
      ext.close();
    },
    CAP_SIZED_TIMEOUT_MS,
  );
});
