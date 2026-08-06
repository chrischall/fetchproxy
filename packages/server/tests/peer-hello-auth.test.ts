import { describe, it, expect, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  type HelloFrameFromExtension,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import type { AddressInfo } from 'node:net';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { buildServerHello } from '../src/build-server-hello.js';
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
    protocolVersion: 3,
    role: 'extension',
    platform: 'chrome',
    extensionId: 'fetchproxy',
    version: '0.4.0',
    identityX25519Pub: 'AAAA',
    identityEd25519Pub: 'AAAA',
    sessionNonce: 'AAAA',
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
    const { idDir, port } = await startTestHost();
    const peerId = await loadOrCreateIdentity('resy-mcp', idDir);
    const peerMcpId = 'resy-mcp:0.0.1:abc1234567890de2';
    const peerHello = await buildServerHello({
      identity: peerId,
      mcpId: peerMcpId,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
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
    const peerHello = await buildServerHello({
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

    const legitHello = await buildServerHello({
      identity: peerId,
      mcpId: peerMcpId,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
    });
    // Attacker signs a hello for the SAME mcpId with its OWN identity. The
    // signature self-verifies (attacker holds its own key) but the identity
    // differs from the mapped slot's.
    const squatHello = await buildServerHello({
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
    const helloA = await buildServerHello({
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
    const helloB = await buildServerHello({
      identity: peerId,
      mcpId: peerMcpId,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domains: ['resy.com'],
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
