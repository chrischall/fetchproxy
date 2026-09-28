import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ACCOUNT_ATTEST_FRAME,
  ACCOUNT_KEY_FRAME,
  type AccountAttestFrame,
  type AccountKeyFrame,
  type HelloFrameFromExtension,
} from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { buildTestPeerHello } from './helpers/peer-hello.js';
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

const b64 = (n: number): string => btoa(String.fromCharCode(...new Uint8Array(n).fill(7)));
const PEER_MCP_ID = 'resy-mcp:0.0.1:abc1234567890de2';

const KEY: AccountKeyFrame = {
  type: ACCOUNT_KEY_FRAME,
  accountId: 'acc_f05c0ebf831e35df687660d1',
  slug: 'chris',
  displayName: 'Chris',
  confirmedBy: 'c***@gmail.com',
  tokenId: 'brt_0123456789abcdef01234567',
  kid: '9f2c41ab7de05613',
  publicKey: b64(32),
  generation: 1,
  bridgedRegistrations: 1,
};

const ATTEST: AccountAttestFrame = {
  type: ACCOUNT_ATTEST_FRAME,
  mcpId: PEER_MCP_ID,
  accountId: 'acc_f05c0ebf831e35df687660d1',
  generation: 1,
  tokenId: 'brt_0123456789abcdef01234567',
  kid: '9f2c41ab7de05613',
  registrationId: 'reg_89abcdef0123456789abcdef',
  slug: 'resy',
  identityHash: 'ab'.repeat(32),
  identityEd25519Pub: b64(32),
  scopeDigest: '0'.repeat(64),
  consent: 'silent',
  notAfter: 1788063212,
  sig: b64(64),
};

/**
 * Account frames are minted by a HOSTED relay (mcp-host) and nobody else. The
 * loopback concentrator is not a relay that may mint them, and must not become
 * a path for one either: a peer MCP that sends one is vouching for itself
 * (mcp-host spec I-3), and one arriving from the extension has no business
 * reaching an MCP. The host has no dispatch branch for either type — this
 * pins that, in both directions, with both ends advertising the types.
 */
describe('host: account-key / account-attest are never relayed on loopback', () => {
  let host: HostHandle | null = null;
  afterEach(async () => {
    if (host) await host.close();
    host = null;
  });

  it('drops them from a peer and from the extension, and keeps both sockets up', async () => {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-acct-'));
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

    const open = (ws: WebSocket) => new Promise<void>((r) => ws.once('open', () => r()));
    const framesOf = (ws: WebSocket): string[] => {
      const seen: string[] = [];
      ws.on('message', (data: Buffer) => seen.push(JSON.parse(data.toString()).type));
      return seen;
    };

    const peer = new WebSocket(`ws://127.0.0.1:${port}`);
    await open(peer);
    const peerSeen = framesOf(peer);
    peer.send(
      JSON.stringify(
        await buildTestPeerHello({
          identity: peerId,
          mcpId: PEER_MCP_ID,
          serverName: 'resy-mcp',
          version: '0.0.1',
          domains: ['resy.com'],
          accepts: ['hello-rejected', ACCOUNT_KEY_FRAME, ACCOUNT_ATTEST_FRAME],
        }),
      ),
    );

    const ext = new WebSocket(`ws://127.0.0.1:${port}`);
    await open(ext);
    const extSeen = framesOf(ext);
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
        accepts: ['peer-gone', ACCOUNT_KEY_FRAME, ACCOUNT_ATTEST_FRAME],
      } satisfies HelloFrameFromExtension),
    );
    await vi.waitFor(() => expect(peerSeen).toContain('hello'));
    await vi.waitFor(() => expect(extSeen).toContain('hello'));

    // A peer vouching for itself, and a peer handing the extension a key.
    peer.send(JSON.stringify(ATTEST));
    peer.send(JSON.stringify(KEY));
    // The extension (or anything posing as it) sending them toward an MCP.
    ext.send(JSON.stringify(ATTEST));
    ext.send(JSON.stringify(KEY));

    await new Promise((r) => setTimeout(r, 100));
    for (const seen of [peerSeen, extSeen]) {
      expect(seen).not.toContain(ACCOUNT_ATTEST_FRAME);
      expect(seen).not.toContain(ACCOUNT_KEY_FRAME);
    }
    expect(peer.readyState).toBe(WebSocket.OPEN);
    expect(ext.readyState).toBe(WebSocket.OPEN);

    peer.close();
    ext.close();
  });
});
