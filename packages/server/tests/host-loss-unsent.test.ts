import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FetchproxyServer } from '../src/index.js';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import {
  linkedPeer,
  newFakeExtension,
  startFakeConcentrator,
  type FakeConcentrator,
} from './helpers/concentrator.js';

// B-BUG-6 follow-up: when a peer's host exits, the requests that may already
// have run in the browser fail with "may already have run — check before
// retrying". A request still QUEUED in this process — waiting for a session,
// never handed to the socket — has not run anywhere, and telling the user to
// go and check is wrong: it must say it was not sent, so it is retried.

let server: FetchproxyServer | null = null;
let rig: FakeConcentrator | null = null;
let peer: InternalPeerHandle | null = null;
afterEach(async () => {
  vi.restoreAllMocks();
  if (peer) peer.close();
  peer = null;
  if (server) await server.close();
  server = null;
  if (rig) await rig.close().catch(() => undefined);
  rig = null;
});

describe('a request that was never sent says so when its host exits', () => {
  it('a POST queued behind a lost session fails as "not sent", not "may already have run"', async () => {
    rig = await startFakeConcentrator();
    const dir = mkdtempSync(join(tmpdir(), 'fp-unsent-'));
    server = new FetchproxyServer({
      serverName: 'resy-mcp',
      version: '0.9.1',
      domains: ['resy.com'],
      host: '127.0.0.1',
      port: rig.port,
      identityDir: dir,
      trustDir: dir,
      allowNewExtensionIdentity: true,
      fetchTimeoutMs: 15_000,
      bridgeReviveDelayMs: 0,
      keepAliveIntervalMs: 0,
    });
    await server.listen();
    await server.connect();
    await rig.waitForHello();
    const ext = await newFakeExtension();
    await rig.relayExtensionHello(ext);
    await rig.answerReady(ext, await rig.waitForHello(1));
    await vi.waitFor(() => expect(server!.bridgeHealth().session.state).toBe('linked'));

    // The extension drops off the host: the peer's session is gone, so a new
    // request waits in this process for the next one.
    await rig.relayExtensionDisconnected();
    await vi.waitFor(() => expect(server!.bridgeHealth().session.state).not.toBe('linked'));
    const post = server.post('/book', '{}').catch((e: unknown) => e);
    await new Promise((r) => setTimeout(r, 20));
    expect(rig.sent().filter((f) => f.type === 'frame')).toHaveLength(0);

    // The host exits before a session ever came back.
    (await rig.socket()).terminate();
    await rig.close();
    rig = null;

    const err = (await post) as Error;
    expect(err).toBeInstanceOf(Error);
    expect(err.message).toMatch(/not sent/);
    expect(err.message).not.toMatch(/may already have run/);
  }, 20_000);
});

describe('peer.sendInner refuses a socket that is no longer open', () => {
  it('throws "not sent" instead of writing into a closed socket and resolving', async () => {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-unsent-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
    const linked = await linkedPeer({
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      identity,
      startPeer: startPeer as unknown as Parameters<typeof linkedPeer>[0]['startPeer'],
    });
    rig = linked.rig;
    peer = linked.peer as unknown as InternalPeerHandle;
    await peer.session;
    const closed = new Promise<void>((r) => peer!.ws.once('close', () => r()));
    peer.ws.terminate();
    await closed;
    await expect(peer.sendInner({ type: 'ping' })).rejects.toThrow(/not sent/);
  });
});
