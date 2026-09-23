import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openEncryptedFrame, type EncryptedFrame } from '@fetchproxy/protocol';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import {
  startFakeConcentrator,
  newFakeExtension,
  memoryTrust,
  type FakeConcentrator,
} from './helpers/concentrator.js';

// B-BUG-5: on `extension-disconnected` the peer cleared the extension hello
// but kept its session and told nobody. In-flight calls were not failed (they
// waited out fetchTimeoutMs and then fetch()'s retry re-sent them), and new
// calls were sealed with the dead key — dropped by the host or by the
// reconnected extension — so every call made across a browser restart burned
// its full timeout. The host role fails these at once.

const MCP_ID = 'resy-mcp:0.9.1:a3f7c91d2e8b4f56';

let rig: FakeConcentrator | null = null;
let peer: InternalPeerHandle | null = null;
afterEach(async () => {
  peer?.close();
  peer = null;
  if (rig) await rig.close();
  rig = null;
});

async function linked() {
  rig = await startFakeConcentrator();
  const identity = await loadOrCreateIdentity(
    'resy-mcp',
    mkdtempSync(join(tmpdir(), 'fp-peer-disc-')),
  );
  peer = await startPeer({
    host: '127.0.0.1',
    port: rig.port,
    identity,
    mcpId: MCP_ID,
    serverName: 'resy-mcp',
    version: '0.9.1',
    domains: ['resy.com'],
    extensionTrust: memoryTrust(),
  });
  await rig.waitForHello();
  const ext1 = await newFakeExtension();
  await rig.relayExtensionHello(ext1);
  const key1 = await rig.answerReady(ext1, await rig.waitForHello(1));
  await peer.sendInner({ type: 'ping' });
  await rig.waitForFrames(1);
  return { ext1, key1 };
}

async function stillPending(p: Promise<unknown>): Promise<boolean> {
  const marker = Symbol('pending');
  const settled = await Promise.race([
    p.then(
      () => 'settled',
      () => 'settled',
    ),
    new Promise((r) => setTimeout(() => r(marker), 150)),
  ]);
  return settled === marker;
}

describe('B-BUG-5: peer drops its session when the extension disconnects', () => {
  it('notifies the owner so in-flight calls fail fast', async () => {
    await linked();
    const onDisconnect = vi.fn();
    peer!.onExtensionDisconnect(onDisconnect);
    await rig!.relayExtensionDisconnected();
    await vi.waitFor(() => expect(onDisconnect).toHaveBeenCalledTimes(1));
    expect(peer!.sessionLinked()).toBe(false);
  });

  it('does not seal new calls with the dead key; they go out under the next session', async () => {
    const { ext1, key1 } = await linked();
    await rig!.relayExtensionDisconnected();
    await vi.waitFor(() => expect(peer!.extensionConnected()).toBe(false));

    const sending = peer!.sendInner({ type: 'ping' });
    expect(await stillPending(sending)).toBe(true);
    // Nothing was sealed under the old key while the extension was gone.
    expect((await rig!.waitForFrames(1)).length).toBe(1);

    const ext2 = await newFakeExtension(ext1);
    await rig!.relayExtensionHello(ext2);
    const key2 = await rig!.answerReady(ext2, await rig!.waitForHello(2));
    await sending;
    const frames = await rig!.waitForFrames(2);
    const last = frames[frames.length - 1] as unknown as EncryptedFrame;
    expect((await openEncryptedFrame(key2, last, 's2e')).type).toBe('ping');
    await expect(openEncryptedFrame(key1, last, 's2e')).rejects.toThrow();
  });
});
