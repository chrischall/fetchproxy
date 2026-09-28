import { describe, it, expect, afterEach } from 'vitest';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openEncryptedFrame, type EncryptedFrame } from '@fetchproxy/protocol';
import {
  FetchproxyHelloRejectedError,
  FetchproxySessionNotReadyError,
  classifyBridgeError,
} from '../src/index.js';
import { startHost, type HostHandle } from '../src/host.js';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import type { ExtensionPin, ExtensionTrustPort } from '../src/extension-trust.js';
import { connectMockExtension, newExtensionIdentity } from './helpers/mock-extension.js';
import {
  memoryTrust,
  newFakeExtension,
  startFakeConcentrator,
  type FakeConcentrator,
} from './helpers/concentrator.js';

/**
 * A2 / D12 (account-level bridge pairing): `awaiting-approval:` is the one
 * hello refusal that is RETRYABLE. The extension sends it when it has queued an
 * approval card on a remote link and nobody is at the browser, so the call
 * fails at once with "approve it in your browser" — and once the person does,
 * the next hello (or the `ready` the extension was holding) must succeed. Every
 * other refusal is the extension's final answer and stays latched.
 */

const AWAITING = 'awaiting-approval: approve zillow in Chrome';
const UNSUPPORTED = 'unsupported-capability: download (not available in this browser)';

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

/** Whether `p` is still pending after the event loop has had a real turn. */
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

describe('FetchproxyHelloRejectedError — awaiting-approval', () => {
  it('is retryable, and says to approve in the browser', () => {
    const e = new FetchproxyHelloRejectedError({ mcpId: 'zillow-mcp:1.0.0:abc', reason: AWAITING });
    expect(e.retryable).toBe(true);
    expect(e.reason).toBe(AWAITING);
    expect(e.hint).not.toBeNull();
    expect(e.hint).toMatch(/approve/i);
    expect(e.hint).toMatch(/browser/i);
    expect(e.hint).toContain('approve zillow in Chrome');
    expect(e.hint).toMatch(/retry/i);
    expect(e.message).toContain(e.hint!);
    // The wording every other refusal carries would be false here.
    expect(e.message).not.toMatch(/refused the same way/);
    expect(e.unavailableCapabilities).toEqual([]);
  });

  it('still says to approve in the browser when the extension gave no detail', () => {
    const e = new FetchproxyHelloRejectedError({ mcpId: 'zillow-mcp:1.0.0:abc', reason: 'awaiting-approval:' });
    expect(e.retryable).toBe(true);
    expect(e.hint).toMatch(/approve/i);
    expect(e.hint).toMatch(/browser/i);
  });

  it('is not retryable for any other reason', () => {
    for (const reason of [
      UNSUPPORTED,
      'sessionSig invalid',
      'serverName/domains mismatch with trust record',
      'Awaiting-approval: approve zillow',
      ' awaiting-approval: approve zillow',
    ]) {
      const e = new FetchproxyHelloRejectedError({ mcpId: 'x', reason });
      expect(e.retryable, reason).toBe(false);
    }
  });
});

describe('classifyBridgeError — awaiting_approval', () => {
  it('classifies an awaiting-approval refusal as awaiting_approval', () => {
    const e = new FetchproxyHelloRejectedError({ mcpId: 'x', reason: AWAITING });
    expect(classifyBridgeError(e)).toBe('awaiting_approval');
  });

  it('keeps every other refusal as hello_rejected', () => {
    expect(classifyBridgeError(new FetchproxyHelloRejectedError({ mcpId: 'x', reason: UNSUPPORTED }))).toBe(
      'hello_rejected',
    );
    expect(
      classifyBridgeError(new FetchproxyHelloRejectedError({ mcpId: 'x', reason: 'sessionSig invalid' })),
    ).toBe('hello_rejected');
  });

  it('does not touch session_not_ready', () => {
    expect(classifyBridgeError(new FetchproxySessionNotReadyError({ mcpId: 'x', pairCode: null }))).toBe(
      'session_not_ready',
    );
  });
});

describe('host: an awaiting-approval refusal does not latch', () => {
  const MCP_ID = 'zillow-mcp:1.0.0:abc1234567890de1';
  let host: HostHandle | null = null;
  afterEach(async () => {
    if (host) await host.close();
    host = null;
  });

  async function startTestHost(): Promise<number> {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const id = await loadOrCreateIdentity('zillow-mcp', mkdtempSync(join(tmpdir(), 'fp-a2-host-')));
    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: MCP_ID,
      ownServerName: 'zillow-mcp',
      ownVersion: '1.0.0',
      ownDomains: ['zillow.com'],
      extensionTrust: blankTrust(),
    });
    return port;
  }

  /** Refuse our own hello with `reason`, and return the refusal the waiter saw. */
  async function refuse(port: number, reason: string) {
    const ext = await connectMockExtension(port);
    const seen = await ext.waitForServerHello(MCP_ID);
    const waiting = host!.sendOwnInner({ type: 'ping' }).catch((e: unknown) => e);
    ext.ws.send(JSON.stringify({ type: 'hello-rejected', mcpId: MCP_ID, reason }));
    const err = await waiting;
    expect(err).toBeInstanceOf(FetchproxyHelloRejectedError);
    return { ext, seen, err: err as FetchproxyHelloRejectedError };
  }

  function nextOwnFrame(ext: Awaited<ReturnType<typeof connectMockExtension>>) {
    return new Promise<Record<string, unknown>>((resolve) => {
      ext.ws.on('message', (data: Buffer) => {
        const parsed = JSON.parse(data.toString());
        if (parsed.type === 'frame' && parsed.mcpId === MCP_ID) resolve(parsed);
      });
    });
  }

  it('fails the waiting call at once, retryable', async () => {
    const port = await startTestHost();
    const { err } = await refuse(port, AWAITING);
    expect(err.retryable).toBe(true);
    expect(classifyBridgeError(err)).toBe('awaiting_approval');
  });

  it('fails a call made before the person approves at once, not after the timeout', async () => {
    const port = await startTestHost();
    await refuse(port, AWAITING);
    const again = host!.sendOwnInner({ type: 'ping' }).catch((e: unknown) => e);
    expect(await stillPending(again)).toBe(false);
    const err = await again;
    expect(err).toBeInstanceOf(FetchproxyHelloRejectedError);
    expect((err as FetchproxyHelloRejectedError).retryable).toBe(true);
  });

  it('lets the ready the extension sends after approval open the session', async () => {
    const port = await startTestHost();
    const { ext, seen } = await refuse(port, AWAITING);
    // The person approves; the extension completes the hello it was holding.
    const key = await ext.answerReady(seen);
    await new Promise((r) => setTimeout(r, 50));
    const sealed = nextOwnFrame(ext);
    await host!.sendOwnInner({ type: 'ping' });
    const frame = await sealed;
    expect((await openEncryptedFrame(key, frame as unknown as EncryptedFrame, 's2e')).type).toBe('ping');
    ext.close();
  });

  it('lets the next extension session hello afresh and succeed', async () => {
    const port = await startTestHost();
    const browser = await newExtensionIdentity();
    const ext1 = await connectMockExtension(port, browser);
    await ext1.waitForServerHello(MCP_ID);
    ext1.ws.send(JSON.stringify({ type: 'hello-rejected', mcpId: MCP_ID, reason: AWAITING }));
    await new Promise((r) => setTimeout(r, 50));
    ext1.close();
    await ext1.closed();
    await new Promise((r) => setTimeout(r, 50));

    const ext2 = await connectMockExtension(port, browser);
    const key = await ext2.completeHandshake(MCP_ID);
    await new Promise((r) => setTimeout(r, 50));
    const sealed = nextOwnFrame(ext2);
    await host!.sendOwnInner({ type: 'ping' });
    const frame = await sealed;
    expect((await openEncryptedFrame(key, frame as unknown as EncryptedFrame, 's2e')).type).toBe('ping');
    ext2.close();
  });

  it('keeps any other refusal latched even if a ready follows on the same link', async () => {
    const port = await startTestHost();
    const { ext, seen, err } = await refuse(port, UNSUPPORTED);
    expect(err.retryable).toBe(false);
    await ext.answerReady(seen);
    await new Promise((r) => setTimeout(r, 50));
    const again = await host!.sendOwnInner({ type: 'ping' }).catch((e: unknown) => e);
    expect(again).toBeInstanceOf(FetchproxyHelloRejectedError);
    expect((again as FetchproxyHelloRejectedError).reason).toBe(UNSUPPORTED);
    ext.close();
  });

  // The latch is the invariant: an awaiting-approval refusal must never be
  // able to undo a final one, whichever order they arrive in.
  it('does not let an awaiting-approval refusal after a final one un-latch it', async () => {
    const port = await startTestHost();
    const { ext, seen } = await refuse(port, UNSUPPORTED);
    ext.ws.send(JSON.stringify({ type: 'hello-rejected', mcpId: MCP_ID, reason: AWAITING }));
    await new Promise((r) => setTimeout(r, 50));
    await ext.answerReady(seen);
    await new Promise((r) => setTimeout(r, 50));
    const again = await host!.sendOwnInner({ type: 'ping' }).catch((e: unknown) => e);
    expect(again).toBeInstanceOf(FetchproxyHelloRejectedError);
    expect((again as FetchproxyHelloRejectedError).reason).toBe(UNSUPPORTED);
    ext.close();
  });

  it('lets a final refusal after an awaiting-approval one latch, with its own reason', async () => {
    const port = await startTestHost();
    const { ext, seen } = await refuse(port, AWAITING);
    ext.ws.send(JSON.stringify({ type: 'hello-rejected', mcpId: MCP_ID, reason: UNSUPPORTED }));
    await new Promise((r) => setTimeout(r, 50));
    const before = await host!.sendOwnInner({ type: 'ping' }).catch((e: unknown) => e);
    expect((before as FetchproxyHelloRejectedError).reason).toBe(UNSUPPORTED);
    await ext.answerReady(seen);
    await new Promise((r) => setTimeout(r, 50));
    const after = await host!.sendOwnInner({ type: 'ping' }).catch((e: unknown) => e);
    expect(after).toBeInstanceOf(FetchproxyHelloRejectedError);
    expect((after as FetchproxyHelloRejectedError).reason).toBe(UNSUPPORTED);
    ext.close();
  });

  it('does not let an awaiting-approval refusal disturb a live session', async () => {
    const port = await startTestHost();
    const ext = await connectMockExtension(port);
    const key = await ext.completeHandshake(MCP_ID);
    await new Promise((r) => setTimeout(r, 50));
    ext.ws.send(JSON.stringify({ type: 'hello-rejected', mcpId: MCP_ID, reason: AWAITING }));
    await new Promise((r) => setTimeout(r, 50));
    const sealed = nextOwnFrame(ext);
    await host!.sendOwnInner({ type: 'ping' });
    const frame = await sealed;
    expect((await openEncryptedFrame(key, frame as unknown as EncryptedFrame, 's2e')).type).toBe('ping');
    ext.close();
  });
});

describe('peer: an awaiting-approval refusal does not latch', () => {
  const MCP_ID = 'zillow-mcp:1.0.0:a3f7c91d2e8b4f56';
  let rig: FakeConcentrator | null = null;
  let peer: InternalPeerHandle | null = null;
  afterEach(async () => {
    peer?.close();
    peer = null;
    if (rig) await rig.close();
    rig = null;
  });

  async function refused(reason: string) {
    rig = await startFakeConcentrator();
    const identity = await loadOrCreateIdentity('zillow-mcp', mkdtempSync(join(tmpdir(), 'fp-a2-peer-')));
    peer = await startPeer({
      host: '127.0.0.1',
      port: rig.port,
      identity,
      mcpId: MCP_ID,
      serverName: 'zillow-mcp',
      version: '1.0.0',
      domains: ['zillow.com'],
      extensionTrust: memoryTrust(),
    });
    await rig.waitForHello();
    const ext = await newFakeExtension();
    await rig.relayExtensionHello(ext);
    const hello = await rig.waitForHello(1);
    const waiting = peer.sendInner({ type: 'ping' }).catch((e: unknown) => e);
    await rig.send({ type: 'hello-rejected', mcpId: MCP_ID, reason });
    const err = await waiting;
    expect(err).toBeInstanceOf(FetchproxyHelloRejectedError);
    return { ext, hello, err: err as FetchproxyHelloRejectedError };
  }

  it('fails the waiting call at once, retryable', async () => {
    const { err } = await refused(AWAITING);
    expect(err.retryable).toBe(true);
    expect(classifyBridgeError(err)).toBe('awaiting_approval');
  });

  it('fails a call made before the person approves at once', async () => {
    await refused(AWAITING);
    const again = peer!.sendInner({ type: 'ping' }).catch((e: unknown) => e);
    expect(await stillPending(again)).toBe(false);
    expect((await again) as FetchproxyHelloRejectedError).toBeInstanceOf(FetchproxyHelloRejectedError);
  });

  it('lets the ready the extension sends after approval open the session', async () => {
    const { ext, hello } = await refused(AWAITING);
    const key = await rig!.answerReady(ext, hello);
    await new Promise((r) => setTimeout(r, 50));
    await peer!.sendInner({ type: 'ping' });
    const frames = await rig!.waitForFrames(1);
    const last = frames[frames.length - 1] as unknown as EncryptedFrame;
    expect((await openEncryptedFrame(key, last, 's2e')).type).toBe('ping');
  });

  it('lets the next extension session hello afresh and succeed', async () => {
    const { ext } = await refused(AWAITING);
    await rig!.relayExtensionDisconnected();
    const ext2 = await newFakeExtension(ext);
    await rig!.relayExtensionHello(ext2);
    const key = await rig!.answerReady(ext2, await rig!.waitForHello(2));
    await new Promise((r) => setTimeout(r, 50));
    await peer!.sendInner({ type: 'ping' });
    const frames = await rig!.waitForFrames(1);
    const last = frames[frames.length - 1] as unknown as EncryptedFrame;
    expect((await openEncryptedFrame(key, last, 's2e')).type).toBe('ping');
  });

  it('lets a fresh relayed hello succeed even with no disconnect between', async () => {
    const { ext } = await refused(AWAITING);
    const ext2 = await newFakeExtension(ext);
    await rig!.relayExtensionHello(ext2);
    const key = await rig!.answerReady(ext2, await rig!.waitForHello(2));
    await new Promise((r) => setTimeout(r, 50));
    await peer!.sendInner({ type: 'ping' });
    const frames = await rig!.waitForFrames(1);
    const last = frames[frames.length - 1] as unknown as EncryptedFrame;
    expect((await openEncryptedFrame(key, last, 's2e')).type).toBe('ping');
  });

  it('waits for the new extension session once it hellos, instead of repeating the old refusal', async () => {
    const { ext } = await refused(AWAITING);
    const ext2 = await newFakeExtension(ext);
    await rig!.relayExtensionHello(ext2);
    const hello2 = await rig!.waitForHello(2);
    const sending = peer!.sendInner({ type: 'ping' });
    expect(await stillPending(sending)).toBe(true);
    const key = await rig!.answerReady(ext2, hello2);
    await sending;
    const frames = await rig!.waitForFrames(1);
    const last = frames[frames.length - 1] as unknown as EncryptedFrame;
    expect((await openEncryptedFrame(key, last, 's2e')).type).toBe('ping');
  });

  it('waits for the next extension session after the refusing browser goes', async () => {
    const { ext } = await refused(AWAITING);
    await rig!.relayExtensionDisconnected();
    await new Promise((r) => setTimeout(r, 50));
    const sending = peer!.sendInner({ type: 'ping' });
    expect(await stillPending(sending)).toBe(true);
    const ext2 = await newFakeExtension(ext);
    await rig!.relayExtensionHello(ext2);
    const key = await rig!.answerReady(ext2, await rig!.waitForHello(2));
    await sending;
    const frames = await rig!.waitForFrames(1);
    const last = frames[frames.length - 1] as unknown as EncryptedFrame;
    expect((await openEncryptedFrame(key, last, 's2e')).type).toBe('ping');
  });

  it('keeps any other refusal latched across a later hello and ready', async () => {
    const { ext, err } = await refused(UNSUPPORTED);
    expect(err.retryable).toBe(false);
    await rig!.relayExtensionDisconnected();
    const ext2 = await newFakeExtension(ext);
    await rig!.relayExtensionHello(ext2);
    await rig!.answerReady(ext2, await rig!.waitForHello(2));
    await new Promise((r) => setTimeout(r, 50));
    const again = await peer!.sendInner({ type: 'ping' }).catch((e: unknown) => e);
    expect(again).toBeInstanceOf(FetchproxyHelloRejectedError);
    expect((again as FetchproxyHelloRejectedError).reason).toBe(UNSUPPORTED);
  });

  it('does not let an awaiting-approval refusal after a final one un-latch it', async () => {
    const { ext, hello } = await refused(UNSUPPORTED);
    await rig!.send({ type: 'hello-rejected', mcpId: MCP_ID, reason: AWAITING });
    await new Promise((r) => setTimeout(r, 50));
    await rig!.answerReady(ext, hello);
    await new Promise((r) => setTimeout(r, 50));
    const again = await peer!.sendInner({ type: 'ping' }).catch((e: unknown) => e);
    expect(again).toBeInstanceOf(FetchproxyHelloRejectedError);
    expect((again as FetchproxyHelloRejectedError).reason).toBe(UNSUPPORTED);
  });

  it('lets a final refusal after an awaiting-approval one latch, with its own reason', async () => {
    const { ext, hello } = await refused(AWAITING);
    await rig!.send({ type: 'hello-rejected', mcpId: MCP_ID, reason: UNSUPPORTED });
    await new Promise((r) => setTimeout(r, 50));
    const before = await peer!.sendInner({ type: 'ping' }).catch((e: unknown) => e);
    expect((before as FetchproxyHelloRejectedError).reason).toBe(UNSUPPORTED);
    await rig!.answerReady(ext, hello);
    await new Promise((r) => setTimeout(r, 50));
    const after = await peer!.sendInner({ type: 'ping' }).catch((e: unknown) => e);
    expect(after).toBeInstanceOf(FetchproxyHelloRejectedError);
    expect((after as FetchproxyHelloRejectedError).reason).toBe(UNSUPPORTED);
  });
});
