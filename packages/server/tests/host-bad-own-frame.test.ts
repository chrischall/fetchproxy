import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import {
  openEncryptedFrame,
  sealInnerFrame,
  toB64,
  type EncryptedFrame,
  type InnerFrame,
} from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { connectMockExtension, type MockExtension } from './helpers/mock-extension.js';

// B-BUG-4: on the host role, one frame addressed to the host's OWN session
// that failed GCM or failed validation was rethrown into the socket handler,
// which closed the EXTENSION socket with 1011 — disconnecting the extension
// from every MCP on the concentrator. The peer path already handled both
// cases per frame; the host must too.

const MCP_ID = 'opentable-mcp:0.9.1:abc1234567890def';

let host: HostHandle | null = null;
let ext: MockExtension | null = null;
afterEach(async () => {
  vi.restoreAllMocks();
  ext?.close();
  ext = null;
  if (host) await host.close();
  host = null;
});

async function linkedHost(): Promise<{ key: Uint8Array; received: InnerFrame[] }> {
  const el = await electRole({ host: '127.0.0.1', port: 0 });
  if (el.role !== 'host') throw new Error('expected host');
  const port = (el.server.address() as AddressInfo).port;
  host = await startHost({
    httpServer: el.server,
    ownIdentity: await loadOrCreateIdentity(
      'opentable-mcp',
      mkdtempSync(join(tmpdir(), 'fp-badframe-')),
    ),
    ownMcpId: MCP_ID,
    ownServerName: 'opentable-mcp',
    ownVersion: '0.9.1',
    ownDomains: ['opentable.com'],
    extensionTrust: { allowNew: false, read: async () => null, write: async () => {} },
  });
  ext = await connectMockExtension(port);
  const key = await ext.completeHandshake(MCP_ID);
  await vi.waitFor(() => expect(host!.sessionLinked()).toBe(true));
  const received: InnerFrame[] = [];
  host.onOwnInner((inner) => received.push(inner));
  return { key, received };
}

describe('B-BUG-4: host survives one bad frame on its own session', () => {
  it('drops an undecryptable frame and keeps the extension connected', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const { key, received } = await linkedHost();
    const wrongKey = new Uint8Array(32).fill(7);
    ext!.ws.send(
      JSON.stringify(await sealInnerFrame(wrongKey, MCP_ID, 1, { type: 'pong' }, 'e2s')),
    );
    // Let the forged frame finish failing first. While it is still being
    // opened its seq is CLAIMED, and a same-seq frame arriving in that window
    // is refused as in flight — which made this case flaky.
    await vi.waitFor(() => expect(warn).toHaveBeenCalled());
    // The genuine frame behind it (same seq — the forged one must not spend it).
    ext!.ws.send(JSON.stringify(await sealInnerFrame(key, MCP_ID, 1, { type: 'pong' }, 'e2s')));
    await vi.waitFor(() => expect(received).toHaveLength(1));
    expect(host!.extensionConnected()).toBe(true);
    expect(ext!.ws.readyState).toBe(ext!.ws.OPEN);
  });

  it('fails only the affected request when a frame decrypts but fails validation', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const { key, received } = await linkedHost();
    const bad = new TextEncoder().encode(
      JSON.stringify({ type: 'response', id: 42, op: 'fetch', ok: 'not-a-boolean' }),
    );
    ext!.ws.send(JSON.stringify(await sealInnerFrame(key, MCP_ID, 1, bad, 'e2s')));
    await vi.waitFor(() => expect(received).toHaveLength(1));
    expect(received[0]).toMatchObject({ type: 'response', id: 42, ok: false });
    expect(errors).toHaveBeenCalled();
    // The link is intact: the next genuine frame is delivered.
    ext!.ws.send(JSON.stringify(await sealInnerFrame(key, MCP_ID, 2, { type: 'pong' }, 'e2s')));
    await vi.waitFor(() => expect(received).toHaveLength(2));
    expect(ext!.ws.readyState).toBe(ext!.ws.OPEN);
  });
});

// B-BUG-4 took away the old self-healing (closing the socket) without putting
// anything in its place: if the host's own session key ever diverges from the
// extension's, every frame for it fails authentication and is dropped,
// forever. A run of consecutive failures now re-handshakes the host's OWN
// session — a fresh hello on the same socket — without touching the shared
// extension socket or any other MCP's session.
describe('host re-handshakes its own session after repeated decrypt failures', () => {
  const wrongKey = new Uint8Array(32).fill(7);
  const bad = async (seq: number): Promise<string> =>
    JSON.stringify(await sealInnerFrame(wrongKey, MCP_ID, seq, { type: 'pong' }, 'e2s'));
  const dropped = (warn: { mock: { calls: unknown[][] } }): number =>
    warn.mock.calls.filter((c) =>
      /dropped an inbound frame .*failed authentication/.test(String(c[0])),
    ).length;
  // Send one forged frame and wait until the host has finished rejecting it,
  // so a same-seq frame behind it is not refused as still in flight.
  const sendBad = async (warn: { mock: { calls: unknown[][] } }, seq: number): Promise<void> => {
    const before = dropped(warn);
    ext!.ws.send(await bad(seq));
    await vi.waitFor(() => expect(dropped(warn)).toBe(before + 1));
  };

  it('sends a fresh hello after 3 consecutive failures and recovers on the new key', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const { received } = await linkedHost();
    for (let seq = 1; seq <= 3; seq++) await sendBad(warn, seq);

    const second = await ext!.waitForServerHello(MCP_ID, 1);
    // Answers THIS extension session, on the same socket.
    expect(second.answersExtNonce).toBe(toB64(ext!.sessionNonce));
    expect(ext!.ws.readyState).toBe(ext!.ws.OPEN);
    expect(host!.extensionConnected()).toBe(true);
    expect(warn.mock.calls.some((c) => /re-handshak/i.test(String(c[0])))).toBe(true);

    const newKey = await ext!.answerReady(second);
    await vi.waitFor(() => expect(host!.sessionLinked()).toBe(true));
    // Inbound on the new key is delivered…
    ext!.ws.send(JSON.stringify(await sealInnerFrame(newKey, MCP_ID, 1, { type: 'pong' }, 'e2s')));
    await vi.waitFor(() => expect(received).toHaveLength(1));
    // …and outbound is sealed under it.
    await host!.sendOwnInner({ type: 'ping' });
    await vi.waitFor(() =>
      expect(ext!.framesFor(MCP_ID).some((f) => f.type === 'frame')).toBe(true),
    );
    const sealed = ext!
      .framesFor(MCP_ID)
      .filter((f) => f.type === 'frame')
      .at(-1) as unknown as EncryptedFrame;
    expect(await openEncryptedFrame(newKey, sealed, 's2e')).toEqual({ type: 'ping' });
  });

  it('an authenticated frame resets the count, so scattered stragglers do not re-handshake', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const { key, received } = await linkedHost();
    await sendBad(warn, 1);
    await sendBad(warn, 1);
    ext!.ws.send(JSON.stringify(await sealInnerFrame(key, MCP_ID, 1, { type: 'pong' }, 'e2s')));
    await vi.waitFor(() => expect(received).toHaveLength(1));
    await sendBad(warn, 2);
    await sendBad(warn, 2);
    ext!.ws.send(JSON.stringify(await sealInnerFrame(key, MCP_ID, 2, { type: 'pong' }, 'e2s')));
    await vi.waitFor(() => expect(received).toHaveLength(2));
    expect(ext!.serverHellosFor(MCP_ID)).toHaveLength(1);
    expect(host!.sessionLinked()).toBe(true);
  });
});
