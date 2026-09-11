import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocket, WebSocketServer } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateFrame,
  generateX25519,
  generateEd25519,
  derivePairCodeFromIds,
  type HelloFrameFromExtension,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import { FetchproxyServer } from '../../src/index.js';
import { getEphemeralPort } from '../helpers/ephemeral-port.js';

/**
 * M1: the pair code an MCP surfaces has to be the one IT derived from the
 * two identities, never the number a `pair-pending` frame carried. The
 * frame crosses the concentrator (and, when the MCP is hosted, a remote
 * relay) in plaintext, so a party in the middle presenting its own
 * identity to each end can make both "channels" the user compares agree
 * with each other — which is the whole of what the SAS is for.
 *
 * This mock extension is the in-path party: it derives the joint code
 * honestly (agreeing case) or sends a number of its own (disagreeing).
 */
async function connectMockExtension(
  port: number,
  codeFor: (derived: string, hello: HelloFrameFromServer) => string,
) {
  const extIdX = await generateX25519();
  const extIdEd = await generateEd25519();
  const extSessionNonce = new Uint8Array(32);
  crypto.getRandomValues(extSessionNonce);

  const ws = new WebSocket(`ws://127.0.0.1:${port}`);
  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });

  const closes: { code: number; reason: string }[] = [];
  ws.on('close', (code, reason) => closes.push({ code, reason: reason.toString() }));

  let helloCount = 0;
  /** serverName → the code this extension actually sent for it. */
  const sent = new Map<string, string>();
  ws.on('message', (data) => {
    void (async () => {
      try {
        const frame = validateFrame(JSON.parse(data.toString()));
        if (frame.type !== 'hello' || frame.role !== 'server') return;
        const derived = await derivePairCodeFromIds(
          Buffer.from(frame.identityX25519Pub, 'base64'),
          extIdX.publicKey,
        );
        const code = codeFor(derived, frame);
        sent.set(frame.serverName, code);
        ws.send(JSON.stringify({ type: 'pair-pending', mcpId: frame.mcpId, pairCode: code }));
        // Counted AFTER the send, so `helloCountReached` means "the frame is
        // on the wire and `sentFor` knows its code", not "the derivation
        // started" — a `sentFor` that is still null makes an assertion pass
        // against a null the server has not produced either.
        helloCount += 1;
      } catch {
        /* ignore */
      }
    })();
  });

  const extHello: HelloFrameFromExtension = {
    type: 'hello',
    protocolVersion: 3,
    role: 'extension',
    platform: 'chrome',
    extensionId: 'fetchproxy',
    version: '0.5.0',
    identityX25519Pub: Buffer.from(extIdX.publicKey).toString('base64'),
    identityEd25519Pub: Buffer.from(extIdEd.publicKey).toString('base64'),
    sessionNonce: Buffer.from(extSessionNonce).toString('base64'),
  };
  ws.send(JSON.stringify(extHello));

  return {
    ws,
    closes,
    sentFor: (serverName: string) => sent.get(serverName) ?? null,
    helloCountReached: (n: number, timeoutMs = 2000) =>
      new Promise<void>((resolve, reject) => {
        const start = Date.now();
        const tick = (): void => {
          if (helloCount >= n) return resolve();
          if (Date.now() - start > timeoutMs) {
            return reject(new Error(`only saw ${helloCount}/${n} hellos within ${timeoutMs}ms`));
          }
          setTimeout(tick, 10);
        };
        tick();
      }),
  };
}

/** A valid-shaped six-digit code that is not `code`. */
function otherCode(code: string): string {
  return code === '000-000' ? '999-999' : '000-000';
}

describe('the MCP surfaces only the pair code it derived itself (M1)', () => {
  let host: FetchproxyServer | null = null;
  let peer: FetchproxyServer | null = null;
  let extWs: WebSocket | null = null;

  afterEach(async () => {
    vi.restoreAllMocks();
    if (extWs && extWs.readyState === extWs.OPEN) extWs.close();
    if (peer) await peer.close();
    if (host) await host.close();
    host = null;
    peer = null;
    extWs = null;
    await new Promise((r) => setTimeout(r, 50));
  });

  async function startHost(serverName = 'host-mcp'): Promise<number> {
    const port = await getEphemeralPort();
    const idDir = mkdtempSync(join(tmpdir(), 'fp-pair-sas-'));
    host = new FetchproxyServer({
      port,
      serverName,
      version: '0.0.1',
      domains: ['host.example.com'],
      identityDir: idDir,
    });
    await host.listen();
    await host.connect();
    expect(host.role).toBe('host');
    return port;
  }

  it('host: an agreeing pair code is accepted and surfaced', async () => {
    const port = await startHost();
    const ext = await connectMockExtension(port, (derived) => derived);
    extWs = ext.ws;
    await ext.helloCountReached(1);

    await vi.waitFor(() => expect(host!.bridgeHealth().session.pairCode).toBe(ext.sentFor('host-mcp')));
    expect(host!.bridgeHealth().session.pairCode).toMatch(/^\d{3}-\d{3}$/);
    expect(ext.closes).toHaveLength(0);

    const result = await host!.fetch({
      url: 'https://host.example.com/x',
      method: 'GET',
      tabUrl: 'https://host.example.com/',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toContain(ext.sentFor('host-mcp')!);
  }, 15_000);

  it('host: a disagreeing pair code closes the connection with a logged alarm and is never surfaced', async () => {
    const alarm = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const port = await startHost();
    const ext = await connectMockExtension(port, (derived) => otherCode(derived));
    extWs = ext.ws;
    await ext.helloCountReached(1);

    await vi.waitFor(() => expect(ext.closes).toHaveLength(1));
    expect(ext.closes[0]?.code).toBe(1008);
    // The relay's number never reaches anything a user could read.
    expect(host!.bridgeHealth().session.pairCode).toBeNull();
    expect(host!.bridgeHealth().session.state).not.toBe('pair_pending');
    const logged = alarm.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(logged).toMatch(/pair code/i);
    expect(logged).toMatch(/host-mcp/);
  }, 15_000);

  it('host: a second extension may not pair with the code of the one that left', async () => {
    // The invariant the close path is written for: the joint code commits to
    // a PAIR of identities, so the number a user read off the popup of the
    // browser that has gone must not vouch for the next one to connect. With
    // the code derived from the live hello rather than remembered, there is
    // no stale value for a second identity to match.
    const alarm = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const port = await startHost();

    const first = await connectMockExtension(port, (derived) => derived);
    extWs = first.ws;
    await first.helloCountReached(1);
    await vi.waitFor(() =>
      expect(host!.bridgeHealth().session.pairCode).toBe(first.sentFor('host-mcp')),
    );
    const codeOfTheBrowserThatLeft = first.sentFor('host-mcp')!;

    first.ws.close();
    await vi.waitFor(() => expect(host!.bridgeHealth().session.extensionConnected).toBe(false));

    const second = await connectMockExtension(port, () => codeOfTheBrowserThatLeft);
    extWs = second.ws;
    await second.helloCountReached(1);

    await vi.waitFor(() => expect(second.closes).toHaveLength(1));
    expect(second.closes[0]?.code).toBe(1008);
    expect(host!.bridgeHealth().session.pairCode).toBeNull();
    const logged = alarm.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(logged).toMatch(/pair code/i);
  }, 15_000);

  it('host: a peer joining after the extension left is relayed no identity for it', async () => {
    // The other half of the same invariant, on the host's relay: the hello it
    // keeps IS what a peer derives its pair code from, so leaving a departed
    // browser's identity in place would hand a peer the material to vouch for
    // an extension that is not there.
    const port = await startHost();
    const first = await connectMockExtension(port, (derived) => derived);
    extWs = first.ws;
    await first.helloCountReached(1);
    await vi.waitFor(() =>
      expect(host!.bridgeHealth().session.pairCode).toBe(first.sentFor('host-mcp')),
    );

    first.ws.close();
    await vi.waitFor(() => expect(host!.bridgeHealth().session.extensionConnected).toBe(false));

    const idDir = mkdtempSync(join(tmpdir(), 'fp-pair-sas-peer-late-'));
    peer = new FetchproxyServer({
      port,
      serverName: 'peer-mcp',
      version: '0.0.1',
      domains: ['peer.example.com'],
      identityDir: idDir,
    });
    await peer.listen();
    await peer.connect();
    expect(peer.role).toBe('peer');
    // A relay would be sent in the turn that reads this peer's hello, so a
    // settle is the whole of the wait for it.
    await new Promise((r) => setTimeout(r, 100));
    expect(peer.bridgeHealth().session.extensionConnected).toBe(false);

    // Control: the relay itself works on this path, so the negative above is
    // the host having nothing to relay rather than the harness missing it.
    const second = await connectMockExtension(port, (derived) => derived);
    extWs = second.ws;
    await second.helloCountReached(2);
    await vi.waitFor(() =>
      expect(peer!.bridgeHealth().session.extensionConnected).toBe(true),
    );
  }, 15_000);

  it('peer: an agreeing pair code is accepted and surfaced', async () => {
    const port = await startHost();
    const idDir = mkdtempSync(join(tmpdir(), 'fp-pair-sas-peer-'));
    peer = new FetchproxyServer({
      port,
      serverName: 'peer-mcp',
      version: '0.0.1',
      domains: ['peer.example.com'],
      identityDir: idDir,
    });
    await peer.listen();
    await peer.connect();
    expect(peer.role).toBe('peer');

    const ext = await connectMockExtension(port, (derived) => derived);
    extWs = ext.ws;
    await ext.helloCountReached(2);

    await vi.waitFor(() => expect(peer!.bridgeHealth().session.pairCode).toBe(ext.sentFor('peer-mcp')));
    expect(peer!.bridgeHealth().session.pairCode).toMatch(/^\d{3}-\d{3}$/);
    // Each MCP's code commits to its OWN identity, so the two differ.
    expect(peer!.bridgeHealth().session.pairCode).not.toBe(ext.sentFor('host-mcp'));
    expect(ext.closes).toHaveLength(0);
  }, 15_000);

  it('peer: a disagreeing pair code closes the upstream with a logged alarm and is never surfaced', async () => {
    const alarm = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const port = await startHost();
    const idDir = mkdtempSync(join(tmpdir(), 'fp-pair-sas-peer-bad-'));
    peer = new FetchproxyServer({
      port,
      serverName: 'peer-mcp',
      version: '0.0.1',
      domains: ['peer.example.com'],
      identityDir: idDir,
    });
    await peer.listen();
    await peer.connect();

    // Only the PEER is lied to, so the host stays up and the peer's own
    // upstream is what has to come down.
    const ext = await connectMockExtension(port, (derived, hello) =>
      hello.serverName === 'peer-mcp' ? otherCode(derived) : derived,
    );
    extWs = ext.ws;
    await ext.helloCountReached(2);

    await vi.waitFor(() => {
      const logged = alarm.mock.calls.map((c) => c.join(' ')).join('\n');
      expect(logged).toMatch(/pair code/i);
      expect(logged).toMatch(/peer-mcp/);
    });
    // The hang-up, not only the alarm: the peer's upstream comes down, which
    // at this level shows up as the handle going away and the role resetting
    // (ws-server's `onClose`). Without it the alarm above would be the whole
    // of what "closes with the alarm logged" is pinned by.
    await vi.waitFor(() => expect(peer!.bridgeHealth().session.state).toBe('not_listening'));
    expect(peer!.bridgeHealth().session.pairCode).toBeNull();
    expect(host!.bridgeHealth().session.pairCode).toBe(ext.sentFor('host-mcp'));
  }, 15_000);
});

/**
 * A stand-in concentrator that is NOT this codebase's host, so the peer's own
 * judgement can be driven directly — including the close code it hangs up
 * with, which the real-host cases above can only observe as the handle going
 * away. Two shapes matter to M1:
 *
 *  - `relayExtensionHello: true` is a 1.12.0+ host: the peer learns the far
 *    identity and can derive for itself, so a `pair-pending` is judged.
 *  - `relayExtensionHello: false` is a pre-1.12.0 host, which relays no
 *    extension identity at all. The peer can derive nothing, and M1's answer
 *    for that topology is to show NOTHING rather than the wire's number.
 */
async function startFakeConcentrator(opts: {
  port: number;
  relayExtensionHello: boolean;
  /** Given the code the peer would derive, the code this host actually sends. */
  codeFor: (derived: string) => string;
}) {
  const extIdX = await generateX25519();
  const extIdEd = await generateEd25519();
  const extSessionNonce = new Uint8Array(32);
  crypto.getRandomValues(extSessionNonce);

  const wss = new WebSocketServer({ port: opts.port, host: '127.0.0.1' });
  await new Promise<void>((resolve) => wss.once('listening', () => resolve()));

  /** Closes the PEER performed on its upstream, as this end saw them. */
  const closes: { code: number; reason: string }[] = [];
  let sends = 0;
  let sent: string | null = null;
  let live: WebSocket | null = null;
  let peerMcpId: string | null = null;

  wss.on('connection', (ws: WebSocket) => {
    live = ws;
    ws.on('close', (code, reason) => closes.push({ code, reason: reason.toString() }));
    ws.on('message', (data) => {
      void (async () => {
        const frame = validateFrame(JSON.parse(data.toString()));
        if (frame.type !== 'hello' || frame.role !== 'server') return;
        peerMcpId = frame.mcpId;
        // Derived BEFORE a byte goes out, so the relayed hello and the
        // `pair-pending` behind it leave in ONE synchronous turn. That is the
        // arrival order M1 has to hold against, and the hostile one: `ws` does
        // not serialise an async message handler, so both frames reach the
        // peer's handler before the first has finished with the identity it
        // carries.
        // Deriving BETWEEN the two sends raced the peer's own derivation
        // instead of pinning anything, which is what made this file flaky
        // (reviewer finding on F4.3).
        const derived = await derivePairCodeFromIds(
          Buffer.from(frame.identityX25519Pub, 'base64'),
          extIdX.publicKey,
        );
        sent = opts.codeFor(derived);
        const pairPending = JSON.stringify({
          type: 'pair-pending',
          mcpId: frame.mcpId,
          pairCode: sent,
        });
        if (opts.relayExtensionHello) {
          const extHello: HelloFrameFromExtension = {
            type: 'hello',
            protocolVersion: 3,
            role: 'extension',
            platform: 'chrome',
            extensionId: 'fetchproxy',
            version: '0.5.0',
            identityX25519Pub: Buffer.from(extIdX.publicKey).toString('base64'),
            identityEd25519Pub: Buffer.from(extIdEd.publicKey).toString('base64'),
            sessionNonce: Buffer.from(extSessionNonce).toString('base64'),
          };
          ws.send(JSON.stringify(extHello));
        }
        ws.send(pairPending);
        sends += 1;
        // A second, identical frame: the extension re-announces on every
        // popup open, and "warns once" is a property of the peer rather than
        // of how many frames arrive.
        ws.send(pairPending);
        sends += 1;
      })();
    });
  });

  return {
    closes,
    sentCode: () => sent,
    peerMcpId: () => peerMcpId,
    /** Send a frame of this test's own choosing, once the handshake is done. */
    sendToPeer: (frame: unknown) => live?.send(JSON.stringify(frame)),
    sendsReached: (n: number) => vi.waitFor(() => expect(sends).toBeGreaterThanOrEqual(n)),
    close: () => new Promise<void>((r) => wss.close(() => r())),
  };
}

describe('a peer judging a pair code it did not receive from our own host (M1)', () => {
  let peer: FetchproxyServer | null = null;
  let fake: Awaited<ReturnType<typeof startFakeConcentrator>> | null = null;

  afterEach(async () => {
    vi.restoreAllMocks();
    if (peer) await peer.close();
    if (fake) await fake.close();
    peer = null;
    fake = null;
    await new Promise((r) => setTimeout(r, 50));
  });

  async function startPeerAgainst(port: number): Promise<FetchproxyServer> {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-pair-sas-fake-'));
    const s = new FetchproxyServer({
      port,
      serverName: 'peer-mcp',
      version: '0.0.1',
      domains: ['peer.example.com'],
      identityDir: idDir,
    });
    await s.listen();
    await s.connect();
    expect(s.role).toBe('peer');
    return s;
  }

  it('accepts an agreeing code that arrives in the same read turn as the relayed hello', async () => {
    // `ws` does not serialise an async message handler, so this frame reaches
    // the pair-pending branch while the hello ahead of it is still inside its
    // own awaits. Judging it against a derivation that has not finished is
    // indistinguishable from "no extension identity was ever relayed", which
    // downgraded the close-on-disagreement below to one warning and a live
    // socket (reviewer finding on F4.3).
    const port = await getEphemeralPort();
    fake = await startFakeConcentrator({
      port,
      relayExtensionHello: true,
      codeFor: (derived) => derived,
    });
    peer = await startPeerAgainst(port);
    await fake.sendsReached(2);

    await vi.waitFor(() => expect(peer!.bridgeHealth().session.pairCode).toBe(fake!.sentCode()));
    expect(peer.bridgeHealth().session.pairCode).toMatch(/^\d{3}-\d{3}$/);
    expect(fake.closes).toHaveLength(0);
  }, 15_000);

  it('will not judge a pair code against the identity of an extension that has left', async () => {
    // The mirror of the host case above, on the handle that learns of the
    // departure through a relayed `extension-disconnected`: the code belonged
    // to that browser, and nothing may let it vouch for whatever speaks next.
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const port = await getEphemeralPort();
    fake = await startFakeConcentrator({
      port,
      relayExtensionHello: true,
      codeFor: (derived) => derived,
    });
    peer = await startPeerAgainst(port);
    await fake.sendsReached(2);
    await vi.waitFor(() => expect(peer!.bridgeHealth().session.pairCode).toBe(fake!.sentCode()));
    const codeOfTheBrowserThatLeft = fake.sentCode()!;

    fake.sendToPeer({ type: 'extension-disconnected' });
    await vi.waitFor(() =>
      expect(peer!.bridgeHealth().session.extensionConnected).toBe(false),
    );

    fake.sendToPeer({
      type: 'pair-pending',
      mcpId: fake.peerMcpId(),
      pairCode: codeOfTheBrowserThatLeft,
    });
    await vi.waitFor(() => {
      const warned = warn.mock.calls
        .map((c) => c.join(' '))
        .filter((m) => /cannot derive for itself/.test(m));
      expect(warned).toHaveLength(1);
    });
    expect(peer.bridgeHealth().session.pairCode).toBeNull();
    // Unverifiable, not wrong: as behind a pre-1.12.0 host, the link stays up.
    expect(fake.closes).toHaveLength(0);
  }, 15_000);

  it('closes the upstream with 1008 and the mismatch reason when the code disagrees', async () => {
    const alarm = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    const port = await getEphemeralPort();
    fake = await startFakeConcentrator({
      port,
      relayExtensionHello: true,
      codeFor: (derived) => otherCode(derived),
    });
    peer = await startPeerAgainst(port);

    // The close itself, not merely the alarm: half of "closes with the alarm
    // logged" is the hang-up, and nothing else in the suite pins it on this
    // path (reviewer finding on F4.3).
    await vi.waitFor(() => expect(fake!.closes).toHaveLength(1));
    expect(fake!.closes[0]?.code).toBe(1008);
    expect(fake!.closes[0]?.reason).toBe('pair code mismatch');

    expect(peer.bridgeHealth().session.pairCode).toBeNull();
    const logged = alarm.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(logged).toMatch(/pair code/i);
    expect(logged).toMatch(/peer-mcp/);
  }, 15_000);

  it('shows nothing, warns once and stays connected behind a pre-1.12.0 host', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const port = await getEphemeralPort();
    fake = await startFakeConcentrator({
      port,
      // The pre-1.12.0 shape: no extension identity is relayed, so this peer
      // can derive nothing to judge the frame against.
      relayExtensionHello: false,
      codeFor: (derived) => derived,
    });
    peer = await startPeerAgainst(port);
    await fake.sendsReached(2);

    // The number on the wire is the one the peer WOULD have derived, and it
    // still shows nothing: the refusal is "I cannot check this", not "this
    // looks wrong". Reported as extension_disconnected — the honest state for
    // a peer that has never been told an extension is there — where before
    // this commit the wire's number made it `pair_pending`.
    await vi.waitFor(() => {
      const warned = warn.mock.calls
        .map((c) => c.join(' '))
        .filter((m) => /cannot derive for itself/.test(m));
      expect(warned).toHaveLength(1);
      expect(warned[0]).toMatch(/peer-mcp/);
    });
    expect(peer.bridgeHealth().session).toEqual({
      state: 'extension_disconnected',
      pairCode: null,
      extensionConnected: false,
    });

    // And the socket is still up: refusing a bridge over a hint it merely
    // cannot verify would take down a working (if unverifiable) link.
    expect(fake.closes).toHaveLength(0);
    expect(peer.role).toBe('peer');
  }, 15_000);
});
