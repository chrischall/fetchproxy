import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateFrame,
  pairTranscript,
  ed25519Verify,
  generateX25519,
  aesGcmSeal,
  answersNoExtSession,
  frameAad,
  fromB64,
  toB64,
  helloSignaturePayload,
  openEncryptedFrame,
  type EncryptedFrame,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import { startPeer, type InternalPeerHandle } from '../src/peer.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { listenEphemeral, loopbackWss } from './helpers/ephemeral-port.js';
import {
  memoryTrust,
  newFakeExtension,
  startFakeConcentrator,
} from './helpers/concentrator.js';

describe('peer client', () => {
  let wss: WebSocketServer | null = null;
  let peer: InternalPeerHandle | null = null;

  afterEach(async () => {
    if (peer) peer.close();
    peer = null;
    if (wss) {
      await new Promise<void>((r) => wss!.close(() => r()));
      wss = null;
    }
  });

  it('dials host and sends hello with valid signature', async () => {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);

    wss = loopbackWss();
    const port = await listenEphemeral(wss);

    const helloPromise = new Promise<HelloFrameFromServer>((resolve) => {
      wss!.on('connection', (ws: WebSocket) => {
        ws.on('message', (data) => {
          const parsed = JSON.parse(data.toString());
          if (parsed.type === 'hello') {
            const frame = validateFrame(parsed);
            if (frame.type === 'hello' && frame.role === 'server') {
              resolve(frame);
            }
          }
        });
      });
    });

    peer = await startPeer({
      host: '127.0.0.1',
      port,
      identity,
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
    });

    const hello = await helloPromise;

    // Structural assertions
    expect(hello.role).toBe('server');
    expect(hello.mcpId).toBe('opentable-mcp:0.9.1:a3f7c91d2e8b4f56');
    expect(hello.serverName).toBe('opentable-mcp');
    expect(hello.version).toBe('0.9.1');
    expect(hello.domains).toEqual(['opentable.com']);

    // Identity pub keys round-trip from the identity file
    const identityX25519Pub = new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'));
    expect(Buffer.from(identityX25519Pub).equals(Buffer.from(identity.x25519Pub))).toBe(true);

    // 3.0.0 (protocol 4): `sessionSig` verifies against identity.ed25519Pub
    // over `helloSignaturePayload(mcpId, sessionNonce, sessionPub,
    // answersExtNonce)`. The v3 payload was `mcpId || sessionNonce`, and
    // adding the two new fields to the frame while leaving the signature over
    // the old bytes compiles perfectly well — which is why this asserts the
    // new payload verifies AND that the old one does not.
    const sessionNonce = fromB64(hello.sessionNonce);
    const sessionSig = fromB64(hello.sessionSig);
    const ok = await ed25519Verify(
      identity.ed25519Pub,
      helloSignaturePayload(
        hello.mcpId,
        sessionNonce,
        fromB64(hello.sessionPub),
        fromB64(hello.answersExtNonce),
      ),
      sessionSig,
    );
    expect(ok).toBe(true);
    const v3Msg = new Uint8Array(hello.mcpId.length + sessionNonce.length);
    v3Msg.set(new TextEncoder().encode(hello.mcpId), 0);
    v3Msg.set(sessionNonce, hello.mcpId.length);
    expect(await ed25519Verify(identity.ed25519Pub, v3Msg, sessionSig)).toBe(false);
    // The hello a peer sends at DIAL is a registration hello: it answers no
    // extension session, and says so.
    expect(answersNoExtSession(hello.answersExtNonce)).toBe(true);
  });

  it('sendInner rejects if the host sends a malformed frame', async () => {
    // peer.ts:110 — catch-on-onMessage. When the host pushes something
    // unparseable (not JSON, or a frame validateFrame rejects), the
    // peer's session-derivation promise must reject so any waiting
    // sendInner doesn't hang forever. This is the cousin of the
    // "host closes" rejection — both unblock the awaiter.
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);

    wss = loopbackWss();
    const port = await listenEphemeral(wss);
    wss.on('connection', (ws: WebSocket) => {
      ws.once('message', () => {
        // Receive the peer's hello, then push garbage that JSON.parse
        // would barely choke on (validateFrame definitely will).
        ws.send('this-is-not-json');
      });
    });

    peer = await startPeer({
      host: '127.0.0.1',
      port,
      identity,
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
    });

    await expect(peer.sendInner({ type: 'ping' })).rejects.toThrow();
  });

  it('sendInner rejects if the host WS closes before ready arrives', async () => {
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);

    wss = loopbackWss();
    const port = await listenEphemeral(wss);
    // Host that takes the hello and then immediately closes — never sends ready.
    wss.on('connection', (ws: WebSocket) => {
      ws.once('message', () => ws.close());
    });

    peer = await startPeer({
      host: '127.0.0.1',
      port,
      identity,
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
    });

    await expect(peer.sendInner({ type: 'ping' })).rejects.toThrow(
      /peer WS closed before ready/,
    );
  });

  it('fires onClose listeners when the host WS closes', async () => {
    // The peer needs to tell its owner (FetchproxyServer) when the host
    // vanished so the owner can tear down the stranded handle and re-elect.
    // peer.ts is intent-agnostic: it fires onClose on ANY ws close.
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);

    wss = loopbackWss();
    const port = await listenEphemeral(wss);
    // Host accepts the hello, then closes — simulates the host dying.
    wss.on('connection', (ws: WebSocket) => {
      ws.once('message', () => ws.close());
    });

    peer = await startPeer({
      host: '127.0.0.1',
      port,
      identity,
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
    });

    const closed = new Promise<void>((resolve) => peer!.onClose(() => resolve()));
    await expect(closed).resolves.toBeUndefined();
  });

  it('routes a targeted ok:false through onInner for a frame that decrypts fine but fails validation — instead of silently dropping it or closing the connection', async () => {
    // Regression for the peer-side half of the "kill the whole bridge" bug
    // class: before this fix, peer.ts's openEncryptedFrame call had ONE
    // catch that treated a decrypt failure (stale key — genuinely nothing
    // recoverable) and a post-decrypt VALIDATION failure (e.g. the
    // download bytes:-1 class of bug — a real protocol bug from a source
    // decryption just proved is the CURRENT, legitimate host) identically:
    // silently dropped, with no diagnostic signal and no fast failure for
    // whichever pending call was awaiting that response's id. This test
    // drives a REAL handshake so the frame actually decrypts under the
    // correct session key, then sends a validation-failing payload and
    // asserts it surfaces as a targeted ok:false via onInner — and that a
    // subsequent valid frame still gets delivered normally afterward.
    //
    // 3.0.0: the handshake is now the full v4 one, because there is no
    // shorter route to a real session key. A placeholder signature and no
    // relayed extension hello used to be enough — the peer warned and
    // proceeded — and under v4 the extension's nonce is IN the HKDF salt, so
    // a peer that was never told about the browser can derive nothing.
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);
    const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';
    const enc = new TextEncoder();

    const rig = await startFakeConcentrator();
    const ext = await newFakeExtension();
    peer = await startPeer({
      host: '127.0.0.1',
      port: rig.port,
      identity,
      mcpId,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domains: ['opentable.com'],
      extensionTrust: memoryTrust(),
    });

    const received: unknown[] = [];
    peer.onInner((inner) => received.push(inner));

    await rig.waitForHello();
    await rig.relayExtensionHello(ext);
    const sessionHello = await rig.waitForHello(1);
    const sessionKey = await rig.answerReady(ext, sessionHello);

    // Confirms the session is established (sendInner awaits session-ready
    // internally) before we start sending frames the peer must decrypt.
    await peer.sendInner({ type: 'ping' });
    expect(peer.sessionLinked()).toBe(true);
    expect(peer.extensionConnected()).toBe(true);

    // Send a frame that DECRYPTS FINE (real, current session key) but whose
    // plaintext fails schema validation — the download bytes:-1 class of
    // bug, reused here as a concrete, realistic example.
    const malformed = JSON.stringify({
      type: 'response',
      id: 77,
      ok: true,
      op: 'download',
      value: { path: '/tmp/streamed.bin', bytes: -1 },
    });
    const iv1 = new Uint8Array(12).fill(1);
    // 3.0.0: the AAD binds a frame to `(mcpId, seq, direction)`, so one
    // sealed for the wrong id, ordinal or direction fails the TAG rather than
    // reaching the validator. 'e2s' is what a frame from the extension is.
    const ct1 = await aesGcmSeal(sessionKey, iv1, enc.encode(malformed), frameAad(mcpId, 1, 'e2s'));
    await rig.send({
      type: 'frame',
      mcpId,
      seq: 1,
      iv: Buffer.from(iv1).toString('base64'),
      ciphertext: Buffer.from(ct1).toString('base64'),
    });

    await vi.waitFor(() => expect(received).toHaveLength(1));
    expect(received[0]).toMatchObject({ type: 'response', id: 77, ok: false });
    expect((received[0] as { error: string }).error).toContain('protocol validation');

    // The connection must still be alive: a subsequent VALID frame should
    // be delivered normally, proving this degraded gracefully rather than
    // tearing down the session.
    const iv2 = new Uint8Array(12).fill(2);
    const validInner = JSON.stringify({
      type: 'response',
      id: 88,
      ok: true,
      status: 200,
      url: 'https://opentable.com/x',
      body: 'still alive',
    });
    const ct2 = await aesGcmSeal(
      sessionKey,
      iv2,
      enc.encode(validInner),
      frameAad(mcpId, 2, 'e2s'),
    );
    await rig.send({
      type: 'frame',
      mcpId,
      seq: 2,
      iv: Buffer.from(iv2).toString('base64'),
      ciphertext: Buffer.from(ct2).toString('base64'),
    });

    await vi.waitFor(() => expect(received).toHaveLength(2));
    expect(received[1]).toMatchObject({ type: 'response', id: 88, ok: true, status: 200 });

    // 2.5.0: the host says the extension left — both go back to false, and
    // stay there until the extension is seen again. The session key is
    // kept (sendInner's invariant), only the report changes.
    // M1: the peer surfaces only the code it derived itself, so a frame must
    // carry that number — one of its own would be an alarm and a closed
    // upstream. 3.0.0 (protocol 4): derived from the pair transcript, which
    // includes the hello THIS peer minted in answer to the relayed one.
    const pairCode = await pairTranscript(
      identity.x25519Pub,
      fromB64(ext.hello.identityX25519Pub),
      fromB64(sessionHello.sessionNonce),
      fromB64(ext.hello.sessionNonce),
      fromB64(sessionHello.sessionPub),
    );
    await rig.send({ type: 'pair-pending', mcpId, pairCode });
    await vi.waitFor(() => expect(peer!.pendingPairCode()).toBe(pairCode));
    await rig.relayExtensionDisconnected();
    await vi.waitFor(() => expect(peer!.extensionConnected()).toBe(false));
    expect(peer.sessionLinked()).toBe(false);
    // #283: a code nobody can approve any more goes with the extension.
    expect(peer.pendingPairCode()).toBeNull();
    // It comes back: the host relays the new extension hello, the peer mints
    // and hellos again, and THAT hello's ready re-links. Under v3 this was
    // "the host replays our hello"; that path is gone.
    // The SAME browser, a fresh connection nonce — which is what an MV3
    // eviction is. A different identity here would be correctly refused by
    // the pin this peer wrote during the first handshake.
    const ext2 = await newFakeExtension(ext);
    await rig.relayExtensionHello(ext2);
    const reHello = await rig.waitForHello(2);
    await rig.answerReady(ext2, reHello);
    await vi.waitFor(() => expect(peer!.sessionLinked()).toBe(true));
    expect(peer.extensionConnected()).toBe(true);
    peer.close();
    peer = null;
    await rig.close();
  });
});

/**
 * Task 2.2 — the peer's two keypairs (protocol v4, §1a).
 *
 * The peer's "connection" is not a socket, so "per extension connection" has
 * nothing to hang on here: its one socket goes to the host and outlives every
 * extension session. It therefore holds TWO keypairs with different jobs — a
 * BOOTSTRAP one that only ever signs the registration hello, and a SESSION
 * ephemeral minted when a relayed extension hello arrives — and every
 * assertion below is about keeping those apart.
 */
describe('peer: a bootstrap keypair and a session ephemeral (v4)', () => {
  const MCP_ID = 'resy-mcp:0.9.1:a3f7c91d2e8b4f56';
  let hostRig: Awaited<ReturnType<typeof startFakeConcentrator>> | null = null;
  let peerHandle: InternalPeerHandle | null = null;

  afterEach(async () => {
    if (peerHandle) peerHandle.close();
    peerHandle = null;
    if (hostRig) await hostRig.close();
    hostRig = null;
  });

  async function startTestPeer(
    extra: Partial<Parameters<typeof startPeer>[0]> = {},
  ): Promise<{ rig: NonNullable<typeof hostRig>; peer: InternalPeerHandle }> {
    const rig = await startFakeConcentrator();
    hostRig = rig;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-peer-v4-'));
    const identity = await loadOrCreateIdentity('resy-mcp', idDir);
    const p = await startPeer({
      host: '127.0.0.1',
      port: rig.port,
      identity,
      mcpId: MCP_ID,
      serverName: 'resy-mcp',
      version: '0.9.1',
      domains: ['resy.com'],
      extensionTrust: memoryTrust(),
      ...extra,
    });
    peerHandle = p;
    return { rig, peer: p };
  }

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

  it('registers with a bootstrap ephemeral that says it answers nothing', async () => {
    const { rig } = await startTestPeer();
    const registration = await rig.waitForHello();
    // A peer cannot wait for an extension hello before it hellos — the hello
    // is what REGISTERS it, and the host relays extension hellos only to
    // peers already in its map. So the registration hello must carry a
    // `sessionPub`, and saying it answers nothing on the wire is what makes
    // the frame self-describing rather than merely un-forwarded by convention.
    expect(answersNoExtSession(registration.answersExtNonce)).toBe(true);
    expect(fromB64(registration.sessionPub).length).toBe(32);
    // And the signature covers both new fields, or a relay substitutes the
    // ephemeral and re-points the echo.
    expect(
      await ed25519Verify(
        fromB64(registration.identityEd25519Pub),
        helloSignaturePayload(
          MCP_ID,
          fromB64(registration.sessionNonce),
          fromB64(registration.sessionPub),
          fromB64(registration.answersExtNonce),
        ),
        fromB64(registration.sessionSig),
      ),
    ).toBe(true);
  });

  it('mints a fresh session ephemeral per relayed extension hello and echoes its nonce', async () => {
    const { rig } = await startTestPeer();
    const registration = await rig.waitForHello();
    const ext1 = await newFakeExtension();

    await rig.relayExtensionHello(ext1);
    const first = await rig.waitForHello(1);
    expect(first.answersExtNonce).toBe(ext1.hello.sessionNonce);
    expect(first.sessionPub).not.toBe(registration.sessionPub);
    expect(first.sessionNonce).not.toBe(registration.sessionNonce);

    await rig.relayExtensionDisconnected();
    const ext2 = await newFakeExtension(ext1);
    await rig.relayExtensionHello(ext2);
    const second = await rig.waitForHello(2);
    expect(second.answersExtNonce).toBe(ext2.hello.sessionNonce);
    expect(second.sessionPub).not.toBe(first.sessionPub);
    expect(second.sessionNonce).not.toBe(first.sessionNonce);
  });

  it('derives the key the extension derives, against the ephemeral it just minted', async () => {
    const { rig, peer: p } = await startTestPeer();
    await rig.waitForHello();
    const ext = await newFakeExtension();
    await rig.relayExtensionHello(ext);
    const hello = await rig.waitForHello(1);
    const key = await rig.answerReady(ext, hello);
    // `sendInner` awaits the first ready, so this both proves the session
    // opened and hands us a frame sealed under the peer's key.
    await p.sendInner({ type: 'ping' });
    const sealed = await rig.waitForFrames(1);
    expect(sealed.length).toBe(1);
    const inner = await openEncryptedFrame(key, sealed[0] as unknown as EncryptedFrame, 's2e');
    expect(inner.type).toBe('ping');
  });

  it('zeroes the bootstrap half at the first committing mint, and the session half on every event that ends the session', async () => {
    const minted: { publicKey: Uint8Array; privateKey: Uint8Array }[] = [];
    const { rig } = await startTestPeer({
      generateSessionKeypair: async () => {
        const kp = await generateX25519();
        minted.push(kp);
        return kp;
      },
    });
    await rig.waitForHello();
    // The bootstrap keypair is mint #1 and derives nothing, ever.
    expect(minted.length).toBe(1);
    const bootstrap = minted[0]!;
    expect(bootstrap.privateKey.some((b) => b !== 0)).toBe(true);

    const ext1 = await newFakeExtension();
    await rig.relayExtensionHello(ext1);
    await rig.waitForHello(1);
    expect(minted.length).toBe(2);
    // It is a registration credential, so it dies at the first session mint
    // that COMMITS — not at the peer's exit, and not never.
    expect(bootstrap.privateKey.every((b) => b === 0)).toBe(true);

    await rig.relayExtensionDisconnected();
    await new Promise((r) => setTimeout(r, 50));
    expect(minted[1]!.privateKey.every((b) => b === 0)).toBe(true);

    // And the session half that is live when the peer's own socket to the
    // host closes goes too — a teardown obligation rather than part of §1a's
    // invariant, since that socket is not the extension's.
    const ext2 = await newFakeExtension(ext1);
    await rig.relayExtensionHello(ext2);
    await rig.waitForHello(2);
    expect(minted.length).toBe(3);
    expect(minted[2]!.privateKey.some((b) => b !== 0)).toBe(true);
    peerHandle!.close();
    await new Promise((r) => setTimeout(r, 80));
    expect(minted[2]!.privateKey.every((b) => b === 0)).toBe(true);
  });

  it('zeroes the bootstrap half at its own socket close when no session mint ever commits', async () => {
    // The peer that dials, is never told an extension exists, and exits. §1a
    // gives the bootstrap half two deaths — "at the first session mint that
    // COMMITS, or at the peer socket's close if none ever does" — and the
    // test above can only reach the first, because there the bootstrap has
    // already died to the winning mint before the close arrives.
    //
    // No key is ever derived from this half by construction (the frame
    // carrying it says it answers nothing, Rule B refuses to forward it, so
    // no `ready` can name it), so what is at stake is the teardown
    // obligation rather than a decryptable session — which is exactly why
    // nothing else would ever report its absence.
    const minted: { publicKey: Uint8Array; privateKey: Uint8Array }[] = [];
    const { rig } = await startTestPeer({
      generateSessionKeypair: async () => {
        const kp = await generateX25519();
        minted.push(kp);
        return kp;
      },
    });
    await rig.waitForHello();
    // One mint, and it is the bootstrap: no extension hello is ever relayed.
    expect(minted.length).toBe(1);
    expect(minted[0]!.privateKey.some((b) => b !== 0)).toBe(true);

    peerHandle!.close();
    await new Promise((r) => setTimeout(r, 80));
    expect(minted.length).toBe(1);
    expect(minted[0]!.privateKey.every((b) => b === 0)).toBe(true);
  });

  it('never warns-and-proceeds when no extension hello has been relayed', async () => {
    // The `warnedUnverifiable` branch cannot survive v4: the transcript salt
    // contains the EXTENSION's nonce, and that arrives only on the relayed
    // hello, so a peer that was never told about the browser has nothing to
    // derive from. Two shapes reach a peer from such a host, and neither may
    // open a session.
    const { rig, peer: p } = await startTestPeer();
    const registration = await rig.waitForHello();
    const ext = await newFakeExtension();

    // (1) A v4-shaped `ready` naming the BOOTSTRAP ephemeral — what a host
    // with no Rule B gate would let the extension answer. Rule C discards it:
    // this peer holds no SESSION ephemeral at all, so there is nothing it
    // could match, and the bootstrap half is not a candidate by construction.
    await rig.answerReady(ext, registration);
    await new Promise((r) => setTimeout(r, 60));
    expect(p.sessionLinked()).toBe(false);
    expect((await rig.socket()).readyState).toBe(WebSocket.OPEN);

    // (2) A pre-3.0.0 `ready`, with no `mcpSessionPub` at all — what a v3
    // extension behind a v3 host sends. It fails the validator, which fails
    // this peer's wait with a reason rather than leaving it to time out. The
    // v3 code accepted such a frame, warned, and derived a session from a
    // long-term key.
    const pending = p.sendInner({ type: 'ping' });
    await rig.send({
      type: 'ready',
      mcpId: MCP_ID,
      extensionSessionPub: registration.sessionPub,
      sessionSig: toB64(new Uint8Array(64).fill(1)),
    });
    await expect(pending).rejects.toThrow();
    expect(p.sessionLinked()).toBe(false);
  });

  it('discards a ready for a superseded ephemeral and refuses a bad signature for the current one (Rule C)', async () => {
    // Both outcomes, in one file, because they are one branch: a test of
    // either alone passes on the pre-Rule-C code, where a stale `ready` and
    // a forged one were the same 1008 plus `rejectFirstReady` — an MV3
    // eviction reported as a security failure.
    const { rig, peer: p } = await startTestPeer();
    await rig.waitForHello();
    const ext1 = await newFakeExtension();
    await rig.relayExtensionHello(ext1);
    const staleHello = await rig.waitForHello(1);

    await rig.relayExtensionDisconnected();
    const ext2 = await newFakeExtension(ext1);
    await rig.relayExtensionHello(ext2);
    const liveHello = await rig.waitForHello(2);

    const sending = p.sendInner({ type: 'ping' });
    // Genuinely signed by the pinned browser, naming an ephemeral this peer
    // has already zeroed.
    await rig.answerReady(ext2, staleHello);
    await new Promise((r) => setTimeout(r, 60));
    expect((await rig.socket()).readyState).toBe(WebSocket.OPEN);
    expect(p.sessionLinked()).toBe(false);
    expect(await stillPending(sending)).toBe(true);

    // The genuine one still opens the session.
    const key = await rig.answerReady(ext2, liveHello);
    await sending;
    const sealed = await rig.waitForFrames(1);
    expect(sealed.length).toBe(1);
    expect(
      (await openEncryptedFrame(key, sealed[0] as unknown as EncryptedFrame, 's2e')).type,
    ).toBe('ping');

    // The other outcome: naming the CURRENT ephemeral with a signature that
    // does not verify is still a 1008 and still fails the peer's wait.
    const closed = new Promise<number>((resolve) => {
      (peerHandle as InternalPeerHandle).ws.once('close', (code: number) => resolve(code));
    });
    await rig.answerReady(ext2, liveHello, { forgeSignature: true });
    expect(await closed).toBe(1008);
  });

  it('does not install a session whose ephemeral was superseded mid-derivation', async () => {
    // The mirror of Rule D, one handshake later: the `ready` handler awaits
    // `authenticateExtension` and two crypto calls, and a Rule A mint can
    // COMMIT inside that window — which zeroes the private half the
    // derivation is using, so the key comes out of a scrubbed scalar.
    //
    // Driven by holding the extension-pin READ, which is the first await in
    // `authenticateExtension` and happens once per peer. Without the guard
    // the dead session is installed over the live one and the first-ready
    // promise resolves with it, so the assertion has to be POSITIVE — the
    // session that opens is E2's — rather than "nothing bad happened".
    let releaseRead: (() => void) | null = null;
    const readHeld = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    let reads = 0;
    const { rig, peer: p } = await startTestPeer({
      extensionTrust: {
        allowNew: false,
        read: async () => {
          if (++reads === 1) await readHeld;
          return null;
        },
        write: async () => undefined,
      },
    });
    await rig.waitForHello();

    const ext1 = await newFakeExtension();
    await rig.relayExtensionHello(ext1);
    const first = await rig.waitForHello(1);
    // A genuine ready for the ephemeral the peer currently holds: Rule C
    // passes and the handler suspends inside the held pin read.
    await rig.answerReady(ext1, first);
    await new Promise((r) => setTimeout(r, 50));
    expect(reads).toBe(1);

    // A new extension session lands and its mint commits, zeroing the half
    // the suspended derivation is holding.
    const ext2 = await newFakeExtension(ext1);
    await rig.relayExtensionHello(ext2);
    const second = await rig.waitForHello(2);
    expect(second.sessionPub).not.toBe(first.sessionPub);

    releaseRead!();
    await new Promise((r) => setTimeout(r, 60));
    expect(p.sessionLinked()).toBe(false);

    // E2's ready opens the session, and the key it opens is the live one.
    const key = await rig.answerReady(ext2, second);
    await p.sendInner({ type: 'ping' });
    const sealed = await rig.waitForFrames(1);
    expect(
      (await openEncryptedFrame(key, sealed[0] as unknown as EncryptedFrame, 's2e')).type,
    ).toBe('ping');
  });

  it('derives against the extension hello the ready ANSWERS, not one that landed mid-derivation', async () => {
    // The test above drives the window in which E2's mint has COMMITTED, so
    // the `sessionEphemeral !== held` guard catches it. This one drives the
    // window one step earlier, which that guard cannot see: E2's relayed
    // hello has LANDED — `extensionHello` is reassigned synchronously, before
    // the mint's first await — while its mint is still inside
    // `generateSessionKeypair`, so `sessionEphemeral` is still E1's and the
    // guard passes.
    //
    // Every value the ready branch reads must therefore be the one captured
    // at Rule C rather than re-read off the mutable binding afterwards. The
    // ready's signature is verified against E1's nonce (the payload is built
    // synchronously on entry), so a salt carrying E2's nonce derives a key
    // the browser does not hold — and does it SILENTLY: the session installs
    // and the first-ready promise resolves. Hence a POSITIVE assertion — the
    // frame the peer seals must open under the key E1's extension derived —
    // rather than "nothing bad was sent".
    let releaseRead: (() => void) | null = null;
    const readHeld = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    let reads = 0;
    let releaseMint: (() => void) | null = null;
    const mintHeld = new Promise<void>((resolve) => {
      releaseMint = resolve;
    });
    let mints = 0;
    const { rig, peer: p } = await startTestPeer({
      generateSessionKeypair: async () => {
        // 1 = the bootstrap, 2 = E1's mint, 3 = E2's — held, so E2's hello
        // is in hand while its ephemeral is not.
        if (++mints === 3) await mintHeld;
        return generateX25519();
      },
      extensionTrust: {
        allowNew: false,
        read: async () => {
          if (++reads === 1) await readHeld;
          return null;
        },
        write: async () => undefined,
      },
    });
    await rig.waitForHello();

    const ext1 = await newFakeExtension();
    await rig.relayExtensionHello(ext1);
    const first = await rig.waitForHello(1);
    // Genuine, for the ephemeral the peer holds: Rule C passes and the
    // handler suspends inside the held pin read.
    const key1 = await rig.answerReady(ext1, first);
    await vi.waitFor(() => expect(reads).toBe(1));

    const ext2 = await newFakeExtension(ext1);
    await rig.relayExtensionHello(ext2);
    await new Promise((r) => setTimeout(r, 50));
    // Two hellos, not three: E2's mint is held, so nothing has committed and
    // the peer still holds E1's ephemeral. That is the window.
    expect(rig.hellos().length).toBe(2);

    releaseRead!();
    await vi.waitFor(() => expect(p.sessionLinked()).toBe(true));
    await p.sendInner({ type: 'ping' });
    const sealed = await rig.waitForFrames(1);
    expect(
      (await openEncryptedFrame(key1, sealed[0] as unknown as EncryptedFrame, 's2e')).type,
    ).toBe('ping');
    releaseMint!();
  });

  it('drops the session cleanly when the extension leaves mid-derivation, rather than faulting on it', async () => {
    // The other shape of the same read-after-await, and the one TypeScript
    // actively hides: `extensionHello` is narrowed non-null by a check at the
    // top of `authenticateExtension` and the narrowing is NOT reset across
    // the awaits below it, so a read after the pin fetch compiles as
    // non-nullable and is `null` at runtime the moment an
    // `extension-disconnected` lands in that window. Reading it inside
    // `decideExtensionTrust` then faulted the handler, and `onMessage`'s
    // catch turns any throw into `rejectFirstReady` — so an ordinary browser
    // disconnect failed the caller's pending call with a TypeError instead of
    // being the supersession drop it is.
    let releaseRead: (() => void) | null = null;
    const readHeld = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    let reads = 0;
    const ext1 = await newFakeExtension();
    const { rig, peer: p } = await startTestPeer({
      // A PIN, deliberately: with none, `decideExtensionTrust` answers
      // `first-use` before it looks at the hello at all, and the fault this
      // pins needs the comparison to be reached.
      extensionTrust: {
        allowNew: false,
        read: async () => {
          if (++reads === 1) await readHeld;
          return ext1.pin();
        },
        write: async () => undefined,
      },
    });
    await rig.waitForHello();
    await rig.relayExtensionHello(ext1);
    const first = await rig.waitForHello(1);

    const sending = p.sendInner({ type: 'ping' });
    await rig.answerReady(ext1, first);
    await vi.waitFor(() => expect(reads).toBe(1));
    await rig.relayExtensionDisconnected();
    // Wait for the peer to have PROCESSED it before releasing the read:
    // `extensionConnected()` is exactly `extensionHello !== null`, so this is
    // the window the fault lives in. Releasing without it lands the notice
    // during the ECDH instead, where the trust decision has already been
    // taken and the read-after-await is invisible.
    await vi.waitFor(() => expect(p.extensionConnected()).toBe(false));
    releaseRead!();
    await new Promise((r) => setTimeout(r, 60));

    // No session, no fault: the caller's call is still waiting for one rather
    // than having been failed with whatever the handler threw.
    expect(p.sessionLinked()).toBe(false);
    expect(await stillPending(sending)).toBe(true);
    expect((await rig.socket()).readyState).toBe(WebSocket.OPEN);

    // And the next extension session opens normally, which is what makes
    // "dropped" different from "wedged".
    const ext2 = await newFakeExtension(ext1);
    await rig.relayExtensionHello(ext2);
    const second = await rig.waitForHello(2);
    const key = await rig.answerReady(ext2, second);
    await sending;
    const sealed = await rig.waitForFrames(1);
    expect(
      (await openEncryptedFrame(key, sealed[0] as unknown as EncryptedFrame, 's2e')).type,
    ).toBe('ping');
  });

  it('lets the newer mint win when an older one resolves late, for both shapes of mismatch (Rule D)', async () => {
    // Driven AT THE PEER, because the whole of Rule D is inside the peer
    // process: `onMessage` is async and nothing awaits the promise
    // `ws.on('message', onMessage)` returns, so two of one peer's mints can
    // be in flight and install in whatever order their crypto resolved.
    for (const shape of ['disconnected', 'newer-hello'] as const) {
      const minted: { publicKey: Uint8Array; privateKey: Uint8Array }[] = [];
      let releaseHeld: (() => void) | null = null;
      const held = new Promise<void>((resolve) => {
        releaseHeld = resolve;
      });
      let calls = 0;
      const { rig, peer: p } = await startTestPeer({
        generateSessionKeypair: async () => {
          const kp = await generateX25519();
          minted.push(kp);
          // Call 1 is the bootstrap; call 2 is E1's session mint, held.
          if (++calls === 2) await held;
          return kp;
        },
      });
      await rig.waitForHello();

      const ext1 = await newFakeExtension();
      await rig.relayExtensionHello(ext1);
      await new Promise((r) => setTimeout(r, 50));
      expect(minted.length).toBe(2);
      expect(rig.hellos().length).toBe(1); // E1's mint is stuck inside the mint

      const ext2 = await newFakeExtension(ext1);
      if (shape === 'disconnected') await rig.relayExtensionDisconnected();
      await rig.relayExtensionHello(ext2);
      const liveHello = await rig.waitForHello(1);
      expect(minted.length).toBe(3);

      // Release E1's mint. It must zero its own half, assign nothing and
      // send nothing: the hello it would send is one Rule B refuses to
      // forward anyway, but the ASSIGNMENT is the bug.
      releaseHeld!();
      await new Promise((r) => setTimeout(r, 100));
      expect(minted[1]!.privateKey.every((b) => b === 0)).toBe(true);
      expect(rig.hellos().length).toBe(2);

      // The assertion that actually fails on the bug, and it has to be
      // POSITIVE: without Rule D the late mint has overwritten E2's, Rule C
      // discards the one legitimate `ready`, and the failure is a HANG
      // rather than an error.
      const key = await rig.answerReady(ext2, liveHello);
      await p.sendInner({ type: 'ping' });
      const sealed = await rig.waitForFrames(1);
      expect(sealed.length).toBe(1);
      expect(
        (await openEncryptedFrame(key, sealed[0] as unknown as EncryptedFrame, 's2e')).type,
      ).toBe('ping');

      peerHandle!.close();
      peerHandle = null;
      await rig.close();
      hostRig = null;
    }
  });
});
