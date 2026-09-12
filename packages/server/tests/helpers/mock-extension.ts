import { WebSocket } from 'ws';
import {
  ecdhX25519,
  ed25519Sign,
  generateEd25519,
  generateX25519,
  hkdfSha256,
  readySignaturePayload,
  transcriptHash,
  validateFrame,
  fromB64,
  toB64,
  HKDF_SESSION_INFO,
  PROTOCOL_VERSION,
  type HelloFrameFromExtension,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import type { ExtensionPin } from '../../src/extension-trust.js';

const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');

/**
 * One server hello this mock saw, with the v4 fields already decoded.
 *
 * Recorded as a LIST per mcpId rather than a latest-wins slot, because v4's
 * whole staleness story is about a second hello arriving for the same id: a
 * test has to be able to answer the FIRST one on purpose (that is what a
 * `ready` for a superseded ephemeral is) and to assert how many arrived.
 */
export interface ServerHelloSeen {
  frame: HelloFrameFromServer;
  sessionNonce: Uint8Array;
  sessionPub: Uint8Array;
  /** b64, as it arrived — so a test can compare it to an extension nonce. */
  answersExtNonce: string;
}

export interface MockExtension {
  ws: WebSocket;
  hello: HelloFrameFromExtension;
  /** This extension's own hello nonce, raw. */
  sessionNonce: Uint8Array;
  /** The pin this extension's hello would produce. */
  pin(pinnedAt?: number): ExtensionPin;
  /** Every server hello seen for `mcpId`, oldest first. */
  serverHellosFor(mcpId: string): ServerHelloSeen[];
  /** Every frame of any type seen for `mcpId` (hellos included). */
  framesFor(mcpId: string): Record<string, unknown>[];
  /**
   * Wait until at least `nth + 1` server hellos have arrived for `mcpId`, then
   * return the `nth` (default: the first).
   */
  waitForServerHello(mcpId: string, nth?: number): Promise<ServerHelloSeen>;
  /**
   * Answer one specific server hello with a `ready`, exactly as the browser
   * does under v4: ECDH of a fresh ephemeral against THAT hello's `sessionPub`,
   * HKDF salted with `transcriptHash`, and the signature over all four fields.
   *
   * Resolves with the AES-256-GCM key the two sides just agreed, so a test can
   * seal a frame the server will really open. Meaningless under
   * `forgeSignature`, where no session is derived.
   */
  answerReady(
    seen: ServerHelloSeen,
    opts?: {
      /** Send a signature that cannot verify. */
      forgeSignature?: boolean;
      /**
       * Sign the v3 payload — the same three fields without `mcpSessionPub` —
       * while still carrying the field on the wire. A v4 verifier must refuse
       * it, which is the assertion that the widening actually reached the
       * verifier rather than only the producer.
       */
      omitMcpSessionPubFromSignature?: boolean;
    },
  ): Promise<Uint8Array>;
  /**
   * Wait for the first server hello for `mcpId` and answer it. The common
   * case, and the shape every pre-v4 caller of this helper already used.
   */
  completeHandshake(mcpId: string, opts?: { forgeSignature?: boolean }): Promise<Uint8Array>;
  closed(): Promise<{ code: number; reason: string }>;
  close(): void;
}

/**
 * A mock extension that holds a REAL identity and signs the ready frame the
 * way the browser does. Tests about pinning have to use real keys: the whole
 * question is whether the MCP recognises the same identity twice and refuses a
 * different one, which a stub with fixed base64 could not exercise.
 */
export async function connectMockExtension(
  port: number,
  identity?: { x25519: CryptoKeyPairRaw; ed25519: CryptoKeyPairRaw },
): Promise<MockExtension> {
  const x = identity?.x25519 ?? (await generateX25519());
  const ed = identity?.ed25519 ?? (await generateEd25519());
  const sessionNonce = new Uint8Array(32);
  crypto.getRandomValues(sessionNonce);

  const hello: HelloFrameFromExtension = {
    type: 'hello',
    protocolVersion: PROTOCOL_VERSION,
    role: 'extension',
    platform: 'chrome',
    extensionId: 'fetchproxy',
    version: '3.0.0',
    identityX25519Pub: b64(x.publicKey),
    identityEd25519Pub: b64(ed.publicKey),
    sessionNonce: b64(sessionNonce),
  };

  const ws = new WebSocket(`ws://127.0.0.1:${port}`);
  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });
  // A refused extension gets its socket closed under it; without this the
  // EPIPE surfaces as an unhandled 'error' event and fails the run.
  ws.on('error', () => {
    /* expected on refusal */
  });

  // A close is LATCHED rather than waited for from wherever the caller happens
  // to be. `closed()` used to attach the listener on the spot, so a refusal
  // that had already arrived — the host answers a forged `ready` by closing
  // 1008 immediately, and the caller has awaited two crypto operations since
  // sending it — woke nobody and the case sat there until the test timed out.
  let closeSeen: { code: number; reason: string } | null = null;
  const closeWaiters: ((r: { code: number; reason: string }) => void)[] = [];
  ws.on('close', (code: number, reason: Buffer) => {
    closeSeen = { code, reason: reason.toString() };
    for (const wake of closeWaiters.splice(0)) wake(closeSeen);
  });

  const serverHellos = new Map<string, ServerHelloSeen[]>();
  const frames = new Map<string, Record<string, unknown>[]>();
  // Keyed by mcpId, because a concentrator announces every MCP on one socket.
  // Draining a flat list on each hello woke waiters for OTHER ids and dropped
  // them, so a caller waiting on two MCPs only ever settled by timing out —
  // harmless with today's single-id callers, and a trap for the next one.
  const helloWaiters = new Map<string, (() => void)[]>();
  ws.on('message', (data) => {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(data.toString()) as Record<string, unknown>;
    } catch {
      return;
    }
    const id = typeof parsed.mcpId === 'string' ? parsed.mcpId : null;
    if (id !== null) frames.set(id, [...(frames.get(id) ?? []), parsed]);
    try {
      const frame = validateFrame(parsed);
      if (frame.type === 'hello' && frame.role === 'server') {
        const list = serverHellos.get(frame.mcpId) ?? [];
        list.push({
          frame,
          sessionNonce: fromB64(frame.sessionNonce),
          sessionPub: fromB64(frame.sessionPub),
          answersExtNonce: frame.answersExtNonce,
        });
        serverHellos.set(frame.mcpId, list);
        for (const wake of helloWaiters.get(frame.mcpId) ?? []) wake();
        helloWaiters.delete(frame.mcpId);
      }
    } catch {
      /* ignore */
    }
  });

  const waitForServerHello = async (mcpId: string, nth = 0): Promise<ServerHelloSeen> => {
    for (;;) {
      const seen = serverHellos.get(mcpId) ?? [];
      if (seen.length > nth) return seen[nth]!;
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error(`no server hello #${nth} for ${mcpId}`)),
          5_000,
        );
        const waiting = helloWaiters.get(mcpId) ?? [];
        waiting.push(() => {
          clearTimeout(timer);
          resolve();
        });
        helloWaiters.set(mcpId, waiting);
      });
    }
  };

  ws.send(JSON.stringify(hello));

  const answerReady: MockExtension['answerReady'] = async (seen, opts = {}) => {
    const eph = await generateX25519();
    const payload = opts.omitMcpSessionPubFromSignature
      ? // The v3 payload: the same three fields, with no MCP ephemeral at all.
        readySignaturePayload(seen.sessionNonce, sessionNonce, eph.publicKey, new Uint8Array(0))
      : readySignaturePayload(seen.sessionNonce, sessionNonce, eph.publicKey, seen.sessionPub);
    const sig = opts.forgeSignature
      ? new Uint8Array(64).fill(9)
      : await ed25519Sign(ed.privateKey, payload);
    ws.send(
      JSON.stringify({
        type: 'ready',
        mcpId: seen.frame.mcpId,
        extensionSessionPub: b64(eph.publicKey),
        mcpSessionPub: toB64(seen.sessionPub),
        sessionSig: b64(sig),
      }),
    );
    // v4: ephemeral × ephemeral, salted with the transcript over both nonces
    // and both ephemerals. The identity key is no longer in the ECDH at all.
    const shared = await ecdhX25519(eph.privateKey, seen.sessionPub);
    const salt = await transcriptHash(
      seen.sessionNonce,
      sessionNonce,
      seen.sessionPub,
      eph.publicKey,
    );
    return hkdfSha256(shared, salt, new TextEncoder().encode(HKDF_SESSION_INFO), 32);
  };

  return {
    ws,
    hello,
    sessionNonce,
    pin: (pinnedAt = 1_700_000_000_000) => ({
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
      pinnedAt,
    }),
    serverHellosFor: (mcpId) => [...(serverHellos.get(mcpId) ?? [])],
    framesFor: (mcpId) => [...(frames.get(mcpId) ?? [])],
    waitForServerHello,
    answerReady,
    completeHandshake: async (mcpId, opts = {}) =>
      answerReady(await waitForServerHello(mcpId), opts),
    closed: () =>
      closeSeen ? Promise.resolve(closeSeen) : new Promise((resolve) => closeWaiters.push(resolve)),
    close: () => ws.close(),
  };
}

export interface CryptoKeyPairRaw {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/** A stable identity, so two connections can be the "same browser". */
export async function newExtensionIdentity(): Promise<{
  x25519: CryptoKeyPairRaw;
  ed25519: CryptoKeyPairRaw;
}> {
  return { x25519: await generateX25519(), ed25519: await generateEd25519() };
}
