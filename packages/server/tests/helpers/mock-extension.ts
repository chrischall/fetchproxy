import { WebSocket } from 'ws';
import {
  ecdhX25519,
  ed25519Sign,
  generateEd25519,
  generateX25519,
  hkdfSha256,
  readySignaturePayload,
  validateFrame,
  HKDF_SESSION_INFO,
  type HelloFrameFromExtension,
} from '@fetchproxy/protocol';
import type { ExtensionPin } from '../../src/extension-trust.js';

const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');

export interface MockExtension {
  ws: WebSocket;
  hello: HelloFrameFromExtension;
  /** The pin this extension's hello would produce. */
  pin(pinnedAt?: number): ExtensionPin;
  /**
   * Wait for the server hello for `mcpId`, then answer with a signed ready.
   *
   * Resolves with the AES-256-GCM session key the two sides just agreed —
   * derived exactly as the browser derives it (ECDH of this ready's ephemeral
   * private key against the MCP's identity X25519 pub, salted with the MCP's
   * own session nonce) — so a test can seal a frame the host will really
   * open. Meaningless under `forgeSignature`, where no session is derived.
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
    protocolVersion: 3,
    role: 'extension',
    platform: 'chrome',
    extensionId: 'fetchproxy',
    version: '1.11.0',
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

  const serverHellos = new Map<string, { sessionNonce: string; identityX25519Pub: string }>();
  // Keyed by mcpId, because a concentrator announces every MCP on one socket.
  // Draining a flat list on each hello woke waiters for OTHER ids and dropped
  // them, so a caller waiting on two MCPs only ever settled by timing out —
  // harmless with today's single-id callers, and a trap for the next one.
  const helloWaiters = new Map<string, (() => void)[]>();
  ws.on('message', (data) => {
    try {
      const frame = validateFrame(JSON.parse(data.toString()));
      if (frame.type === 'hello' && frame.role === 'server') {
        serverHellos.set(frame.mcpId, {
          sessionNonce: frame.sessionNonce,
          identityX25519Pub: frame.identityX25519Pub,
        });
        for (const wake of helloWaiters.get(frame.mcpId) ?? []) wake();
        helloWaiters.delete(frame.mcpId);
      }
    } catch {
      /* ignore */
    }
  });

  const waitForServerHello = async (
    mcpId: string,
  ): Promise<{ sessionNonce: string; identityX25519Pub: string }> => {
    const seen = serverHellos.get(mcpId);
    if (seen) return seen;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no server hello for ${mcpId}`)), 5_000);
      const waiting = helloWaiters.get(mcpId) ?? [];
      waiting.push(() => {
        clearTimeout(timer);
        resolve();
      });
      helloWaiters.set(mcpId, waiting);
    });
    return serverHellos.get(mcpId)!;
  };

  ws.send(JSON.stringify(hello));

  return {
    ws,
    hello,
    pin: (pinnedAt = 1_700_000_000_000) => ({
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
      pinnedAt,
    }),
    completeHandshake: async (mcpId, opts = {}) => {
      const { sessionNonce: mcpNonceB64, identityX25519Pub } = await waitForServerHello(mcpId);
      const mcpNonce = new Uint8Array(Buffer.from(mcpNonceB64, 'base64'));
      const eph = await generateX25519();
      const payload = readySignaturePayload(mcpNonce, sessionNonce, eph.publicKey);
      const sig = opts.forgeSignature
        ? new Uint8Array(64).fill(9)
        : await ed25519Sign(ed.privateKey, payload);
      ws.send(
        JSON.stringify({
          type: 'ready',
          mcpId,
          extensionSessionPub: b64(eph.publicKey),
          sessionSig: b64(sig),
        }),
      );
      const shared = await ecdhX25519(
        eph.privateKey,
        new Uint8Array(Buffer.from(identityX25519Pub, 'base64')),
      );
      return hkdfSha256(shared, mcpNonce, new TextEncoder().encode(HKDF_SESSION_INFO), 32);
    },
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
