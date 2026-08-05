import { WebSocket } from 'ws';
import {
  ed25519Sign,
  generateEd25519,
  generateX25519,
  validateFrame,
  type HelloFrameFromExtension,
} from '@fetchproxy/protocol';
import type { ExtensionPin } from '../../src/extension-trust.js';

const b64 = (u: Uint8Array): string => Buffer.from(u).toString('base64');

export interface MockExtension {
  ws: WebSocket;
  hello: HelloFrameFromExtension;
  /** The pin this extension's hello would produce. */
  pin(pinnedAt?: number): ExtensionPin;
  /** Wait for the server hello for `mcpId`, then answer with a signed ready. */
  completeHandshake(mcpId: string, opts?: { forgeSignature?: boolean }): Promise<void>;
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
    protocolVersion: 2,
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

  const serverHellos = new Map<string, { sessionNonce: string }>();
  const helloWaiters: ((mcpId: string) => void)[] = [];
  ws.on('message', (data) => {
    try {
      const frame = validateFrame(JSON.parse(data.toString()));
      if (frame.type === 'hello' && frame.role === 'server') {
        serverHellos.set(frame.mcpId, { sessionNonce: frame.sessionNonce });
        for (const w of helloWaiters.splice(0)) w(frame.mcpId);
      }
    } catch {
      /* ignore */
    }
  });

  const waitForServerHello = async (mcpId: string): Promise<{ sessionNonce: string }> => {
    const seen = serverHellos.get(mcpId);
    if (seen) return seen;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`no server hello for ${mcpId}`)), 5_000);
      helloWaiters.push(() => {
        if (!serverHellos.has(mcpId)) return;
        clearTimeout(timer);
        resolve();
      });
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
      const { sessionNonce: mcpNonceB64 } = await waitForServerHello(mcpId);
      const mcpNonce = new Uint8Array(Buffer.from(mcpNonceB64, 'base64'));
      const payload = new Uint8Array(mcpNonce.length + sessionNonce.length);
      payload.set(mcpNonce, 0);
      payload.set(sessionNonce, mcpNonce.length);
      const sig = opts.forgeSignature
        ? new Uint8Array(64).fill(9)
        : await ed25519Sign(ed.privateKey, payload);
      const eph = await generateX25519();
      ws.send(
        JSON.stringify({
          type: 'ready',
          mcpId,
          extensionSessionPub: b64(eph.publicKey),
          sessionSig: b64(sig),
        }),
      );
    },
    closed: () =>
      new Promise((resolve) =>
        ws.once('close', (code: number, reason: Buffer) =>
          resolve({ code, reason: reason.toString() }),
        ),
      ),
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
