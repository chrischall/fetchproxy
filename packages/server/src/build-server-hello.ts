import {
  PROTOCOL_VERSION,
  concatBytes,
  ed25519Sign,
  toB64,
  type Capability,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import type { Identity } from './identity.js';

/**
 * Inputs to `buildServerHello`. Mirrors the fields a host or peer
 * already has to track on startup — `serverName`, `version`, declared
 * `domains[]`, optional `capabilities[]` — so callers don't have to
 * spread their own ad-hoc structure into one.
 */
export interface BuildServerHelloOpts {
  identity: Identity;
  mcpId: string;
  serverName: string;
  version: string;
  domains: string[];
  /** Optional. Defaults to `['fetch']` to preserve pre-capability behavior. */
  capabilities?: Capability[];
}

/**
 * Build a `HelloFrameFromServer` frame, including a fresh 32-byte
 * session nonce and the Ed25519 signature over `mcpId || sessionNonce`.
 *
 * Both `startHost` (concentrator path) and `startPeer` (joiner path)
 * emit this frame on startup with identical structure; consolidating
 * the construction here keeps the nonce length, signing payload, and
 * field defaults in one place. Callers should NOT cache the result —
 * `sessionNonce` is fresh per call and must remain fresh per session.
 */
export async function buildServerHello(
  opts: BuildServerHelloOpts,
): Promise<HelloFrameFromServer> {
  const sessionNonce = new Uint8Array(32);
  (globalThis.crypto as Crypto).getRandomValues(sessionNonce);
  const sig = await ed25519Sign(
    opts.identity.ed25519Priv,
    concatBytes(new TextEncoder().encode(opts.mcpId), sessionNonce),
  );
  return {
    type: 'hello',
    protocolVersion: PROTOCOL_VERSION,
    role: 'server',
    mcpId: opts.mcpId,
    serverName: opts.serverName,
    version: opts.version,
    domains: [...opts.domains],
    capabilities: [...(opts.capabilities ?? ['fetch'])],
    identityX25519Pub: toB64(opts.identity.x25519Pub),
    identityEd25519Pub: toB64(opts.identity.ed25519Pub),
    sessionNonce: toB64(sessionNonce),
    sessionSig: toB64(sig),
  };
}
