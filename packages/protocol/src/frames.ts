/**
 * Frame types for fetchproxy protocol v1 (0.2.0+).
 *
 * Top-level frames on the wire: hello, ready, frame (encrypted).
 * Inner frames (inside ciphertext): ping, pong, request, response.
 *
 * 0.2.0 wire change: the server hello carries `domains: string[]`
 * instead of `domain: string`. 0.1.x and 0.2.x cannot interoperate.
 */

export const PROTOCOL_VERSION = 1 as const;
export type Platform = 'chrome' | 'safari' | 'firefox';

export interface HelloFrameFromServer {
  type: 'hello';
  protocolVersion: 1;
  role: 'server';
  mcpId: string;                  // server:version:rand
  serverName: string;
  version: string;
  /**
   * Non-empty array of hostnames this MCP is allowed to reach. The
   * extension treats each entry as "exact hostname or any subdomain
   * of it." (0.2.0+: replaces the singular `domain: string` field.)
   */
  domains: string[];
  identityX25519Pub: string;      // base64 raw 32B
  identityEd25519Pub: string;     // base64 raw 32B
  sessionNonce: string;           // base64 raw ≥16B
  sessionSig: string;             // base64 — Ed25519Sign(identityEd25519Priv, mcpId || sessionNonce)
}

export interface HelloFrameFromExtension {
  type: 'hello';
  protocolVersion: 1;
  role: 'extension';
  platform: Platform;
  extensionId: string;
  version: string;
}

export type HelloFrame = HelloFrameFromServer | HelloFrameFromExtension;

export interface ReadyFrame {
  type: 'ready';
  mcpId: string;
  extensionSessionPub: string;    // base64 raw 32B (ephemeral extension X25519 pub)
}

export interface EncryptedFrame {
  type: 'frame';
  mcpId: string;
  seq: number;                    // monotonic per direction per session, ≥ 1
  iv: string;                     // base64 raw 12B
  ciphertext: string;             // base64 — AES-256-GCM(sessionKey, iv, innerFrameJson)
}

export type Frame = HelloFrame | ReadyFrame | EncryptedFrame;

// --- Inner frames (inside ciphertext) ---

export interface FetchInit {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  tabUrl: string;
}

export interface InnerPing {
  type: 'ping';
}
export interface InnerPong {
  type: 'pong';
}
export interface InnerRequest {
  type: 'request';
  id: number;
  op: 'fetch';
  init: FetchInit;
}
export interface InnerResponseOk {
  type: 'response';
  id: number;
  ok: true;
  status: number;
  url: string;
  body: string;
}
export interface InnerResponseError {
  type: 'response';
  id: number;
  ok: false;
  error: string;
}
export type InnerFrame =
  | InnerPing
  | InnerPong
  | InnerRequest
  | InnerResponseOk
  | InnerResponseError;
