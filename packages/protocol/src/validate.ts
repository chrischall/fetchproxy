import type { Capability, Frame, HelloFrame, ReadyFrame, EncryptedFrame, InnerFrame } from './frames.js';
import { KNOWN_CAPABILITIES, PROTOCOL_VERSION } from './frames.js';
import { isValidMcpId } from './mcp-id.js';

/**
 * Thrown by `validateFrame` / `validateInnerFrame` when a structurally
 * invalid frame is received on the wire. Carries a one-line message
 * identifying the field that failed (`hello.domains`, `frame.seq`, etc.)
 * so the receiver can log / surface it without rebuilding the context.
 */
export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
/**
 * Strict DNS hostname: ≥2 labels, alphanumeric + hyphen, no leading or
 * trailing hyphen per label. Shared by the protocol validator and the
 * extension's `ensureDomainTab` so server, validator, and extension
 * agree on what counts as a "valid hostname".
 */
export const HOSTNAME_RE =
  /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

function assertObject(x: unknown, label: string): asserts x is Record<string, unknown> {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) {
    throw new ProtocolError(`${label}: expected object, got ${typeof x}`);
  }
  const proto = Object.getPrototypeOf(x);
  if (proto !== Object.prototype && proto !== null) {
    throw new ProtocolError(`${label}: non-plain object`);
  }
  for (const k of Object.keys(x)) {
    if (FORBIDDEN_KEYS.has(k)) throw new ProtocolError(`${label}: forbidden key ${k}`);
  }
}

function assertString(x: unknown, label: string): asserts x is string {
  if (typeof x !== 'string') {
    throw new ProtocolError(`${label}: expected string, got ${typeof x}`);
  }
}

function assertBase64(x: unknown, label: string): asserts x is string {
  assertString(x, label);
  if (!BASE64_RE.test(x)) throw new ProtocolError(`${label}: invalid base64`);
}

function assertPositiveInt(x: unknown, label: string): asserts x is number {
  if (typeof x !== 'number' || !Number.isInteger(x) || x <= 0) {
    throw new ProtocolError(`${label}: expected positive integer`);
  }
}

function assertHttpUrl(x: unknown, label: string): asserts x is string {
  assertString(x, label);
  let u: URL;
  try {
    u = new URL(x);
  } catch {
    throw new ProtocolError(`${label}: not a valid URL`);
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    throw new ProtocolError(`${label}: must be http(s), got ${u.protocol}`);
  }
}

/**
 * Validate a raw JSON-parsed value as a top-level fetchproxy frame.
 * Throws `ProtocolError` on any structural issue (wrong type, missing
 * field, bad encoding, forbidden prototype-pollution key). Used by both
 * sides of the WebSocket — anything that comes in over the wire passes
 * through this before the handler touches it.
 */
export function validateFrame(raw: unknown): Frame {
  assertObject(raw, 'frame');
  const t = raw.type;
  if (t === 'hello') return validateHello(raw);
  if (t === 'ready') return validateReady(raw);
  if (t === 'frame') return validateEncrypted(raw);
  throw new ProtocolError(`unknown frame type: ${String(t)}`);
}

function validateHello(raw: Record<string, unknown>): HelloFrame {
  if (raw.protocolVersion !== PROTOCOL_VERSION) {
    throw new ProtocolError(`hello.protocolVersion: must be ${PROTOCOL_VERSION}`);
  }
  const role = raw.role;
  if (role === 'server') {
    assertString(raw.mcpId, 'hello.mcpId');
    if (!isValidMcpId(raw.mcpId)) throw new ProtocolError('hello.mcpId: invalid format');
    assertString(raw.serverName, 'hello.serverName');
    assertString(raw.version, 'hello.version');
    if (!Array.isArray(raw.domains)) {
      throw new ProtocolError('hello.domains: expected array');
    }
    if (raw.domains.length === 0) {
      throw new ProtocolError('hello.domains: must be non-empty');
    }
    for (const d of raw.domains) {
      if (typeof d !== 'string') {
        throw new ProtocolError(`hello.domains: entry must be string, got ${typeof d}`);
      }
      if (!HOSTNAME_RE.test(d)) {
        throw new ProtocolError(`hello.domains: invalid hostname ${JSON.stringify(d)}`);
      }
    }
    if (raw.capabilities !== undefined) {
      if (!Array.isArray(raw.capabilities)) {
        throw new ProtocolError('hello.capabilities: expected array');
      }
      if (raw.capabilities.length === 0) {
        throw new ProtocolError('hello.capabilities: must be non-empty');
      }
      for (const c of raw.capabilities) {
        if (typeof c !== 'string') {
          throw new ProtocolError(`hello.capabilities: entry must be string, got ${typeof c}`);
        }
        if (!KNOWN_CAPABILITIES.has(c as Capability)) {
          throw new ProtocolError(
            `hello.capabilities: unknown capability ${JSON.stringify(c)}`,
          );
        }
      }
    }
    assertBase64(raw.identityX25519Pub, 'hello.identityX25519Pub');
    assertBase64(raw.identityEd25519Pub, 'hello.identityEd25519Pub');
    assertBase64(raw.sessionNonce, 'hello.sessionNonce');
    assertBase64(raw.sessionSig, 'hello.sessionSig');
    return raw as unknown as HelloFrame;
  }
  if (role === 'extension') {
    assertString(raw.platform, 'hello.platform');
    if (!['chrome', 'safari', 'firefox'].includes(raw.platform)) {
      throw new ProtocolError(`hello.platform: invalid (${raw.platform})`);
    }
    assertString(raw.extensionId, 'hello.extensionId');
    assertString(raw.version, 'hello.version');
    return raw as unknown as HelloFrame;
  }
  throw new ProtocolError(`hello.role: must be 'server' or 'extension', got ${String(role)}`);
}

function validateReady(raw: Record<string, unknown>): ReadyFrame {
  assertString(raw.mcpId, 'ready.mcpId');
  if (!isValidMcpId(raw.mcpId)) throw new ProtocolError('ready.mcpId: invalid format');
  assertBase64(raw.extensionSessionPub, 'ready.extensionSessionPub');
  return raw as unknown as ReadyFrame;
}

function validateEncrypted(raw: Record<string, unknown>): EncryptedFrame {
  assertString(raw.mcpId, 'frame.mcpId');
  if (!isValidMcpId(raw.mcpId)) throw new ProtocolError('frame.mcpId: invalid format');
  assertPositiveInt(raw.seq, 'frame.seq');
  assertBase64(raw.iv, 'frame.iv');
  assertBase64(raw.ciphertext, 'frame.ciphertext');
  return raw as unknown as EncryptedFrame;
}

/**
 * Validate a raw JSON-parsed value as an inner (post-decryption) frame.
 * Sibling of `validateFrame`; each side runs this on the JSON payload
 * recovered from a successful AES-GCM open before dispatching to a
 * verb handler.
 */
export function validateInnerFrame(raw: unknown): InnerFrame {
  assertObject(raw, 'inner');
  const t = raw.type;
  if (t === 'ping') return { type: 'ping' };
  if (t === 'pong') return { type: 'pong' };
  if (t === 'request') return validateInnerRequest(raw);
  if (t === 'response') return validateInnerResponse(raw);
  throw new ProtocolError(`unknown inner frame type: ${String(t)}`);
}

function validateInnerRequest(raw: Record<string, unknown>): InnerFrame {
  assertPositiveInt(raw.id, 'inner.id');
  // 0.2.0 made `op` a discriminated union. The validator switches on it
  // so the rest of the request shape (which differs per op) can be
  // checked precisely. Unknown ops are rejected here rather than at the
  // extension — keeps the trust boundary clean.
  if (raw.op === 'fetch') {
    assertObject(raw.init, 'inner.init');
    assertHttpUrl(raw.init.url, 'inner.init.url');
    assertString(raw.init.method, 'inner.init.method');
    assertHttpUrl(raw.init.tabUrl, 'inner.init.tabUrl');
    if (raw.init.headers !== undefined) {
      // Sweep nested headers object for prototype-pollution keys + non-plain proto.
      assertObject(raw.init.headers, 'inner.init.headers');
      for (const [k, v] of Object.entries(raw.init.headers)) {
        if (typeof v !== 'string') {
          throw new ProtocolError(`inner.init.headers[${k}]: must be string`);
        }
      }
    }
    if (raw.init.body !== undefined) {
      assertString(raw.init.body, 'inner.init.body');
    }
    return raw as unknown as InnerFrame;
  }
  if (raw.op === 'read_cookies') {
    assertObject(raw.init, 'inner.init');
    assertHttpUrl(raw.init.tabUrl, 'inner.init.tabUrl');
    // No other init fields are valid for read_cookies. Trim the
    // attack surface by rejecting anything else explicitly so a
    // malformed-but-accepted frame can't smuggle data through.
    for (const k of Object.keys(raw.init)) {
      if (k !== 'tabUrl') {
        throw new ProtocolError(`inner.init: unexpected field ${JSON.stringify(k)} on read_cookies`);
      }
    }
    return raw as unknown as InnerFrame;
  }
  throw new ProtocolError(
    `inner.op: must be "fetch" or "read_cookies", got ${JSON.stringify(raw.op)}`,
  );
}

function validateInnerResponse(raw: Record<string, unknown>): InnerFrame {
  assertPositiveInt(raw.id, 'inner.id');
  if (raw.ok === true) {
    // Discriminate by `op` so we can validate the shape that goes with it.
    // For back-compat with 0.1.x responses that don't carry `op` we treat
    // a missing op as `fetch`. New senders should always set it.
    const op = raw.op === undefined ? 'fetch' : raw.op;
    if (op === 'fetch') {
      assertPositiveInt(raw.status, 'inner.status');
      assertString(raw.url, 'inner.url');
      assertString(raw.body, 'inner.body');
      return raw as unknown as InnerFrame;
    }
    if (op === 'read_cookies') {
      assertString(raw.cookies, 'inner.cookies');
      return raw as unknown as InnerFrame;
    }
    throw new ProtocolError(
      `inner.op: must be "fetch" or "read_cookies", got ${JSON.stringify(raw.op)}`,
    );
  }
  if (raw.ok === false) {
    assertString(raw.error, 'inner.error');
    if (raw.op !== undefined) {
      if (typeof raw.op !== 'string' || !KNOWN_CAPABILITIES.has(raw.op as Capability)) {
        throw new ProtocolError(
          `inner.op: unknown response op ${JSON.stringify(raw.op)}`,
        );
      }
    }
    return raw as unknown as InnerFrame;
  }
  throw new ProtocolError(`inner.ok: must be boolean, got ${typeof raw.ok}`);
}
