import type { Frame, HelloFrame, ReadyFrame, EncryptedFrame, InnerFrame } from './frames.js';
import { PROTOCOL_VERSION } from './frames.js';
import { isValidMcpId } from './mcp-id.js';

export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

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
    assertString(raw.domain, 'hello.domain');
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

export function validateInnerFrame(raw: unknown): InnerFrame {
  assertObject(raw, 'inner');
  const t = raw.type;
  if (t === 'ping') return { type: 'ping' };
  if (t === 'pong') return { type: 'pong' };
  if (t === 'request') {
    assertPositiveInt(raw.id, 'inner.id');
    if (raw.op !== 'fetch') throw new ProtocolError(`inner.op: must be "fetch", got ${String(raw.op)}`);
    assertObject(raw.init, 'inner.init');
    assertHttpUrl(raw.init.url, 'inner.init.url');
    assertString(raw.init.method, 'inner.init.method');
    assertString(raw.init.tabUrl, 'inner.init.tabUrl');
    return raw as unknown as InnerFrame;
  }
  if (t === 'response') {
    assertPositiveInt(raw.id, 'inner.id');
    if (raw.ok === true) {
      assertPositiveInt(raw.status, 'inner.status');
      assertString(raw.url, 'inner.url');
      assertString(raw.body, 'inner.body');
      return raw as unknown as InnerFrame;
    }
    if (raw.ok === false) {
      assertString(raw.error, 'inner.error');
      return raw as unknown as InnerFrame;
    }
    throw new ProtocolError(`inner.ok: must be boolean, got ${typeof raw.ok}`);
  }
  throw new ProtocolError(`unknown inner frame type: ${String(t)}`);
}
