/**
 * Runtime schema validation for incoming WS frames. Defensive against
 * malformed input (prototype pollution, wrong types, unknown frame
 * types). Throws ProtocolError on invalid input; callers should close
 * the WS with code 1002.
 */
import type { Frame } from './frames.js';

export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function assertObject(x: unknown): asserts x is Record<string, unknown> {
  if (x === null || typeof x !== 'object' || Array.isArray(x)) {
    throw new ProtocolError(`expected object, got ${typeof x}`);
  }
  const proto = Object.getPrototypeOf(x);
  if (proto !== Object.prototype && proto !== null) {
    throw new ProtocolError(`forbidden key: __proto__`);
  }
  for (const k of Object.keys(x)) {
    if (FORBIDDEN_KEYS.has(k)) {
      throw new ProtocolError(`forbidden key: ${k}`);
    }
  }
}

function assertString(x: unknown, field: string): asserts x is string {
  if (typeof x !== 'string') {
    throw new ProtocolError(`expected string for ${field}, got ${typeof x}`);
  }
}

function assertInteger(x: unknown, field: string): asserts x is number {
  if (typeof x !== 'number' || !Number.isInteger(x)) {
    throw new ProtocolError(`expected integer for ${field}, got ${typeof x}`);
  }
}

function assertHttpUrl(x: unknown, field: string): asserts x is string {
  assertString(x, field);
  try {
    const u = new URL(x);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') {
      throw new ProtocolError(`${field} must be http(s), got ${u.protocol}`);
    }
  } catch (e) {
    if (e instanceof ProtocolError) throw e;
    throw new ProtocolError(`${field} is not a valid URL: ${String(x).slice(0, 80)}`);
  }
}

/** Validate an incoming frame. Returns the same value (narrowed) on
 *  success; throws ProtocolError on any malformation. */
export function validateFrame(raw: unknown): Frame {
  assertObject(raw);
  assertString(raw.type, 'type');
  switch (raw.type) {
    case 'hello': {
      assertString(raw.role, 'role');
      if (raw.role === 'extension') {
        assertString(raw.version, 'version');
        assertString(raw.platform, 'platform');
        assertString(raw.extension_id, 'extension_id');
        return raw as unknown as Frame;
      }
      if (raw.role === 'server') {
        assertString(raw.server, 'server');
        assertString(raw.version, 'version');
        assertString(raw.domain, 'domain');
        return raw as unknown as Frame;
      }
      throw new ProtocolError(`unknown hello role: ${raw.role}`);
    }
    case 'ready':
    case 'ping':
    case 'pong':
      return raw as unknown as Frame;
    case 'request': {
      assertInteger(raw.id, 'id');
      assertString(raw.op, 'op');
      if (raw.op !== 'fetch') {
        throw new ProtocolError(`unknown op: ${raw.op}`);
      }
      assertObject(raw.init);
      assertHttpUrl(raw.init.url, 'init.url');
      assertString(raw.init.method, 'init.method');
      assertString(raw.init.tabUrl, 'init.tabUrl');
      return raw as unknown as Frame;
    }
    case 'response': {
      assertInteger(raw.id, 'id');
      if (raw.ok === true) {
        assertInteger(raw.status, 'status');
        assertString(raw.url, 'url');
        assertString(raw.body, 'body');
        return raw as unknown as Frame;
      }
      if (raw.ok === false) {
        assertString(raw.error, 'error');
        return raw as unknown as Frame;
      }
      throw new ProtocolError(`response.ok must be boolean, got ${typeof raw.ok}`);
    }
    default:
      throw new ProtocolError(`unknown frame type: ${raw.type}`);
  }
}
