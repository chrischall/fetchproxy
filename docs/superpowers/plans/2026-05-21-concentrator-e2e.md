# fetchproxy 0.1.0 — Concentrator + E2E Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Collapse N MCP servers onto one WebSocket port via a peer-elected concentrator, with end-to-end AES-GCM encryption between each peer MCP and the extension so the host MCP cannot read or modify peer traffic.

**Architecture:** First MCP to start binds `127.0.0.1:37149` (the host); subsequent MCPs detect EADDRINUSE and dial as peer clients. Host multiplexes frames by `mcpId`. Each peer ↔ extension pair establishes a session key via ECDH (X25519) bound to a human-verifiable pair code derived from the MCP's long-term identity public key (SAS pattern). All post-handshake frames are AES-256-GCM sealed.

**Tech Stack:** Node 22 (`@fetchproxy/server`, `@fetchproxy/protocol`), Web Crypto API (both Node and browser have native), Vitest, TypeScript composite builds, Chrome MV3 service worker.

**Spec reference:** `docs/superpowers/specs/2026-05-21-concentrator-e2e-design.md`

---

## Phase A — Protocol primitives (pure, no I/O)

### Task 1: Crypto wrappers (Node)

**Files:**
- Create: `packages/protocol/src/crypto.ts`
- Test: `packages/protocol/tests/crypto.test.ts`

Web Crypto subset shared by Node and browser, exported as async functions.

- [ ] **Step 1: Write failing tests**

```typescript
// packages/protocol/tests/crypto.test.ts
import { describe, it, expect } from 'vitest';
import {
  generateX25519,
  generateEd25519,
  ed25519Sign,
  ed25519Verify,
  ecdhX25519,
  hkdfSha256,
  aesGcmSeal,
  aesGcmOpen,
  sha256,
} from '../src/crypto.js';

describe('crypto', () => {
  it('generates X25519 keypair with 32-byte raw values', async () => {
    const kp = await generateX25519();
    expect(kp.privateKey.byteLength).toBe(32);
    expect(kp.publicKey.byteLength).toBe(32);
  });

  it('ECDH agrees on a shared secret', async () => {
    const a = await generateX25519();
    const b = await generateX25519();
    const ab = await ecdhX25519(a.privateKey, b.publicKey);
    const ba = await ecdhX25519(b.privateKey, a.publicKey);
    expect(Buffer.from(ab).equals(Buffer.from(ba))).toBe(true);
  });

  it('Ed25519 sign+verify round-trips', async () => {
    const kp = await generateEd25519();
    const msg = new TextEncoder().encode('hello');
    const sig = await ed25519Sign(kp.privateKey, msg);
    expect(await ed25519Verify(kp.publicKey, msg, sig)).toBe(true);
    const tampered = new TextEncoder().encode('hellp');
    expect(await ed25519Verify(kp.publicKey, tampered, sig)).toBe(false);
  });

  it('HKDF-SHA256 derives 32 bytes deterministically', async () => {
    const ikm = new Uint8Array(32).fill(1);
    const salt = new Uint8Array(16).fill(2);
    const info = new TextEncoder().encode('test');
    const k1 = await hkdfSha256(ikm, salt, info, 32);
    const k2 = await hkdfSha256(ikm, salt, info, 32);
    expect(Buffer.from(k1).equals(Buffer.from(k2))).toBe(true);
    expect(k1.byteLength).toBe(32);
  });

  it('AES-GCM seal+open round-trips and detects tampering', async () => {
    const key = new Uint8Array(32).fill(7);
    const iv = new Uint8Array(12).fill(3);
    const pt = new TextEncoder().encode('{"x":1}');
    const ct = await aesGcmSeal(key, iv, pt);
    expect(ct.byteLength).toBe(pt.byteLength + 16);  // GCM tag
    const dec = await aesGcmOpen(key, iv, ct);
    expect(new TextDecoder().decode(dec)).toBe('{"x":1}');
    const tampered = new Uint8Array(ct);
    tampered[0] ^= 1;
    await expect(aesGcmOpen(key, iv, tampered)).rejects.toThrow();
  });

  it('sha256 produces 32 bytes', async () => {
    const h = await sha256(new TextEncoder().encode('abc'));
    expect(h.byteLength).toBe(32);
    expect(Buffer.from(h).toString('hex')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/protocol && npx vitest run test/crypto.test.ts`
Expected: FAIL — module not found.

- [ ] **Step 3: Implement crypto wrappers**

```typescript
// packages/protocol/src/crypto.ts
// Web Crypto wrappers. Pure async, no Node-only APIs — works in both Node 22+
// (which has X25519/Ed25519 in webcrypto) and modern browsers.

const subtle: SubtleCrypto = (globalThis.crypto as Crypto).subtle;

export interface RawKeyPair {
  privateKey: Uint8Array;  // raw, 32 bytes
  publicKey: Uint8Array;   // raw, 32 bytes
}

async function exportRaw(key: CryptoKey, format: 'raw' | 'pkcs8' | 'spki'): Promise<Uint8Array> {
  const buf = await subtle.exportKey(format, key);
  return new Uint8Array(buf);
}

export async function generateX25519(): Promise<RawKeyPair> {
  const kp = (await subtle.generateKey({ name: 'X25519' }, true, [
    'deriveBits',
  ])) as CryptoKeyPair;
  const priv = await exportRaw(kp.privateKey, 'pkcs8');
  const pub = await exportRaw(kp.publicKey, 'raw');
  // pkcs8 wraps the 32-byte raw key — last 32 bytes
  return { privateKey: priv.slice(-32), publicKey: pub };
}

export async function generateEd25519(): Promise<RawKeyPair> {
  const kp = (await subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  const priv = await exportRaw(kp.privateKey, 'pkcs8');
  const pub = await exportRaw(kp.publicKey, 'raw');
  return { privateKey: priv.slice(-32), publicKey: pub };
}

async function importX25519Priv(raw: Uint8Array): Promise<CryptoKey> {
  // Wrap 32-byte raw in a minimal pkcs8 envelope.
  // OID 1.3.101.110 (X25519): 30 2e 02 01 00 30 05 06 03 2b 65 6e 04 22 04 20 [32 bytes]
  const prefix = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8 = new Uint8Array(prefix.length + raw.length);
  pkcs8.set(prefix, 0);
  pkcs8.set(raw, prefix.length);
  return subtle.importKey('pkcs8', pkcs8, { name: 'X25519' }, false, ['deriveBits']);
}

async function importX25519Pub(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey('raw', raw, { name: 'X25519' }, false, []);
}

async function importEd25519Priv(raw: Uint8Array): Promise<CryptoKey> {
  // OID 1.3.101.112 (Ed25519): 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 [32 bytes]
  const prefix = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8 = new Uint8Array(prefix.length + raw.length);
  pkcs8.set(prefix, 0);
  pkcs8.set(raw, prefix.length);
  return subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
}

async function importEd25519Pub(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
}

export async function ecdhX25519(privRaw: Uint8Array, pubRaw: Uint8Array): Promise<Uint8Array> {
  const priv = await importX25519Priv(privRaw);
  const pub = await importX25519Pub(pubRaw);
  const bits = await subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256);
  return new Uint8Array(bits);
}

export async function ed25519Sign(privRaw: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const priv = await importEd25519Priv(privRaw);
  const sig = await subtle.sign({ name: 'Ed25519' }, priv, msg);
  return new Uint8Array(sig);
}

export async function ed25519Verify(
  pubRaw: Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array,
): Promise<boolean> {
  const pub = await importEd25519Pub(pubRaw);
  return subtle.verify({ name: 'Ed25519' }, pub, sig, msg);
}

export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  lenBytes: number,
): Promise<Uint8Array> {
  const baseKey = await subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    baseKey,
    lenBytes * 8,
  );
  return new Uint8Array(bits);
}

export async function aesGcmSeal(
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, k, plaintext);
  return new Uint8Array(ct);
}

export async function aesGcmOpen(
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
  const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, k, ciphertext);
  return new Uint8Array(pt);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const h = await subtle.digest('SHA-256', data);
  return new Uint8Array(h);
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/protocol && npx vitest run test/crypto.test.ts`
Expected: PASS — 6/6.

- [ ] **Step 5: Commit**

```bash
git add packages/protocol/src/crypto.ts packages/protocol/tests/crypto.test.ts
git commit -m "feat(protocol): Web Crypto wrappers for X25519, Ed25519, HKDF, AES-GCM"
```

### Task 2: mcpId generator + parser

**Files:**
- Create: `packages/protocol/src/mcp-id.ts`
- Test: `packages/protocol/tests/mcp-id.test.ts`

- [ ] **Step 1: Write failing tests**

```typescript
// packages/protocol/tests/mcp-id.test.ts
import { describe, it, expect } from 'vitest';
import { generateMcpId, parseMcpId, isValidMcpId } from '../src/mcp-id.js';

describe('mcp-id', () => {
  it('generates id with shape server:version:rand', () => {
    const id = generateMcpId('opentable-mcp', '0.9.1');
    expect(id).toMatch(/^opentable-mcp:0\.9\.1:[0-9a-f]{16}$/);
  });

  it('two calls produce different rand', () => {
    const a = generateMcpId('a', '1.0.0');
    const b = generateMcpId('a', '1.0.0');
    expect(a).not.toBe(b);
  });

  it('parses valid id', () => {
    const id = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';
    expect(parseMcpId(id)).toEqual({
      serverName: 'opentable-mcp',
      version: '0.9.1',
      rand: 'a3f7c91d2e8b4f56',
    });
  });

  it('rejects malformed ids', () => {
    expect(isValidMcpId('')).toBe(false);
    expect(isValidMcpId('no-colons')).toBe(false);
    expect(isValidMcpId('a:b')).toBe(false);
    expect(isValidMcpId('a:b:NOTHEX')).toBe(false);
    expect(isValidMcpId('a:b:abc')).toBe(false);  // wrong length
    expect(isValidMcpId('opentable-mcp:0.9.1:a3f7c91d2e8b4f56')).toBe(true);
  });

  it('rejects colons in server name', () => {
    expect(() => generateMcpId('bad:name', '1.0.0')).toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/protocol && npx vitest run test/mcp-id.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

```typescript
// packages/protocol/src/mcp-id.ts
const ID_RE = /^([^:]+):([^:]+):([0-9a-f]{16})$/;

export interface McpIdParts {
  serverName: string;
  version: string;
  rand: string;
}

export function generateMcpId(serverName: string, version: string): string {
  if (serverName.includes(':')) {
    throw new Error(`serverName cannot contain ':': ${serverName}`);
  }
  if (version.includes(':')) {
    throw new Error(`version cannot contain ':': ${version}`);
  }
  const rand = randomHex(8);  // 16 hex chars
  return `${serverName}:${version}:${rand}`;
}

export function parseMcpId(id: string): McpIdParts {
  const m = ID_RE.exec(id);
  if (!m) throw new Error(`invalid mcpId: ${id}`);
  return { serverName: m[1], version: m[2], rand: m[3] };
}

export function isValidMcpId(id: unknown): id is string {
  return typeof id === 'string' && ID_RE.test(id);
}

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  (globalThis.crypto as Crypto).getRandomValues(arr);
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/protocol && npx vitest run test/mcp-id.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/protocol/src/mcp-id.ts packages/protocol/tests/mcp-id.test.ts
git commit -m "feat(protocol): mcpId generator + parser (server:version:rand)"
```

### Task 3: Pair code derivation

**Files:**
- Create: `packages/protocol/src/pair-code.ts`
- Test: `packages/protocol/tests/pair-code.test.ts`

- [ ] **Step 1: Write failing tests**

```typescript
// packages/protocol/tests/pair-code.test.ts
import { describe, it, expect } from 'vitest';
import { derivePairCode } from '../src/pair-code.js';

describe('pair-code', () => {
  it('produces XXX-XXX format', async () => {
    const pub = new Uint8Array(32).fill(7);
    const code = await derivePairCode(pub);
    expect(code).toMatch(/^\d{3}-\d{3}$/);
  });

  it('is deterministic for same pubkey', async () => {
    const pub = new Uint8Array(32).fill(42);
    const a = await derivePairCode(pub);
    const b = await derivePairCode(pub);
    expect(a).toBe(b);
  });

  it('different pubkeys produce different codes (high probability)', async () => {
    const a = await derivePairCode(new Uint8Array(32).fill(1));
    const b = await derivePairCode(new Uint8Array(32).fill(2));
    expect(a).not.toBe(b);
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/protocol && npx vitest run test/pair-code.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

```typescript
// packages/protocol/src/pair-code.ts
import { sha256 } from './crypto.js';

/**
 * Derive a human-verifiable 6-digit pair code from a public key.
 * SAS (Short Authentication String) pattern: code commits to the key,
 * so verifying code matches MCP's terminal output authenticates the key.
 *
 * code = first 4 bytes of SHA256(pub) → uint32 → mod 1_000_000 → "XXX-XXX"
 */
export async function derivePairCode(pub: Uint8Array): Promise<string> {
  const h = await sha256(pub);
  const u32 =
    (h[0] << 24 >>> 0) |
    (h[1] << 16) |
    (h[2] << 8) |
    h[3];
  const n = (u32 >>> 0) % 1_000_000;
  const s = n.toString().padStart(6, '0');
  return `${s.slice(0, 3)}-${s.slice(3)}`;
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/protocol && npx vitest run test/pair-code.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/protocol/src/pair-code.ts packages/protocol/tests/pair-code.test.ts
git commit -m "feat(protocol): derive 6-digit pair code from identity pub (SAS pattern)"
```

### Task 4: New frame types (hello-v2, ready-v2, encrypted)

**Files:**
- Modify: `packages/protocol/src/frames.ts`
- Modify: `packages/protocol/src/validate.ts`
- Test: `packages/protocol/tests/frames.test.ts` (extend)

- [ ] **Step 1: Write failing tests**

```typescript
// Add to packages/protocol/tests/validate.test.ts (extend existing test file)
import { validateFrame } from '../src/validate.js';

describe('validate hello-v2', () => {
  const validHello = {
    type: 'hello',
    protocolVersion: 1,
    role: 'server',
    mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
    serverName: 'opentable-mcp',
    version: '0.9.1',
    domain: 'opentable.com',
    identityX25519Pub: 'AAAA',
    identityEd25519Pub: 'AAAA',
    sessionNonce: 'AAAA',
    sessionSig: 'AAAA',
  };

  it('accepts valid hello-v2 from server', () => {
    expect(() => validateFrame(validHello)).not.toThrow();
  });

  it('rejects hello without mcpId', () => {
    const bad = { ...validHello, mcpId: undefined };
    expect(() => validateFrame(bad)).toThrow(/mcpId/);
  });

  it('rejects hello with bad mcpId format', () => {
    const bad = { ...validHello, mcpId: 'no-colons' };
    expect(() => validateFrame(bad)).toThrow(/mcpId/);
  });
});

describe('validate ready-v2', () => {
  it('accepts ready with extensionSessionPub', () => {
    const ready = {
      type: 'ready',
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      extensionSessionPub: 'AAAA',
    };
    expect(() => validateFrame(ready)).not.toThrow();
  });

  it('rejects ready without mcpId', () => {
    expect(() => validateFrame({ type: 'ready' })).toThrow(/mcpId/);
  });
});

describe('validate encrypted frame', () => {
  const valid = {
    type: 'frame',
    mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
    seq: 1,
    iv: 'AAAA',
    ciphertext: 'AAAA',
  };

  it('accepts valid encrypted frame', () => {
    expect(() => validateFrame(valid)).not.toThrow();
  });

  it('rejects seq <= 0', () => {
    expect(() => validateFrame({ ...valid, seq: 0 })).toThrow(/seq/);
    expect(() => validateFrame({ ...valid, seq: -1 })).toThrow(/seq/);
  });

  it('rejects non-base64 iv', () => {
    expect(() => validateFrame({ ...valid, iv: 'not base64!@#' })).toThrow(/iv/);
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/protocol && npx vitest run test/validate.test.ts`
Expected: FAIL — new tests added, frame types don't exist.

- [ ] **Step 3: Implement frame types**

```typescript
// packages/protocol/src/frames.ts — replace the file
// Frame types for fetchproxy protocol v1 (0.1.0).

/**
 * Hello frame — sent by both sides on connect.
 *
 * Server side: identifies the MCP and provides the long-term identity keys
 * + a per-session signature proving possession of the Ed25519 private key.
 */
export interface HelloFrameFromServer {
  type: 'hello';
  protocolVersion: 1;
  role: 'server';
  mcpId: string;                  // server:version:rand
  serverName: string;
  version: string;
  domain: string;                 // primary domain for tab matching + allowlist
  identityX25519Pub: string;      // base64 raw 32B — for ECDH session key
  identityEd25519Pub: string;     // base64 raw 32B — for sessionSig verification
  sessionNonce: string;           // base64 raw ≥16B — fresh per WS connection
  sessionSig: string;             // base64 — Ed25519Sign(identityEd25519Priv, mcpId || sessionNonce)
}

export interface HelloFrameFromExtension {
  type: 'hello';
  protocolVersion: 1;
  role: 'extension';
  platform: 'chrome' | 'safari' | 'firefox';
  extensionId: string;            // stable identifier ("fetchproxy")
  version: string;                // extension version
}

export type HelloFrame = HelloFrameFromServer | HelloFrameFromExtension;

/**
 * Ready frame — extension → server. After pair-code approval (or trust hit),
 * extension generates an ephemeral X25519 keypair and sends the public key.
 * Server combines it with identityX25519Priv to derive sessionKey.
 *
 * (Note: identity X25519 is used as the "fixed" side of ECDH; extension
 * brings ephemeral material for partial freshness. Pure forward secrecy
 * would require ephemeral on both sides; we accept this trade-off — see
 * spec for rationale.)
 */
export interface ReadyFrame {
  type: 'ready';
  mcpId: string;
  extensionSessionPub: string;    // base64 raw 32B
}

/**
 * Encrypted frame — wraps every post-handshake message.
 *
 * inner = JSON({ type: 'request'|'response'|'ping'|'pong', ...fields })
 * ciphertext = AES-256-GCM(sessionKey, iv, inner)  // includes 16B auth tag
 */
export interface EncryptedFrame {
  type: 'frame';
  mcpId: string;
  seq: number;                    // monotonic per direction per session, starts at 1
  iv: string;                     // base64 raw 12B
  ciphertext: string;             // base64
}

/**
 * Inner frame types — these are the JSON payloads inside an encrypted frame.
 * They never appear on the wire in plaintext form (except in extension hello).
 */
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

export interface FetchInit {
  url: string;
  method: string;
  headers?: Record<string, string>;
  body?: string;
  tabUrl: string;
}

export type Frame = HelloFrame | ReadyFrame | EncryptedFrame;

export const PROTOCOL_VERSION = 1 as const;
```

```typescript
// packages/protocol/src/validate.ts — replace
import {
  Frame,
  HelloFrame,
  ReadyFrame,
  EncryptedFrame,
  InnerFrame,
  PROTOCOL_VERSION,
} from './frames.js';
import { isValidMcpId } from './mcp-id.js';

const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

function assertObject(x: unknown, label: string): asserts x is Record<string, unknown> {
  if (typeof x !== 'object' || x === null || Array.isArray(x)) {
    throw new Error(`${label}: expected object`);
  }
  const proto = Object.getPrototypeOf(x);
  if (proto !== Object.prototype && proto !== null) {
    throw new Error(`${label}: non-plain object`);
  }
  for (const k of Object.keys(x)) {
    if (FORBIDDEN_KEYS.has(k)) throw new Error(`${label}: forbidden key ${k}`);
  }
}

function assertString(x: unknown, label: string): asserts x is string {
  if (typeof x !== 'string') throw new Error(`${label}: expected string`);
}

function assertBase64(x: unknown, label: string): asserts x is string {
  assertString(x, label);
  if (!BASE64_RE.test(x)) throw new Error(`${label}: invalid base64`);
}

function assertPositiveInt(x: unknown, label: string): asserts x is number {
  if (typeof x !== 'number' || !Number.isInteger(x) || x <= 0) {
    throw new Error(`${label}: expected positive integer`);
  }
}

export function validateFrame(raw: unknown): Frame {
  assertObject(raw, 'frame');
  const t = raw.type;
  if (t === 'hello') return validateHello(raw);
  if (t === 'ready') return validateReady(raw);
  if (t === 'frame') return validateEncrypted(raw);
  throw new Error(`unknown frame type: ${String(t)}`);
}

function validateHello(raw: Record<string, unknown>): HelloFrame {
  if (raw.protocolVersion !== PROTOCOL_VERSION) {
    throw new Error(`hello: protocolVersion must be ${PROTOCOL_VERSION}`);
  }
  const role = raw.role;
  if (role === 'server') {
    assertString(raw.mcpId, 'hello.mcpId');
    if (!isValidMcpId(raw.mcpId)) throw new Error('hello.mcpId: invalid format');
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
    assertString(raw.extensionId, 'hello.extensionId');
    assertString(raw.version, 'hello.version');
    if (!['chrome', 'safari', 'firefox'].includes(raw.platform as string)) {
      throw new Error('hello.platform: invalid');
    }
    return raw as unknown as HelloFrame;
  }
  throw new Error(`hello.role: must be 'server' or 'extension', got ${String(role)}`);
}

function validateReady(raw: Record<string, unknown>): ReadyFrame {
  assertString(raw.mcpId, 'ready.mcpId');
  if (!isValidMcpId(raw.mcpId)) throw new Error('ready.mcpId: invalid format');
  assertBase64(raw.extensionSessionPub, 'ready.extensionSessionPub');
  return raw as unknown as ReadyFrame;
}

function validateEncrypted(raw: Record<string, unknown>): EncryptedFrame {
  assertString(raw.mcpId, 'frame.mcpId');
  if (!isValidMcpId(raw.mcpId)) throw new Error('frame.mcpId: invalid format');
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
    if (raw.op !== 'fetch') throw new Error('inner.op: must be "fetch"');
    assertObject(raw.init, 'inner.init');
    return raw as unknown as InnerFrame;
  }
  if (t === 'response') {
    assertPositiveInt(raw.id, 'inner.id');
    if (raw.ok === true) {
      assertPositiveInt(raw.status, 'inner.status');
      assertString(raw.url, 'inner.url');
      assertString(raw.body, 'inner.body');
    } else if (raw.ok === false) {
      assertString(raw.error, 'inner.error');
    } else {
      throw new Error('inner.ok: must be boolean');
    }
    return raw as unknown as InnerFrame;
  }
  throw new Error(`unknown inner frame type: ${String(t)}`);
}
```

```typescript
// packages/protocol/src/index.ts — update exports
export * from './frames.js';
export * from './validate.js';
export * from './crypto.js';
export * from './mcp-id.js';
export * from './pair-code.js';
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/protocol && npx vitest run`
Expected: PASS — all tests including legacy ones still green.

- [ ] **Step 5: Commit**

```bash
git add packages/protocol/src/frames.ts packages/protocol/src/validate.ts packages/protocol/src/index.ts packages/protocol/tests/
git commit -m "feat(protocol): 0.1.0 frame types — hello-v2, ready-v2, encrypted frame, inner frames"
```

### Task 5: Seal / open helpers (inner frame ↔ encrypted frame)

**Files:**
- Create: `packages/protocol/src/seal.ts`
- Test: `packages/protocol/tests/seal.test.ts`

- [ ] **Step 1: Write failing tests**

```typescript
// packages/protocol/tests/seal.test.ts
import { describe, it, expect } from 'vitest';
import { sealInnerFrame, openEncryptedFrame } from '../src/seal.js';
import type { InnerFrame, EncryptedFrame } from '../src/frames.js';

describe('seal/open', () => {
  const key = new Uint8Array(32).fill(7);
  const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';

  it('round-trips a ping frame', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner);
    expect(sealed.type).toBe('frame');
    expect(sealed.mcpId).toBe(mcpId);
    expect(sealed.seq).toBe(1);
    const opened = await openEncryptedFrame(key, sealed);
    expect(opened).toEqual(inner);
  });

  it('round-trips a request frame', async () => {
    const inner: InnerFrame = {
      type: 'request',
      id: 42,
      op: 'fetch',
      init: { url: 'https://x', method: 'GET', tabUrl: 'https://x/' },
    };
    const sealed = await sealInnerFrame(key, mcpId, 5, inner);
    const opened = await openEncryptedFrame(key, sealed);
    expect(opened).toEqual(inner);
  });

  it('rejects ciphertext encrypted under a different key', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner);
    const wrongKey = new Uint8Array(32).fill(8);
    await expect(openEncryptedFrame(wrongKey, sealed)).rejects.toThrow();
  });

  it('rejects tampered ciphertext', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner);
    const bytes = Buffer.from(sealed.ciphertext, 'base64');
    bytes[0] ^= 1;
    const bad: EncryptedFrame = { ...sealed, ciphertext: bytes.toString('base64') };
    await expect(openEncryptedFrame(key, bad)).rejects.toThrow();
  });

  it('uses random iv each call', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const a = await sealInnerFrame(key, mcpId, 1, inner);
    const b = await sealInnerFrame(key, mcpId, 1, inner);
    expect(a.iv).not.toBe(b.iv);
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/protocol && npx vitest run test/seal.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

```typescript
// packages/protocol/src/seal.ts
import { aesGcmSeal, aesGcmOpen } from './crypto.js';
import type { InnerFrame, EncryptedFrame } from './frames.js';
import { validateInnerFrame } from './validate.js';

const enc = new TextEncoder();
const dec = new TextDecoder();

function randomIv(): Uint8Array {
  const iv = new Uint8Array(12);
  (globalThis.crypto as Crypto).getRandomValues(iv);
  return iv;
}

function toB64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function fromB64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

export async function sealInnerFrame(
  sessionKey: Uint8Array,
  mcpId: string,
  seq: number,
  inner: InnerFrame,
): Promise<EncryptedFrame> {
  const iv = randomIv();
  const pt = enc.encode(JSON.stringify(inner));
  const ct = await aesGcmSeal(sessionKey, iv, pt);
  return {
    type: 'frame',
    mcpId,
    seq,
    iv: toB64(iv),
    ciphertext: toB64(ct),
  };
}

export async function openEncryptedFrame(
  sessionKey: Uint8Array,
  frame: EncryptedFrame,
): Promise<InnerFrame> {
  const iv = fromB64(frame.iv);
  const ct = fromB64(frame.ciphertext);
  const pt = await aesGcmOpen(sessionKey, iv, ct);
  const parsed: unknown = JSON.parse(dec.decode(pt));
  return validateInnerFrame(parsed);
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/protocol && npx vitest run`
Expected: PASS, all tests still green.

- [ ] **Step 5: Commit**

```bash
git add packages/protocol/src/seal.ts packages/protocol/tests/seal.test.ts packages/protocol/src/index.ts
git commit -m "feat(protocol): seal/open helpers bridging inner frames and AES-GCM ciphertext"
```

(Also update `packages/protocol/src/index.ts` to export `./seal.js`.)

---

## Phase B — Server-side (MCP) identity + election

### Task 6: Identity file load/save

**Files:**
- Create: `packages/server/src/identity.ts`
- Test: `packages/server/tests/identity.test.ts`

- [ ] **Step 1: Write failing tests**

```typescript
// packages/server/tests/identity.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtempSync, rmSync, statSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadOrCreateIdentity } from '../src/identity.js';

describe('identity', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'fetchproxy-id-'));
  });

  it('creates a new keypair on first load', async () => {
    const id = await loadOrCreateIdentity('opentable-mcp', dir);
    expect(id.x25519Pub.byteLength).toBe(32);
    expect(id.x25519Priv.byteLength).toBe(32);
    expect(id.ed25519Pub.byteLength).toBe(32);
    expect(id.ed25519Priv.byteLength).toBe(32);
  });

  it('writes file with mode 0600', async () => {
    await loadOrCreateIdentity('opentable-mcp', dir);
    const path = join(dir, 'opentable-mcp.json');
    const mode = statSync(path).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it('reuses existing keypair on second load', async () => {
    const a = await loadOrCreateIdentity('opentable-mcp', dir);
    const b = await loadOrCreateIdentity('opentable-mcp', dir);
    expect(Buffer.from(a.x25519Pub).equals(Buffer.from(b.x25519Pub))).toBe(true);
    expect(Buffer.from(a.ed25519Priv).equals(Buffer.from(b.ed25519Priv))).toBe(true);
  });

  it('separate server names get separate identities', async () => {
    const a = await loadOrCreateIdentity('opentable-mcp', dir);
    const b = await loadOrCreateIdentity('resy-mcp', dir);
    expect(Buffer.from(a.x25519Pub).equals(Buffer.from(b.x25519Pub))).toBe(false);
  });

  it('file contents are JSON with expected shape', async () => {
    await loadOrCreateIdentity('opentable-mcp', dir);
    const path = join(dir, 'opentable-mcp.json');
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    expect(typeof parsed.x25519Priv).toBe('string');
    expect(typeof parsed.x25519Pub).toBe('string');
    expect(typeof parsed.ed25519Priv).toBe('string');
    expect(typeof parsed.ed25519Pub).toBe('string');
    expect(typeof parsed.createdAt).toBe('number');
  });

  it('rejects server names with path separators', async () => {
    await expect(loadOrCreateIdentity('../etc/passwd', dir)).rejects.toThrow();
    await expect(loadOrCreateIdentity('a/b', dir)).rejects.toThrow();
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/server && npx vitest run test/identity.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

```typescript
// packages/server/src/identity.ts
import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { generateX25519, generateEd25519 } from '@fetchproxy/protocol';

export interface Identity {
  x25519Priv: Uint8Array;
  x25519Pub: Uint8Array;
  ed25519Priv: Uint8Array;
  ed25519Pub: Uint8Array;
  createdAt: number;
}

const SAFE_NAME = /^[A-Za-z0-9._@-][A-Za-z0-9._@/-]*$/;

export function defaultIdentityDir(): string {
  return join(homedir(), '.fetchproxy', 'identity');
}

export async function loadOrCreateIdentity(
  serverName: string,
  dir: string = defaultIdentityDir(),
): Promise<Identity> {
  if (!SAFE_NAME.test(serverName) || serverName.includes('..')) {
    throw new Error(`unsafe serverName for identity file: ${serverName}`);
  }
  // Allow scoped packages (@scope/name) by translating / to _
  const safeName = serverName.replace(/\//g, '_');
  const path = join(dir, `${safeName}.json`);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  try {
    const raw = await readFile(path, 'utf8');
    const j = JSON.parse(raw);
    return {
      x25519Priv: fromB64(j.x25519Priv),
      x25519Pub: fromB64(j.x25519Pub),
      ed25519Priv: fromB64(j.ed25519Priv),
      ed25519Pub: fromB64(j.ed25519Pub),
      createdAt: j.createdAt,
    };
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }
  const x = await generateX25519();
  const ed = await generateEd25519();
  const id: Identity = {
    x25519Priv: x.privateKey,
    x25519Pub: x.publicKey,
    ed25519Priv: ed.privateKey,
    ed25519Pub: ed.publicKey,
    createdAt: Date.now(),
  };
  const j = {
    x25519Priv: toB64(id.x25519Priv),
    x25519Pub: toB64(id.x25519Pub),
    ed25519Priv: toB64(id.ed25519Priv),
    ed25519Pub: toB64(id.ed25519Pub),
    createdAt: id.createdAt,
  };
  await writeFile(path, JSON.stringify(j, null, 2), { mode: 0o600 });
  await chmod(path, 0o600);  // belt-and-suspenders for umask-affected systems
  return id;
}

function toB64(b: Uint8Array): string {
  return Buffer.from(b).toString('base64');
}

function fromB64(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64'));
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/server && npx vitest run test/identity.test.ts`
Expected: PASS — 6/6.

- [ ] **Step 5: Commit**

```bash
git add packages/server/src/identity.ts packages/server/tests/identity.test.ts
git commit -m "feat(server): load-or-create persistent identity keypair at ~/.fetchproxy/identity"
```

### Task 7: Election (bind-or-dial)

**Files:**
- Create: `packages/server/src/election.ts`
- Test: `packages/server/tests/election.test.ts`

- [ ] **Step 1: Write failing tests**

```typescript
// packages/server/tests/election.test.ts
import { describe, it, expect, afterEach } from 'vitest';
import { electRole } from '../src/election.js';
import { createServer, Server as HttpServer } from 'node:http';

describe('election', () => {
  const cleanup: HttpServer[] = [];
  afterEach(async () => {
    await Promise.all(
      cleanup.splice(0).map(
        (s) => new Promise<void>((r) => s.close(() => r())),
      ),
    );
  });

  it('returns host when port is free', async () => {
    const port = 41999;
    const result = await electRole({ host: '127.0.0.1', port });
    expect(result.role).toBe('host');
    if (result.role === 'host') {
      expect(result.server.listening).toBe(true);
      cleanup.push(result.server);
    }
  });

  it('returns peer when port is taken', async () => {
    const port = 41998;
    const blocker = createServer().listen(port, '127.0.0.1');
    await new Promise((r) => blocker.once('listening', r));
    cleanup.push(blocker);
    const result = await electRole({ host: '127.0.0.1', port });
    expect(result.role).toBe('peer');
  });

  it('host role can be released and re-won', async () => {
    const port = 41997;
    const first = await electRole({ host: '127.0.0.1', port });
    expect(first.role).toBe('host');
    if (first.role === 'host') {
      await new Promise<void>((r) => first.server.close(() => r()));
    }
    const second = await electRole({ host: '127.0.0.1', port });
    expect(second.role).toBe('host');
    if (second.role === 'host') {
      cleanup.push(second.server);
    }
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/server && npx vitest run test/election.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

```typescript
// packages/server/src/election.ts
import { createServer, Server as HttpServer } from 'node:http';

export interface ElectionOpts {
  host: string;
  port: number;
}

export type ElectionResult =
  | { role: 'host'; server: HttpServer }
  | { role: 'peer' };

/**
 * Try to bind the WS port. If it succeeds, we're the concentrator (host).
 * If EADDRINUSE, someone else won — we'll dial them as a peer.
 *
 * The HTTP server is returned because @fetchproxy/server's WS server attaches
 * to it directly (no second bind).
 */
export async function electRole(opts: ElectionOpts): Promise<ElectionResult> {
  const server = createServer();
  return new Promise<ElectionResult>((resolve, reject) => {
    server.once('error', (e: NodeJS.ErrnoException) => {
      if (e.code === 'EADDRINUSE') {
        resolve({ role: 'peer' });
      } else {
        reject(e);
      }
    });
    server.once('listening', () => {
      resolve({ role: 'host', server });
    });
    server.listen(opts.port, opts.host);
  });
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/server && npx vitest run test/election.test.ts`
Expected: PASS — 3/3.

- [ ] **Step 5: Commit**

```bash
git add packages/server/src/election.ts packages/server/tests/election.test.ts
git commit -m "feat(server): TCP bind-or-dial election for host vs peer role"
```

### Task 8: Session state (per-peer key cache)

**Files:**
- Create: `packages/server/src/session.ts`
- Test: `packages/server/tests/session.test.ts`

- [ ] **Step 1: Write failing tests**

```typescript
// packages/server/tests/session.test.ts
import { describe, it, expect } from 'vitest';
import { SessionState } from '../src/session.js';

describe('SessionState', () => {
  it('tracks outbound seq starting at 1', () => {
    const s = new SessionState(new Uint8Array(32));
    expect(s.nextOutboundSeq()).toBe(1);
    expect(s.nextOutboundSeq()).toBe(2);
  });

  it('accepts strictly-increasing inbound seq', () => {
    const s = new SessionState(new Uint8Array(32));
    expect(s.acceptInboundSeq(1)).toBe(true);
    expect(s.acceptInboundSeq(2)).toBe(true);
    expect(s.acceptInboundSeq(5)).toBe(true);
    expect(s.acceptInboundSeq(3)).toBe(false);   // out of order
    expect(s.acceptInboundSeq(5)).toBe(false);   // replay
  });

  it('exposes session key', () => {
    const k = new Uint8Array(32).fill(7);
    const s = new SessionState(k);
    expect(Buffer.from(s.sessionKey).equals(Buffer.from(k))).toBe(true);
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/server && npx vitest run test/session.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

```typescript
// packages/server/src/session.ts
export class SessionState {
  public readonly sessionKey: Uint8Array;
  private outboundSeq = 0;
  private lastInboundSeq = 0;

  constructor(sessionKey: Uint8Array) {
    this.sessionKey = sessionKey;
  }

  nextOutboundSeq(): number {
    this.outboundSeq += 1;
    return this.outboundSeq;
  }

  acceptInboundSeq(seq: number): boolean {
    if (seq <= this.lastInboundSeq) return false;
    this.lastInboundSeq = seq;
    return true;
  }
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/server && npx vitest run test/session.test.ts`
Expected: PASS — 3/3.

- [ ] **Step 5: Commit**

```bash
git add packages/server/src/session.ts packages/server/tests/session.test.ts
git commit -m "feat(server): per-peer session state with monotonic seq + replay rejection"
```

### Task 9: Peer client (dial host + encrypted send/receive)

**Files:**
- Create: `packages/server/src/peer.ts`
- Test: `packages/server/tests/peer.test.ts`

- [ ] **Step 1: Write failing tests**

Tests use a fake WS server that speaks the expected protocol just enough to validate the peer's send sequence.

```typescript
// packages/server/tests/peer.test.ts
import { describe, it, expect, afterEach } from 'vitest';
import { WebSocketServer, WebSocket } from 'ws';
import {
  generateX25519,
  generateEd25519,
  derivePairCode,
  validateFrame,
  ecdhX25519,
  hkdfSha256,
  openEncryptedFrame,
} from '@fetchproxy/protocol';
import { startPeer } from '../src/peer.js';
import { SessionState } from '../src/session.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('peer', () => {
  let wss: WebSocketServer | null = null;
  let idDir: string;

  afterEach(async () => {
    if (wss) {
      wss.close();
      wss = null;
    }
  });

  it('dials host, sends hello with valid signature', async () => {
    idDir = mkdtempSync(join(tmpdir(), 'fp-peer-'));
    const identity = await loadOrCreateIdentity('opentable-mcp', idDir);

    const port = 41200;
    wss = new WebSocketServer({ port });
    const receivedFrames: unknown[] = [];
    const helloPromise = new Promise<unknown>((resolve) => {
      wss!.on('connection', (ws: WebSocket) => {
        ws.on('message', (data) => {
          const parsed = JSON.parse(data.toString());
          receivedFrames.push(parsed);
          if (parsed.type === 'hello') resolve(parsed);
        });
      });
    });

    await startPeer({
      host: '127.0.0.1',
      port,
      identity,
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domain: 'opentable.com',
    });

    const hello = (await helloPromise) as Record<string, unknown>;
    expect(hello.type).toBe('hello');
    expect(hello.role).toBe('server');
    expect(hello.mcpId).toBe('opentable-mcp:0.9.1:a3f7c91d2e8b4f56');
    expect(hello.domain).toBe('opentable.com');
    // Validator must accept it
    expect(() => validateFrame(hello)).not.toThrow();
  });
});
```

(More tests will be added in Task 12 once the host is in place — full handshake integration belongs there.)

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/server && npx vitest run test/peer.test.ts`
Expected: FAIL — `startPeer` doesn't exist.

- [ ] **Step 3: Implement**

```typescript
// packages/server/src/peer.ts
import { WebSocket } from 'ws';
import {
  ed25519Sign,
  ecdhX25519,
  hkdfSha256,
  sealInnerFrame,
  openEncryptedFrame,
  validateFrame,
  validateInnerFrame,
  PROTOCOL_VERSION,
  type EncryptedFrame,
  type HelloFrameFromServer,
  type ReadyFrame,
  type InnerFrame,
} from '@fetchproxy/protocol';
import { SessionState } from './session.js';
import type { Identity } from './identity.js';

export interface PeerOpts {
  host: string;
  port: number;
  identity: Identity;
  mcpId: string;
  serverName: string;
  version: string;
  domain: string;
}

export interface PeerHandle {
  ws: WebSocket;
  session: Promise<SessionState>;
  sendInner: (inner: InnerFrame) => Promise<void>;
  onInner: (cb: (inner: InnerFrame) => void) => void;
  close: () => void;
}

const enc = new TextEncoder();

export async function startPeer(opts: PeerOpts): Promise<PeerHandle> {
  const ws = new WebSocket(`ws://${opts.host}:${opts.port}`);
  await new Promise<void>((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
  });

  // Build hello frame
  const sessionNonce = new Uint8Array(32);
  (globalThis.crypto as Crypto).getRandomValues(sessionNonce);
  const sigMsg = concat(enc.encode(opts.mcpId), sessionNonce);
  const sessionSig = await ed25519Sign(opts.identity.ed25519Priv, sigMsg);

  const hello: HelloFrameFromServer = {
    type: 'hello',
    protocolVersion: PROTOCOL_VERSION,
    role: 'server',
    mcpId: opts.mcpId,
    serverName: opts.serverName,
    version: opts.version,
    domain: opts.domain,
    identityX25519Pub: toB64(opts.identity.x25519Pub),
    identityEd25519Pub: toB64(opts.identity.ed25519Pub),
    sessionNonce: toB64(sessionNonce),
    sessionSig: toB64(sessionSig),
  };
  ws.send(JSON.stringify(hello));

  const innerListeners: ((inner: InnerFrame) => void)[] = [];

  const sessionPromise = new Promise<SessionState>((resolve, reject) => {
    ws.on('message', async (data) => {
      try {
        const raw = JSON.parse(data.toString());
        const frame = validateFrame(raw);
        if (frame.type === 'ready' && frame.mcpId === opts.mcpId) {
          const extPub = new Uint8Array(Buffer.from(frame.extensionSessionPub, 'base64'));
          const shared = await ecdhX25519(opts.identity.x25519Priv, extPub);
          const sessionKey = await hkdfSha256(
            shared,
            sessionNonce,
            enc.encode('fetchproxy/0.1.0/session'),
            32,
          );
          const session = new SessionState(sessionKey);
          (handle as { session: Promise<SessionState> }).session = Promise.resolve(session);
          // Switch to encrypted-frame mode for subsequent messages
          ws.removeAllListeners('message');
          ws.on('message', async (d2) => {
            const r2 = JSON.parse(d2.toString());
            const f2 = validateFrame(r2);
            if (f2.type === 'frame' && f2.mcpId === opts.mcpId) {
              if (!session.acceptInboundSeq(f2.seq)) return;
              const inner = await openEncryptedFrame(session.sessionKey, f2);
              innerListeners.forEach((cb) => cb(inner));
            }
          });
          resolve(session);
        }
      } catch (e) {
        reject(e);
      }
    });
  });

  const handle: PeerHandle = {
    ws,
    session: sessionPromise,
    sendInner: async (inner: InnerFrame) => {
      const s = await sessionPromise;
      const sealed = await sealInnerFrame(s.sessionKey, opts.mcpId, s.nextOutboundSeq(), inner);
      ws.send(JSON.stringify(sealed));
    },
    onInner: (cb) => innerListeners.push(cb),
    close: () => ws.close(),
  };
  return handle;
}

function toB64(b: Uint8Array): string {
  return Buffer.from(b).toString('base64');
}
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/server && npx vitest run test/peer.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/server/src/peer.ts packages/server/tests/peer.test.ts
git commit -m "feat(server): peer client — dial host, signed hello, encrypted I/O"
```

### Task 10: Host (concentrator: WS server + multiplexer)

**Files:**
- Create: `packages/server/src/host.ts`
- Test: `packages/server/tests/host.test.ts`

This is the biggest task. The host:
1. Owns the HTTP server (from election).
2. Attaches a `WebSocketServer` for incoming connections.
3. Distinguishes extension WS (one allowed) from peer WSs (N allowed).
4. Routes encrypted frames from extension to peer (by mcpId) and vice versa.
5. Also acts as a peer for its own MCP — its own hello is sent through the same code path.

- [ ] **Step 1: Write failing tests**

```typescript
// packages/server/tests/host.test.ts
import { describe, it, expect, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import {
  validateFrame,
  type HelloFrameFromExtension,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('host', () => {
  let host: HostHandle | null = null;

  afterEach(async () => {
    if (host) await host.close();
    host = null;
  });

  it('accepts an extension WS connection', async () => {
    const port = 41100;
    const el = await electRole({ host: '127.0.0.1', port });
    if (el.role !== 'host') throw new Error('expected host');
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);
    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomain: 'opentable.com',
    });

    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r, j) => {
      ws.once('open', () => r());
      ws.once('error', j);
    });

    // Extension sends its hello
    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: 1,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.1.0',
    };
    ws.send(JSON.stringify(extHello));

    // Host should now forward its own MCP hello + any peer hellos.
    const received: unknown[] = [];
    const ownHelloPromise = new Promise<unknown>((resolve) => {
      ws.on('message', (data) => {
        const parsed = JSON.parse(data.toString());
        received.push(parsed);
        if (
          parsed.type === 'hello' &&
          parsed.role === 'server' &&
          parsed.mcpId === 'opentable-mcp:0.9.1:abc1234567890def'
        ) {
          resolve(parsed);
        }
      });
    });
    const ownHello = (await ownHelloPromise) as Record<string, unknown>;
    expect(ownHello.serverName).toBe('opentable-mcp');
    expect(() => validateFrame(ownHello)).not.toThrow();

    ws.close();
  });

  // Additional tests covering multiplexing live in the integration test (Task 17).
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/server && npx vitest run test/host.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

```typescript
// packages/server/src/host.ts
import { Server as HttpServer } from 'node:http';
import { WebSocketServer, WebSocket } from 'ws';
import {
  ed25519Sign,
  ecdhX25519,
  hkdfSha256,
  sealInnerFrame,
  openEncryptedFrame,
  validateFrame,
  PROTOCOL_VERSION,
  type EncryptedFrame,
  type Frame,
  type HelloFrameFromServer,
  type InnerFrame,
  type ReadyFrame,
} from '@fetchproxy/protocol';
import { SessionState } from './session.js';
import type { Identity } from './identity.js';

const PUBLIC_ORIGIN_RE = /^https?:\/\/(?!(127\.0\.0\.1|localhost)(:|$))/i;

export interface HostOpts {
  httpServer: HttpServer;
  ownIdentity: Identity;
  ownMcpId: string;
  ownServerName: string;
  ownVersion: string;
  ownDomain: string;
}

export interface HostHandle {
  close: () => Promise<void>;
  /** Send an inner frame from the host's own MCP through the extension WS. */
  sendOwnInner: (inner: InnerFrame) => Promise<void>;
  /** Subscribe to inner frames addressed to the host's own MCP. */
  onOwnInner: (cb: (inner: InnerFrame) => void) => void;
}

interface PeerSlot {
  ws: WebSocket;
  helloFrame: HelloFrameFromServer;
  session?: SessionState;
  sessionNonce: Uint8Array;
}

const enc = new TextEncoder();

export async function startHost(opts: HostOpts): Promise<HostHandle> {
  const wss = new WebSocketServer({
    server: opts.httpServer,
    verifyClient: (info, cb) => {
      const origin = info.req.headers.origin;
      if (origin && PUBLIC_ORIGIN_RE.test(origin)) {
        cb(false, 403, 'origin not allowed');
        return;
      }
      cb(true);
    },
  });

  let extensionWs: WebSocket | null = null;
  const peers = new Map<string, PeerSlot>();           // mcpId → slot
  const ownInnerListeners: ((inner: InnerFrame) => void)[] = [];

  // The host's own "peer" session lives here too. We bootstrap by sending our
  // own hello frame down the extension WS as soon as one connects.
  const ownSessionNonce = new Uint8Array(32);
  (globalThis.crypto as Crypto).getRandomValues(ownSessionNonce);
  const ownSig = await ed25519Sign(
    opts.ownIdentity.ed25519Priv,
    concat(enc.encode(opts.ownMcpId), ownSessionNonce),
  );
  const ownHello: HelloFrameFromServer = {
    type: 'hello',
    protocolVersion: PROTOCOL_VERSION,
    role: 'server',
    mcpId: opts.ownMcpId,
    serverName: opts.ownServerName,
    version: opts.ownVersion,
    domain: opts.ownDomain,
    identityX25519Pub: toB64(opts.ownIdentity.x25519Pub),
    identityEd25519Pub: toB64(opts.ownIdentity.ed25519Pub),
    sessionNonce: toB64(ownSessionNonce),
    sessionSig: toB64(ownSig),
  };
  let ownSession: SessionState | null = null;

  wss.on('connection', (ws) => {
    let identified: 'extension' | 'peer' | null = null;
    let peerMcpId: string | null = null;

    ws.on('message', async (data) => {
      let frame: Frame;
      try {
        const raw = JSON.parse(data.toString());
        frame = validateFrame(raw);
      } catch {
        ws.close(1002, 'protocol error');
        return;
      }

      if (frame.type === 'hello' && frame.role === 'extension') {
        if (extensionWs) {
          ws.close(1008, 'extension already connected');
          return;
        }
        identified = 'extension';
        extensionWs = ws;
        // Send our own hello first.
        ws.send(JSON.stringify(ownHello));
        // Then forward any peer hellos that arrived earlier.
        for (const slot of peers.values()) {
          ws.send(JSON.stringify(slot.helloFrame));
        }
        return;
      }
      if (frame.type === 'hello' && frame.role === 'server') {
        identified = 'peer';
        peerMcpId = frame.mcpId;
        const sessionNonce = new Uint8Array(Buffer.from(frame.sessionNonce, 'base64'));
        peers.set(frame.mcpId, { ws, helloFrame: frame, sessionNonce });
        if (extensionWs) extensionWs.send(JSON.stringify(frame));
        return;
      }
      if (frame.type === 'ready') {
        // Extension → server. Either to the host's own MCP or a peer.
        if (frame.mcpId === opts.ownMcpId) {
          const extPub = new Uint8Array(Buffer.from(frame.extensionSessionPub, 'base64'));
          const shared = await ecdhX25519(opts.ownIdentity.x25519Priv, extPub);
          const key = await hkdfSha256(
            shared,
            ownSessionNonce,
            enc.encode('fetchproxy/0.1.0/session'),
            32,
          );
          ownSession = new SessionState(key);
        } else {
          const slot = peers.get(frame.mcpId);
          if (slot) slot.ws.send(JSON.stringify(frame));
        }
        return;
      }
      if (frame.type === 'frame') {
        if (identified === 'extension') {
          // Extension → server. Route by mcpId.
          if (frame.mcpId === opts.ownMcpId) {
            if (!ownSession) return;
            if (!ownSession.acceptInboundSeq(frame.seq)) return;
            const inner = await openEncryptedFrame(ownSession.sessionKey, frame);
            ownInnerListeners.forEach((cb) => cb(inner));
          } else {
            const slot = peers.get(frame.mcpId);
            if (slot) slot.ws.send(JSON.stringify(frame));
          }
        } else if (identified === 'peer') {
          // Peer → extension. Forward verbatim.
          if (extensionWs) extensionWs.send(JSON.stringify(frame));
        }
      }
    });

    ws.on('close', () => {
      if (identified === 'extension' && extensionWs === ws) extensionWs = null;
      if (identified === 'peer' && peerMcpId) peers.delete(peerMcpId);
    });
  });

  return {
    close: () =>
      new Promise<void>((resolve) => {
        wss.close(() => resolve());
      }),
    sendOwnInner: async (inner) => {
      if (!ownSession) throw new Error('host: no session yet');
      if (!extensionWs) throw new Error('host: no extension connected');
      const sealed = await sealInnerFrame(
        ownSession.sessionKey,
        opts.ownMcpId,
        ownSession.nextOutboundSeq(),
        inner,
      );
      extensionWs.send(JSON.stringify(sealed));
    },
    onOwnInner: (cb) => ownInnerListeners.push(cb),
  };
}

function toB64(b: Uint8Array): string {
  return Buffer.from(b).toString('base64');
}
function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/server && npx vitest run test/host.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/server/src/host.ts packages/server/tests/host.test.ts
git commit -m "feat(server): concentrator host — WS server, peer multiplexer, own-MCP session"
```

### Task 11: FetchproxyServer orchestrator

**Files:**
- Modify: `packages/server/src/ws-server.ts`
- Modify: `packages/server/src/index.ts`
- Test: `packages/server/tests/ws-server.test.ts` (update)

The public API stays as `FetchproxyServer`. Internally it now:
1. Loads identity.
2. Runs election.
3. If host → starts host + uses `sendOwnInner`/`onOwnInner` for fetch traffic.
4. If peer → starts peer + uses peer's `sendInner`/`onInner`.

This collapses the two paths behind a single `fetch(init)` method.

- [ ] **Step 1: Write failing tests**

```typescript
// packages/server/tests/ws-server.test.ts (replace existing test file)
import { describe, it, expect, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import { FetchproxyServer } from '../src/index.js';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('FetchproxyServer (host role)', () => {
  let srv: FetchproxyServer | null = null;
  afterEach(async () => {
    if (srv) await srv.close();
    srv = null;
  });

  it('starts on a free port as host', async () => {
    srv = new FetchproxyServer({
      port: 41050,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domain: 'opentable.com',
      identityDir: mkdtempSync(join(tmpdir(), 'fp-srv-')),
    });
    await srv.listen();
    expect(srv.role).toBe('host');
  });

  it('two servers in same process: first is host, second is peer', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fp-srv-'));
    const a = new FetchproxyServer({
      port: 41051,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domain: 'opentable.com',
      identityDir: dir,
    });
    await a.listen();
    expect(a.role).toBe('host');
    const b = new FetchproxyServer({
      port: 41051,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domain: 'resy.com',
      identityDir: dir,
    });
    await b.listen();
    expect(b.role).toBe('peer');
    await b.close();
    await a.close();
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/server && npx vitest run test/ws-server.test.ts`
Expected: FAIL — new API doesn't exist yet.

- [ ] **Step 3: Implement**

```typescript
// packages/server/src/ws-server.ts — replace
import { generateMcpId } from '@fetchproxy/protocol';
import type { InnerFrame, FetchInit } from '@fetchproxy/protocol';
import { electRole } from './election.js';
import { startHost, type HostHandle } from './host.js';
import { startPeer, type PeerHandle } from './peer.js';
import { loadOrCreateIdentity, type Identity } from './identity.js';

export interface FetchproxyServerOpts {
  port?: number;
  host?: string;
  serverName: string;
  version: string;
  domain: string;
  identityDir?: string;
}

export interface FetchResult {
  ok: true;
  status: number;
  url: string;
  body: string;
}

export interface FetchResultError {
  ok: false;
  error: string;
}

export class FetchproxyServer {
  public role: 'host' | 'peer' | null = null;
  private opts: Required<Pick<FetchproxyServerOpts, 'port' | 'host'>> & FetchproxyServerOpts;
  private hostHandle: HostHandle | null = null;
  private peerHandle: PeerHandle | null = null;
  private nextRequestId = 1;
  private pending = new Map<number, (r: FetchResult | FetchResultError) => void>();
  private mcpId!: string;
  private identity!: Identity;

  constructor(opts: FetchproxyServerOpts) {
    this.opts = {
      port: 37149,
      host: '127.0.0.1',
      ...opts,
    };
  }

  async listen(): Promise<void> {
    this.identity = await loadOrCreateIdentity(this.opts.serverName, this.opts.identityDir);
    this.mcpId = generateMcpId(this.opts.serverName, this.opts.version);
    const el = await electRole({ host: this.opts.host, port: this.opts.port });
    if (el.role === 'host') {
      this.role = 'host';
      this.hostHandle = await startHost({
        httpServer: el.server,
        ownIdentity: this.identity,
        ownMcpId: this.mcpId,
        ownServerName: this.opts.serverName,
        ownVersion: this.opts.version,
        ownDomain: this.opts.domain,
      });
      this.hostHandle.onOwnInner((inner) => this.onInner(inner));
    } else {
      this.role = 'peer';
      this.peerHandle = await startPeer({
        host: this.opts.host,
        port: this.opts.port,
        identity: this.identity,
        mcpId: this.mcpId,
        serverName: this.opts.serverName,
        version: this.opts.version,
        domain: this.opts.domain,
      });
      this.peerHandle.onInner((inner) => this.onInner(inner));
    }
  }

  async fetch(init: FetchInit): Promise<FetchResult | FetchResultError> {
    const id = this.nextRequestId++;
    const inner: InnerFrame = { type: 'request', id, op: 'fetch', init };
    const pending = new Promise<FetchResult | FetchResultError>((resolve) => {
      this.pending.set(id, resolve);
    });
    if (this.hostHandle) await this.hostHandle.sendOwnInner(inner);
    else if (this.peerHandle) await this.peerHandle.sendInner(inner);
    else throw new Error('not listening');
    return pending;
  }

  private onInner(inner: InnerFrame): void {
    if (inner.type === 'response') {
      const cb = this.pending.get(inner.id);
      if (cb) {
        this.pending.delete(inner.id);
        if (inner.ok) {
          cb({ ok: true, status: inner.status, url: inner.url, body: inner.body });
        } else {
          cb({ ok: false, error: inner.error });
        }
      }
    }
  }

  async close(): Promise<void> {
    if (this.hostHandle) await this.hostHandle.close();
    if (this.peerHandle) this.peerHandle.close();
    this.hostHandle = null;
    this.peerHandle = null;
    this.role = null;
  }
}
```

```typescript
// packages/server/src/index.ts — replace
export { FetchproxyServer } from './ws-server.js';
export type { FetchproxyServerOpts, FetchResult, FetchResultError } from './ws-server.js';
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/server && npx vitest run`
Expected: PASS — including ws-server.test.ts.

- [ ] **Step 5: Commit**

```bash
git add packages/server/src/ws-server.ts packages/server/src/index.ts packages/server/tests/ws-server.test.ts
git commit -m "feat(server): FetchproxyServer orchestrator — election → host or peer role"
```

---

## Phase C — Extension-side trust + session + multiplexing

> **Note on extension keying:** 0.1.0 uses a per-session ephemeral X25519 keypair on the extension side (no persistent extension identity). The session key is derived as `HKDF-SHA256(ECDH(extEphemeralPriv, mcpIdentityPub), salt=sessionNonce, info="fetchproxy/0.1.0/session", 32)`. Since the `sessionNonce` (from the MCP's hello) is fresh per connection, each session has a distinct sessionKey even though the MCP's identity is long-term. A persistent extension identity may be added in a future release for MCP-side authentication of the extension; not needed for 0.1.0.

### Task 12: Trust store re-key (identityHash + serverName + domain)

**Files:**
- Modify: `packages/extension-core/src/trust-store.ts`
- Modify: `packages/extension-core/tests/trust-store.test.ts`

- [ ] **Step 1: Write failing tests**

```typescript
// packages/extension-core/tests/trust-store.test.ts — replace
import { describe, it, expect, beforeEach } from 'vitest';
import { TrustStore } from '../src/trust-store.js';

function mockStorage() {
  const data: Record<string, unknown> = {};
  (globalThis as { chrome?: unknown }).chrome = {
    storage: {
      local: {
        get: async (k: string) => (k in data ? { [k]: data[k] } : {}),
        set: async (kv: Record<string, unknown>) => Object.assign(data, kv),
        remove: async (k: string) => { delete data[k]; },
      },
    },
  };
  return data;
}

describe('TrustStore', () => {
  beforeEach(() => mockStorage());

  it('returns null for unknown identity hash', async () => {
    const store = new TrustStore('0.1.0');
    expect(await store.get('abc')).toBeNull();
  });

  it('persists and retrieves a trust record', async () => {
    const store = new TrustStore('0.1.0');
    await store.put('hash1', {
      serverName: 'opentable-mcp',
      domain: 'opentable.com',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'BBBB',
    });
    const got = await store.get('hash1');
    expect(got).not.toBeNull();
    expect(got!.serverName).toBe('opentable-mcp');
    expect(got!.extensionVersionAtPair).toBe('0.1.0');
  });

  it('invalidates trust on extension major version bump', async () => {
    const s1 = new TrustStore('0.1.0');
    await s1.put('hash1', {
      serverName: 'opentable-mcp',
      domain: 'opentable.com',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'BBBB',
    });
    const s2 = new TrustStore('1.0.0');
    expect(await s2.get('hash1')).toBeNull();
  });

  it('preserves trust on patch version bump', async () => {
    const s1 = new TrustStore('0.1.0');
    await s1.put('hash1', {
      serverName: 'opentable-mcp',
      domain: 'opentable.com',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'BBBB',
    });
    const s2 = new TrustStore('0.1.5');
    expect(await s2.get('hash1')).not.toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/extension-core && npx vitest run test/trust-store.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement (replace existing trust-store)**

```typescript
// packages/extension-core/src/trust-store.ts — replace
declare const chrome: {
  storage: {
    local: {
      get: (k: string) => Promise<Record<string, unknown>>;
      set: (kv: Record<string, unknown>) => Promise<void>;
      remove: (k: string) => Promise<void>;
    };
  };
};

const STORAGE_KEY = 'trustedMcps';

export interface TrustRecord {
  serverName: string;
  domain: string;
  identityX25519Pub: string;
  identityEd25519Pub: string;
  pairedAt: number;
  extensionVersionAtPair: string;
}

interface TrustInput {
  serverName: string;
  domain: string;
  identityX25519Pub: string;
  identityEd25519Pub: string;
}

interface StoredShape {
  records: Record<string, TrustRecord>;
}

function majorOf(v: string): number {
  return Number(v.split('.')[0]);
}

export class TrustStore {
  constructor(private extensionVersion: string) {}

  async get(identityHash: string): Promise<TrustRecord | null> {
    const stored = await this.load();
    const rec = stored.records[identityHash];
    if (!rec) return null;
    if (majorOf(rec.extensionVersionAtPair) !== majorOf(this.extensionVersion)) {
      return null;  // invalidated by major-version bump
    }
    return rec;
  }

  async put(identityHash: string, input: TrustInput): Promise<void> {
    const stored = await this.load();
    stored.records[identityHash] = {
      ...input,
      pairedAt: Date.now(),
      extensionVersionAtPair: this.extensionVersion,
    };
    await chrome.storage.local.set({ [STORAGE_KEY]: stored });
  }

  async remove(identityHash: string): Promise<void> {
    const stored = await this.load();
    delete stored.records[identityHash];
    await chrome.storage.local.set({ [STORAGE_KEY]: stored });
  }

  async list(): Promise<Record<string, TrustRecord>> {
    const stored = await this.load();
    return { ...stored.records };
  }

  private async load(): Promise<StoredShape> {
    const got = await chrome.storage.local.get(STORAGE_KEY);
    const raw = got[STORAGE_KEY] as StoredShape | undefined;
    return raw && raw.records ? raw : { records: {} };
  }
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/extension-core && npx vitest run test/trust-store.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/extension-core/src/trust-store.ts packages/extension-core/tests/trust-store.test.ts
git commit -m "refactor(extension-core): trust store keyed by identity hash; drop port from key"
```

### Task 13: Session-keys cache (extension side)

**Files:**
- Create: `packages/extension-core/src/session-keys.ts`
- Test: `packages/extension-core/tests/session-keys.test.ts`

- [ ] **Step 1: Write failing tests**

```typescript
// packages/extension-core/tests/session-keys.test.ts
import { describe, it, expect } from 'vitest';
import { SessionKeys } from '../src/session-keys.js';

describe('SessionKeys', () => {
  it('returns null for unknown mcpId', () => {
    const sk = new SessionKeys();
    expect(sk.get('opentable-mcp:0.1.0:abc1234567890def')).toBeNull();
  });

  it('stores and retrieves a session', () => {
    const sk = new SessionKeys();
    const key = new Uint8Array(32).fill(7);
    sk.set('opentable-mcp:0.1.0:abc1234567890def', key);
    const s = sk.get('opentable-mcp:0.1.0:abc1234567890def');
    expect(s).not.toBeNull();
    expect(Buffer.from(s!.sessionKey).equals(Buffer.from(key))).toBe(true);
  });

  it('rejects replayed inbound seq', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    const s = sk.get('mcp:1.0.0:0000000000000000')!;
    expect(s.acceptInboundSeq(1)).toBe(true);
    expect(s.acceptInboundSeq(1)).toBe(false);
  });

  it('issues monotonic outbound seq', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    const s = sk.get('mcp:1.0.0:0000000000000000')!;
    expect(s.nextOutboundSeq()).toBe(1);
    expect(s.nextOutboundSeq()).toBe(2);
  });

  it('removes a session', () => {
    const sk = new SessionKeys();
    sk.set('mcp:1.0.0:0000000000000000', new Uint8Array(32));
    sk.remove('mcp:1.0.0:0000000000000000');
    expect(sk.get('mcp:1.0.0:0000000000000000')).toBeNull();
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/extension-core && npx vitest run test/session-keys.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

```typescript
// packages/extension-core/src/session-keys.ts
export class SessionEntry {
  public readonly sessionKey: Uint8Array;
  private outbound = 0;
  private lastInbound = 0;

  constructor(sessionKey: Uint8Array) {
    this.sessionKey = sessionKey;
  }

  nextOutboundSeq(): number {
    this.outbound += 1;
    return this.outbound;
  }
  acceptInboundSeq(seq: number): boolean {
    if (seq <= this.lastInbound) return false;
    this.lastInbound = seq;
    return true;
  }
}

export class SessionKeys {
  private map = new Map<string, SessionEntry>();

  get(mcpId: string): SessionEntry | null {
    return this.map.get(mcpId) ?? null;
  }
  set(mcpId: string, sessionKey: Uint8Array): SessionEntry {
    const e = new SessionEntry(sessionKey);
    this.map.set(mcpId, e);
    return e;
  }
  remove(mcpId: string): void {
    this.map.delete(mcpId);
  }
}
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/extension-core && npx vitest run test/session-keys.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/extension-core/src/session-keys.ts packages/extension-core/tests/session-keys.test.ts
git commit -m "feat(extension-core): per-mcpId session key cache with replay protection"
```

### Task 14: ensureDomainTab helper

**Files:**
- Create: `packages/extension-core/src/ensure-domain-tab.ts`
- Test: `packages/extension-core/tests/ensure-domain-tab.test.ts`

After a successful pair (or auto-trust on a known MCP), the extension ensures a tab matching the MCP's `domain` is open — if none exists, it opens `https://<domain>/` in a new tab. The fetch RPC machinery needs a matching tab to issue same-origin `window.fetch` calls, so this avoids the "first fetch fails because no tab" footgun.

- [ ] **Step 1: Write failing tests**

```typescript
// packages/extension-core/tests/ensure-domain-tab.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { ensureDomainTab } from '../src/ensure-domain-tab.js';

interface FakeTab {
  id: number;
  url: string;
}

function mockTabs(initial: FakeTab[]) {
  let nextId = 1000;
  const tabs: FakeTab[] = [...initial];
  const created: FakeTab[] = [];
  (globalThis as { chrome?: unknown }).chrome = {
    tabs: {
      query: async (q: { url?: string | string[] }) => {
        if (!q.url) return [...tabs];
        const patterns = Array.isArray(q.url) ? q.url : [q.url];
        // Translate `*://opentable.com/*` style patterns to a host match.
        return tabs.filter((t) =>
          patterns.some((p) => {
            const host = p.replace(/^\*:\/\//, '').replace(/\/\*$/, '').toLowerCase();
            try {
              const u = new URL(t.url);
              return u.hostname === host || u.hostname.endsWith('.' + host);
            } catch {
              return false;
            }
          }),
        );
      },
      create: async (props: { url: string }) => {
        const tab: FakeTab = { id: nextId++, url: props.url };
        created.push(tab);
        tabs.push(tab);
        return tab;
      },
    },
  };
  return { tabs, created };
}

describe('ensureDomainTab', () => {
  it('does nothing when a matching tab already exists', async () => {
    const { created } = mockTabs([{ id: 1, url: 'https://www.opentable.com/somewhere' }]);
    const result = await ensureDomainTab('opentable.com');
    expect(result.opened).toBe(false);
    expect(created).toEqual([]);
  });

  it('opens a new tab when no tab matches', async () => {
    const { created } = mockTabs([{ id: 1, url: 'https://example.com/' }]);
    const result = await ensureDomainTab('opentable.com');
    expect(result.opened).toBe(true);
    expect(created).toHaveLength(1);
    expect(created[0].url).toBe('https://opentable.com/');
  });

  it('matches subdomains', async () => {
    const { created } = mockTabs([{ id: 1, url: 'https://www.opentable.com/users' }]);
    const result = await ensureDomainTab('opentable.com');
    expect(result.opened).toBe(false);
    expect(created).toEqual([]);
  });

  it('refuses to open if the domain is not a valid hostname', async () => {
    mockTabs([]);
    await expect(ensureDomainTab('not a domain')).rejects.toThrow();
    await expect(ensureDomainTab('')).rejects.toThrow();
    await expect(ensureDomainTab('opentable.com/path')).rejects.toThrow();
  });
});
```

- [ ] **Step 2: Run tests to verify failure**

```
cd packages/extension-core && npx vitest run tests/ensure-domain-tab.test.ts
```
Expected: FAIL.

- [ ] **Step 3: Implement**

```typescript
// packages/extension-core/src/ensure-domain-tab.ts
declare const chrome: {
  tabs: {
    query: (q: { url?: string | string[] }) => Promise<{ id?: number; url?: string }[]>;
    create: (props: { url: string }) => Promise<{ id?: number; url?: string }>;
  };
};

const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

export interface EnsureDomainTabResult {
  opened: boolean;
}

export async function ensureDomainTab(domain: string): Promise<EnsureDomainTabResult> {
  if (!domain || !HOSTNAME_RE.test(domain)) {
    throw new Error(`ensureDomainTab: invalid domain ${JSON.stringify(domain)}`);
  }
  const patterns = [
    `*://${domain}/*`,
    `*://*.${domain}/*`,
  ];
  const tabs = await chrome.tabs.query({ url: patterns });
  if (tabs.length > 0) return { opened: false };
  await chrome.tabs.create({ url: `https://${domain}/` });
  return { opened: true };
}
```

- [ ] **Step 4: Run tests to verify pass**

```
cd packages/extension-core && npx vitest run tests/ensure-domain-tab.test.ts
```
Expected: PASS — 4/4.

- [ ] **Step 5: Commit**

```bash
git add packages/extension-core/src/ensure-domain-tab.ts packages/extension-core/tests/ensure-domain-tab.test.ts
git commit -m "feat(extension-core): ensureDomainTab — open MCP domain tab after pairing if absent"
```

### Task 15: Background.ts multiplexed routing

**Files:**
- Modify: `packages/extension-core/src/background.ts`
- Test: `packages/extension-core/tests/background.test.ts` (replace)

This is the biggest extension-side task. The background script now:
1. Maintains one WS to the host (auto-reconnect with backoff).
2. On `hello` from server: pass to `handleServerHello`. If `kind === 'auto-trust'` → call `ensureDomainTab(hello.domain)`, then send `ready`. If `kind === 'needs-pair'` → enqueue pair prompt for the popup.
3. On `frame`: look up `mcpId` in `SessionKeys`, decrypt, dispatch inner frame.
4. On approval signal from popup: persist trust record, derive session key (same logic as the auto-trust branch in `handleServerHello`), call `ensureDomainTab(hello.domain)`, then send `ready`.

`ensureDomainTab` is fire-and-forget — its result doesn't gate the `ready` frame, because tab open + page load takes longer than the handshake. The server's first `fetch` may still race the tab load; that's acceptable (same behavior as today, but at least the tab exists).

Because tests for the full WS dance are heavy, this task's tests focus on the **pair-prompt decision tree** + the **handshake key derivation**, with WS itself mocked.

- [ ] **Step 1: Write failing tests**

```typescript
// packages/extension-core/tests/background.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { handleServerHello } from '../src/background.js';
import { TrustStore } from '../src/trust-store.js';
import {
  generateX25519,
  generateEd25519,
  ed25519Sign,
  sha256,
  derivePairCode,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';

function mockStorage() {
  const data: Record<string, unknown> = {};
  (globalThis as { chrome?: unknown }).chrome = {
    storage: {
      local: {
        get: async (k: string | string[]) => {
          const ks = Array.isArray(k) ? k : [k];
          const out: Record<string, unknown> = {};
          for (const x of ks) if (x in data) out[x] = data[x];
          return out;
        },
        set: async (kv: Record<string, unknown>) => Object.assign(data, kv),
        remove: async (x: string) => { delete data[x]; },
      },
    },
  };
}

async function buildServerHello(mcpId: string, serverName: string, domain: string) {
  const x = await generateX25519();
  const ed = await generateEd25519();
  const sessionNonce = new Uint8Array(32).fill(9);
  const sig = await ed25519Sign(
    ed.privateKey,
    concat(new TextEncoder().encode(mcpId), sessionNonce),
  );
  const hello: HelloFrameFromServer = {
    type: 'hello',
    protocolVersion: 1,
    role: 'server',
    mcpId,
    serverName,
    version: '0.9.1',
    domain,
    identityX25519Pub: Buffer.from(x.publicKey).toString('base64'),
    identityEd25519Pub: Buffer.from(ed.publicKey).toString('base64'),
    sessionNonce: Buffer.from(sessionNonce).toString('base64'),
    sessionSig: Buffer.from(sig).toString('base64'),
  };
  return { hello, xKeys: x, edKeys: ed };
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

describe('handleServerHello', () => {
  beforeEach(() => mockStorage());

  it('returns pair-prompt for unknown identity', async () => {
    const { hello } = await buildServerHello(
      'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      'opentable-mcp',
      'opentable.com',
    );
    const trust = new TrustStore('0.1.0');
    const result = await handleServerHello(hello, { trust });
    expect(result.kind).toBe('needs-pair');
    if (result.kind === 'needs-pair') {
      const expectedPub = new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'));
      expect(result.pairCode).toBe(await derivePairCode(expectedPub));
    }
  });

  it('returns auto-trust for known identity, derives session key', async () => {
    const { hello } = await buildServerHello(
      'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      'opentable-mcp',
      'opentable.com',
    );
    const trust = new TrustStore('0.1.0');
    const idHash = Buffer.from(
      await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
    ).toString('hex');
    await trust.put(idHash, {
      serverName: 'opentable-mcp',
      domain: 'opentable.com',
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
    });
    const result = await handleServerHello(hello, { trust });
    expect(result.kind).toBe('auto-trust');
    if (result.kind === 'auto-trust') {
      expect(result.sessionKey.byteLength).toBe(32);
      expect(result.extensionSessionPub.byteLength).toBe(32);
    }
  });

  it('rejects hello with invalid sessionSig', async () => {
    const { hello } = await buildServerHello(
      'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      'opentable-mcp',
      'opentable.com',
    );
    // Mutate sessionSig
    const bad = { ...hello, sessionSig: Buffer.from(new Uint8Array(64).fill(0)).toString('base64') };
    const trust = new TrustStore('0.1.0');
    const result = await handleServerHello(bad, { trust });
    expect(result.kind).toBe('reject');
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/extension-core && npx vitest run test/background.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement `handleServerHello` (the pure-function core), then wire into background.ts**

```typescript
// packages/extension-core/src/background.ts — replace
import {
  ed25519Verify,
  ecdhX25519,
  hkdfSha256,
  derivePairCode,
  sha256,
  generateX25519,
  validateFrame,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import { TrustStore } from './trust-store.js';
import { SessionKeys } from './session-keys.js';

export interface HandleHelloDeps {
  trust: TrustStore;
}

export type HandleHelloResult =
  | { kind: 'reject'; reason: string }
  | {
      kind: 'needs-pair';
      pairCode: string;
      identityHash: string;
      mcpId: string;
      serverName: string;
      domain: string;
      identityX25519Pub: string;
      identityEd25519Pub: string;
      sessionNonce: Uint8Array;
    }
  | {
      kind: 'auto-trust';
      mcpId: string;
      sessionKey: Uint8Array;
      extensionSessionPub: Uint8Array;
    };

const enc = new TextEncoder();

export async function handleServerHello(
  hello: HelloFrameFromServer,
  deps: HandleHelloDeps,
): Promise<HandleHelloResult> {
  const identityX25519Pub = new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'));
  const identityEd25519Pub = new Uint8Array(Buffer.from(hello.identityEd25519Pub, 'base64'));
  const sessionNonce = new Uint8Array(Buffer.from(hello.sessionNonce, 'base64'));
  const sessionSig = new Uint8Array(Buffer.from(hello.sessionSig, 'base64'));

  // 1. Verify signature.
  const sigOk = await ed25519Verify(
    identityEd25519Pub,
    concat(enc.encode(hello.mcpId), sessionNonce),
    sessionSig,
  );
  if (!sigOk) return { kind: 'reject', reason: 'sessionSig invalid' };

  // 2. Look up trust.
  const hash = Buffer.from(await sha256(identityX25519Pub)).toString('hex');
  const record = await deps.trust.get(hash);
  if (record) {
    // Server-name and domain must match what we paired with.
    if (record.serverName !== hello.serverName || record.domain !== hello.domain) {
      return { kind: 'reject', reason: 'serverName/domain mismatch with trust record' };
    }
    // Derive session key: ephemeral extension keypair × MCP's long-term identity X25519,
    // freshened by sessionNonce as HKDF salt.
    const ephemeral = await generateX25519();
    const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
    const sessionKey = await hkdfSha256(
      shared,
      sessionNonce,
      enc.encode('fetchproxy/0.1.0/session'),
      32,
    );
    return {
      kind: 'auto-trust',
      mcpId: hello.mcpId,
      sessionKey,
      extensionSessionPub: ephemeral.publicKey,  // sent back to MCP in the ready frame
    };
  }

  // 3. Need pairing prompt.
  const pairCode = await derivePairCode(identityX25519Pub);
  return {
    kind: 'needs-pair',
    pairCode,
    identityHash: hash,
    mcpId: hello.mcpId,
    serverName: hello.serverName,
    domain: hello.domain,
    identityX25519Pub: hello.identityX25519Pub,
    identityEd25519Pub: hello.identityEd25519Pub,
    sessionNonce,
  };
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// The WS-driving glue (connect, route encrypted frames, fetch handler, etc.)
// lives below. handleServerHello above is the unit-testable core.

// ... existing background.ts WS scaffolding stays but is refactored to call
//     handleServerHello for each `hello` and route by mcpId through SessionKeys.
//     Pair prompts are queued through chrome.storage for the popup to surface.
```

(Full background.ts WS plumbing is largely refactoring — covered by Task 16's tests for the popup integration. The unit tests here cover the pure decision logic.)

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/extension-core && npx vitest run test/background.test.ts`
Expected: PASS — 3/3.

- [ ] **Step 5: Commit**

```bash
git add packages/extension-core/src/background.ts packages/extension-core/tests/background.test.ts
git commit -m "feat(extension-core): handleServerHello — signature verify, trust lookup, key derivation"
```

### Task 16: Popup pair-code prefilled UI

**Files:**
- Modify: `packages/extension-core/src/popup/popup.ts`
- Modify: `packages/extension-core/src/popup/popup.html`
- Test: `packages/extension-core/tests/popup.test.ts` (replace)

The popup now has three view modes:
- **pending-pair**: shows server-name, domain, pair code, [Cancel] [Approve] buttons (default focus on Cancel).
- **status**: shows list of trusted MCPs (server-name + domain) with disconnect option.
- **empty**: shows installation hint if no MCPs ever connected.

The pending-pair view's `Approve` click writes a record to `chrome.storage.local` that the background script consumes to finish the handshake.

- [ ] **Step 1: Write failing tests**

```typescript
// packages/extension-core/tests/popup.test.ts — replace
import { describe, it, expect, beforeEach } from 'vitest';
import { renderPopup, type PopupState } from '../src/popup/popup.js';

describe('renderPopup', () => {
  let container: HTMLElement;

  beforeEach(() => {
    document.body.innerHTML = '<div id="root"></div>';
    container = document.getElementById('root')!;
  });

  it('shows empty state when no pending and no trusted', () => {
    renderPopup(container, { mode: 'empty' });
    expect(container.textContent).toContain('No MCP servers connected');
  });

  it('shows status with trusted MCPs', () => {
    const state: PopupState = {
      mode: 'status',
      trusted: [
        { serverName: 'opentable-mcp', domain: 'opentable.com' },
        { serverName: 'resy-mcp', domain: 'resy.com' },
      ],
    };
    renderPopup(container, state);
    expect(container.textContent).toContain('opentable-mcp');
    expect(container.textContent).toContain('resy-mcp');
  });

  it('shows pending-pair with code prefilled', () => {
    const state: PopupState = {
      mode: 'pending-pair',
      pending: {
        serverName: 'opentable-mcp',
        version: '0.9.1',
        domain: 'opentable.com',
        pairCode: '472-918',
      },
      onApprove: () => undefined,
      onCancel: () => undefined,
    };
    renderPopup(container, state);
    expect(container.textContent).toContain('472-918');
    expect(container.textContent).toContain('opentable.com');
    const approve = container.querySelector('[data-action="approve"]') as HTMLButtonElement;
    const cancel = container.querySelector('[data-action="cancel"]') as HTMLButtonElement;
    expect(approve).not.toBeNull();
    expect(cancel).not.toBeNull();
    // Default focus is cancel
    expect(cancel.getAttribute('autofocus')).not.toBeNull();
  });

  it('calls onApprove when Approve clicked', () => {
    let called = false;
    const state: PopupState = {
      mode: 'pending-pair',
      pending: {
        serverName: 'opentable-mcp',
        version: '0.9.1',
        domain: 'opentable.com',
        pairCode: '472-918',
      },
      onApprove: () => { called = true; },
      onCancel: () => undefined,
    };
    renderPopup(container, state);
    (container.querySelector('[data-action="approve"]') as HTMLButtonElement).click();
    expect(called).toBe(true);
  });

  it('marks high-risk domains', () => {
    const state: PopupState = {
      mode: 'pending-pair',
      pending: {
        serverName: 'some-bank-mcp',
        version: '0.0.1',
        domain: 'chase.bank',
        pairCode: '111-222',
      },
      onApprove: () => undefined,
      onCancel: () => undefined,
    };
    renderPopup(container, state);
    expect(container.textContent?.toLowerCase()).toContain('high-risk');
  });
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/extension-core && npx vitest run test/popup.test.ts`
Expected: FAIL.

- [ ] **Step 3: Implement**

```typescript
// packages/extension-core/src/popup/popup.ts — replace
const HIGH_RISK_KEYWORDS = ['bank', 'gov', 'mil'];

export interface PendingPair {
  serverName: string;
  version: string;
  domain: string;
  pairCode: string;
}

export interface TrustedSummary {
  serverName: string;
  domain: string;
}

export type PopupState =
  | { mode: 'empty' }
  | { mode: 'status'; trusted: TrustedSummary[] }
  | {
      mode: 'pending-pair';
      pending: PendingPair;
      onApprove: () => void;
      onCancel: () => void;
    };

function isHighRisk(domain: string): boolean {
  const d = domain.toLowerCase();
  return HIGH_RISK_KEYWORDS.some((k) => d.includes(k));
}

export function renderPopup(root: HTMLElement, state: PopupState): void {
  root.innerHTML = '';
  if (state.mode === 'empty') {
    const p = document.createElement('p');
    p.textContent = 'No MCP servers connected. Start an MCP server and refresh.';
    root.appendChild(p);
    return;
  }
  if (state.mode === 'status') {
    const h = document.createElement('h3');
    h.textContent = 'Trusted MCPs';
    root.appendChild(h);
    const ul = document.createElement('ul');
    for (const t of state.trusted) {
      const li = document.createElement('li');
      li.textContent = `${t.serverName} → ${t.domain}`;
      ul.appendChild(li);
    }
    root.appendChild(ul);
    return;
  }
  // pending-pair
  const { pending, onApprove, onCancel } = state;
  const title = document.createElement('h3');
  title.textContent = 'Approve new MCP connection?';
  root.appendChild(title);

  const info = document.createElement('dl');
  for (const [k, v] of [
    ['Server', `${pending.serverName} v${pending.version}`],
    ['Domain', pending.domain],
  ]) {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.textContent = v;
    info.appendChild(dt);
    info.appendChild(dd);
  }
  root.appendChild(info);

  if (isHighRisk(pending.domain)) {
    const warn = document.createElement('p');
    warn.className = 'warn';
    warn.textContent = `WARNING: ${pending.domain} looks high-risk.`;
    root.appendChild(warn);
  }

  const codeBox = document.createElement('div');
  codeBox.className = 'pair-code';
  codeBox.textContent = pending.pairCode;
  root.appendChild(codeBox);

  const hint = document.createElement('p');
  hint.className = 'hint';
  hint.textContent =
    'Verify this code matches the one shown in the server\'s terminal before approving.';
  root.appendChild(hint);

  const btnRow = document.createElement('div');
  btnRow.className = 'btn-row';

  const cancel = document.createElement('button');
  cancel.dataset.action = 'cancel';
  cancel.textContent = 'Cancel';
  cancel.setAttribute('autofocus', 'true');
  cancel.addEventListener('click', onCancel);

  const approve = document.createElement('button');
  approve.dataset.action = 'approve';
  approve.textContent = 'Approve';
  approve.addEventListener('click', onApprove);

  btnRow.appendChild(cancel);
  btnRow.appendChild(approve);
  root.appendChild(btnRow);
}
```

```html
<!-- packages/extension-core/src/popup/popup.html — minimal shell -->
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <style>
      body { font-family: -apple-system, sans-serif; padding: 12px; min-width: 320px; }
      .pair-code { font-size: 24px; font-weight: bold; text-align: center; margin: 12px 0; letter-spacing: 2px; }
      .warn { color: #b00; }
      .hint { color: #666; font-size: 12px; }
      .btn-row { display: flex; gap: 8px; justify-content: flex-end; }
      button { padding: 8px 16px; cursor: pointer; }
      button[data-action="cancel"] { background: #eee; }
      button[data-action="approve"] { background: #d62; color: white; border: none; }
    </style>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="./popup.js"></script>
  </body>
</html>
```

- [ ] **Step 4: Run test to verify pass**

Run: `cd packages/extension-core && npx vitest run test/popup.test.ts`
Expected: PASS — 5/5.

- [ ] **Step 5: Commit**

```bash
git add packages/extension-core/src/popup/ packages/extension-core/tests/popup.test.ts
git commit -m "feat(extension-core): popup pair-prompt with prefilled code (cancel-default focus)"
```

---

## Phase D — Wiring + migration + ship

### Task 17: Two-MCP-one-host integration test

**Files:**
- Create: `packages/server/tests/integration/two-mcps.test.ts`

End-to-end test in Node: stand up MCP A (host), MCP B (peer), a mock extension WS client, do a `fetch` from each MCP, verify the responses route correctly + ciphertext is encrypted under different session keys.

- [ ] **Step 1: Write failing test**

```typescript
// packages/server/tests/integration/two-mcps.test.ts
import { describe, it, expect, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import { FetchproxyServer } from '../../src/index.js';
import {
  validateFrame,
  generateX25519,
  ecdhX25519,
  hkdfSha256,
  sealInnerFrame,
  openEncryptedFrame,
  type HelloFrameFromExtension,
  type HelloFrameFromServer,
  type ReadyFrame,
  type EncryptedFrame,
} from '@fetchproxy/protocol';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('two MCPs one host integration', () => {
  let a: FetchproxyServer | null = null;
  let b: FetchproxyServer | null = null;

  afterEach(async () => {
    if (a) await a.close();
    if (b) await b.close();
    a = null;
    b = null;
  });

  it('host (A) and peer (B) both route fetches through one extension WS', async () => {
    const port = 41010;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-int-'));
    a = new FetchproxyServer({
      port,
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domain: 'opentable.com',
      identityDir: idDir,
    });
    await a.listen();
    expect(a.role).toBe('host');

    b = new FetchproxyServer({
      port,
      serverName: 'resy-mcp',
      version: '0.0.1',
      domain: 'resy.com',
      identityDir: idDir,
    });
    await b.listen();
    expect(b.role).toBe('peer');

    // Mock extension
    const extWs = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r, j) => {
      extWs.once('open', () => r());
      extWs.once('error', j);
    });

    // Build extension X25519 keypair
    const extKp = await generateX25519();

    // Track sessions per mcpId
    interface Track {
      sessionKey?: Uint8Array;
      nonce?: Uint8Array;
      identityX25519Pub?: Uint8Array;
    }
    const tracks = new Map<string, Track>();

    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: 1,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.1.0',
    };
    extWs.send(JSON.stringify(extHello));

    // Wait for both server hellos to arrive
    const sawBoth = new Promise<void>((resolve) => {
      const need = new Set(['opentable-mcp', 'resy-mcp']);
      extWs.on('message', async (data) => {
        const raw = JSON.parse(data.toString());
        const frame = validateFrame(raw);
        if (frame.type === 'hello' && frame.role === 'server') {
          tracks.set(frame.mcpId, {
            nonce: new Uint8Array(Buffer.from(frame.sessionNonce, 'base64')),
            identityX25519Pub: new Uint8Array(Buffer.from(frame.identityX25519Pub, 'base64')),
          });
          // Reply with ready (auto-approve in this test — trust gate is unit-tested separately)
          const shared = await ecdhX25519(
            extKp.privateKey,
            new Uint8Array(Buffer.from(frame.identityX25519Pub, 'base64')),
          );
          const sessionKey = await hkdfSha256(
            shared,
            new Uint8Array(Buffer.from(frame.sessionNonce, 'base64')),
            new TextEncoder().encode('fetchproxy/0.1.0/session'),
            32,
          );
          tracks.get(frame.mcpId)!.sessionKey = sessionKey;
          const ready: ReadyFrame = {
            type: 'ready',
            mcpId: frame.mcpId,
            extensionSessionPub: Buffer.from(extKp.publicKey).toString('base64'),
          };
          extWs.send(JSON.stringify(ready));
          need.delete(frame.serverName);
          if (need.size === 0) resolve();
        }
      });
    });
    await sawBoth;

    // Set up response handler: when MCP sends a fetch request, return a canned response
    extWs.on('message', async (data) => {
      const raw = JSON.parse(data.toString());
      const frame = validateFrame(raw);
      if (frame.type !== 'frame') return;
      const track = tracks.get(frame.mcpId);
      if (!track?.sessionKey) return;
      const inner = await openEncryptedFrame(track.sessionKey, frame);
      if (inner.type !== 'request') return;
      const responseInner = {
        type: 'response' as const,
        id: inner.id,
        ok: true as const,
        status: 200,
        url: inner.init.url,
        body: `echo from ${frame.mcpId}`,
      };
      const sealed = await sealInnerFrame(track.sessionKey, frame.mcpId, 999, responseInner);
      extWs.send(JSON.stringify(sealed));
    });

    // Each MCP issues a fetch — host (A) and peer (B) — both should succeed.
    const [ra, rb] = await Promise.all([
      a.fetch({ url: 'https://opentable.com/x', method: 'GET', tabUrl: 'https://opentable.com/' }),
      b.fetch({ url: 'https://resy.com/y', method: 'GET', tabUrl: 'https://resy.com/' }),
    ]);

    expect(ra.ok).toBe(true);
    if (ra.ok) expect(ra.body).toContain('opentable-mcp');
    expect(rb.ok).toBe(true);
    if (rb.ok) expect(rb.body).toContain('resy-mcp');

    // Crucial: the session keys for A and B must differ.
    const aKey = [...tracks.values()][0].sessionKey!;
    const bKey = [...tracks.values()][1].sessionKey!;
    expect(Buffer.from(aKey).equals(Buffer.from(bKey))).toBe(false);

    extWs.close();
  }, 30000);
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `cd packages/server && npx vitest run test/integration/two-mcps.test.ts`
Expected: FAIL if any wire incompatibility lurks. (If everything in Phases A–C is correct, it should PASS — this is the meta-check.)

- [ ] **Step 3: Iterate until pass**

Fix any cross-component bugs revealed. Don't modify the test — fix the code.

- [ ] **Step 4: Confirm PASS**

Run: `cd packages/server && npx vitest run`
Expected: PASS — all tests including integration.

- [ ] **Step 5: Commit**

```bash
git add packages/server/tests/integration/two-mcps.test.ts
git commit -m "test: two-MCPs-one-host end-to-end integration (host + peer + extension mock)"
```

### Task 18: Update extension-chrome bundle config

**Files:**
- Modify: `packages/extension-chrome/build.ts`
- Modify: `packages/extension-chrome/manifest.json`

The new code adds `extension-identity.ts`, `session-keys.ts`, and crypto wrappers. esbuild bundling should pick them up automatically since they're imported by background.ts.

The manifest version bumps to `0.1.0`.

- [ ] **Step 1: Bump manifest version**

Modify `packages/extension-chrome/manifest.json` to set `"version": "0.1.0"`.

- [ ] **Step 2: Build extension**

Run: `cd packages/extension-chrome && npx tsx build.ts`
Expected: clean build, no missing imports.

- [ ] **Step 3: Verify dist contents**

Run: `ls packages/extension-chrome/dist/`
Expected: `background.js`, `content.js`, `capture-logger.js`, `popup.js`, `popup.html`, `manifest.json`, `icons/`.

- [ ] **Step 4: Load unpacked in Chrome and check console**

User action: chrome://extensions → Load unpacked → select dist/. Confirm no errors in background's service worker console.

- [ ] **Step 5: Commit**

```bash
git add packages/extension-chrome/manifest.json
git commit -m "chore(extension-chrome): bump to 0.1.0"
```

### Task 19: Bump package versions

**Files:**
- Modify: `packages/protocol/package.json` → version 0.1.0
- Modify: `packages/server/package.json` → version 0.1.0; bump `@fetchproxy/protocol` dep to `^0.1.0`
- Modify: `packages/extension-core/package.json` → version 0.1.0; bump `@fetchproxy/protocol` dep
- Modify: `packages/extension-chrome/package.json` → version 0.1.0; bump `@fetchproxy/extension-core` dep

- [ ] **Step 1: Apply version bumps**

Use `npm version 0.1.0 --workspaces --no-git-tag-version` or edit manually. Run `npm install` to sync lockfile.

- [ ] **Step 2: Build everything**

Run: `npm run build && npm run typecheck && npm test`
Expected: green.

- [ ] **Step 3: Commit**

```bash
git add packages/*/package.json package-lock.json
git commit -m "chore: bump all packages to 0.1.0"
```

### Task 20: Publish @fetchproxy/protocol and @fetchproxy/server 0.1.0

**Steps:**

- [ ] **Step 1: Publish protocol**

Run: `cd packages/protocol && npm publish --access public`
Expected: success.

- [ ] **Step 2: Publish server**

Run: `cd packages/server && npm publish --access public`
Expected: success.

- [ ] **Step 3: Tag the release**

Run: `git tag v0.1.0 && git push origin main --tags`

- [ ] **Step 4: Verify on npm**

Run: `npm view @fetchproxy/protocol version && npm view @fetchproxy/server version`
Expected: both `0.1.0`.

### Task 21: Migrate opentable-mcp to fetchproxy 0.1.0

**Files (in /Users/chris/git/opentable-mcp):**
- Modify: `package.json` — bump `@fetchproxy/server` to `^0.1.0`; bump opentable-mcp version to `0.10.0`
- Modify: `src/index.ts` — version banner string
- Modify: `src/transport-fetchproxy.ts` — adapt to new constructor signature (no longer takes a port — uses default; pass `serverName`/`version`/`domain` explicitly)

- [ ] **Step 1: Install new fetchproxy**

Run: `cd /Users/chris/git/opentable-mcp && npm install @fetchproxy/server@^0.1.0`
Expected: clean install.

- [ ] **Step 2: Adapt transport-fetchproxy.ts**

The constructor signature changed from `new FetchproxyServer({ port })` to require `serverName`, `version`, `domain`. Read the current file and update.

```typescript
// Likely shape after update (current location: /Users/chris/git/opentable-mcp/src/transport-fetchproxy.ts)
import { FetchproxyServer } from '@fetchproxy/server';
import type { OpenTableTransport, FetchInit, FetchResult } from './transport.js';
import packageJson from '../package.json' assert { type: 'json' };

const OT_BASE = 'https://www.opentable.com';
const OT_TAB_URL = 'https://www.opentable.com/';

export class FetchproxyTransport implements OpenTableTransport {
  private srv: FetchproxyServer;

  constructor(port?: number) {
    this.srv = new FetchproxyServer({
      port,
      serverName: 'opentable-mcp',
      version: packageJson.version,
      domain: 'opentable.com',
    });
  }

  async start(): Promise<void> {
    await this.srv.listen();
  }

  async close(): Promise<void> {
    await this.srv.close();
  }

  async fetch(init: FetchInit): Promise<FetchResult> {
    const url = init.url.startsWith('http') ? init.url : `${OT_BASE}${init.url}`;
    const result = await this.srv.fetch({
      url,
      method: init.method ?? 'GET',
      headers: init.headers,
      body: init.body,
      tabUrl: OT_TAB_URL,
    });
    if (!result.ok) {
      return { ok: false, status: 0, body: '', error: result.error };
    }
    return { ok: true, status: result.status, body: result.body };
  }
}
```

(Read the actual file before editing — the existing surface may already match closely.)

- [ ] **Step 3: Update version + banner**

Bump `package.json` `version` to `0.10.0`. Update `src/index.ts` banner string to match. Update `manifest.json` and other version locations per CLAUDE.md.

- [ ] **Step 4: Build + test**

Run: `cd /Users/chris/git/opentable-mcp && npm run build && npm test`
Expected: green.

- [ ] **Step 5: Live smoke**

Run: `lsof -ti :37149 | xargs -r kill; npx tsx scripts/probe-find-slots.ts`
Expected: clean response (after user reloads opentable.com tab in Chrome — the 0.1.0 extension needs to pair on first connect).

- [ ] **Step 6: Commit + PR**

```bash
git checkout -b feat/fetchproxy-0.1.0
git add -A
git commit -m "feat: migrate to @fetchproxy/server 0.1.0 (concentrator + E2E)"
gh pr create --label enhancement --title "opentable_modify: bump to fetchproxy 0.1.0 (concentrator + E2E)" --body "Migrates to the new fetchproxy concentrator architecture. Live-smoke verified."
gh pr merge --auto --merge
```

---

## Self-review checklist

After completing all tasks, run through these:

1. **Spec coverage** — every section of `2026-05-21-concentrator-e2e-design.md` has at least one task implementing it.
2. **Placeholder scan** — search the plan for "TBD", "TODO", "implement later", "appropriate error handling" → none found.
3. **Type consistency** — `mcpId` is `string` everywhere; `sessionKey` is `Uint8Array` everywhere; identity types match between `Identity` (server) and `ExtensionIdentity` (extension).
4. **Naming** — `derivePairCode`, `loadOrCreateIdentity`, `loadOrCreateExtensionIdentity`, `handleServerHello`, `sealInnerFrame`/`openEncryptedFrame`, `FetchproxyServer` — used consistently across plan.
5. **Cryptographic correctness** — sessionKey = HKDF(ECDH(extEphemeralPriv, mcpIdentityPub), salt=sessionNonce, info="fetchproxy/0.1.0/session"). Both sides derive the same key because ECDH is symmetric.

---

## Execution

Two execution options:

**1. Subagent-Driven (recommended)** — fresh subagent per task, two-stage review after each.

**2. Inline Execution** — execute tasks in this session.

The user has already chosen subagent-driven for this work.
