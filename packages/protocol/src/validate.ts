import type { Capability, Frame, HelloFrame, ReadyFrame, EncryptedFrame, InnerFrame } from './frames.js';
import { KNOWN_CAPABILITIES, PROTOCOL_VERSION } from './frames.js';
import { isValidMcpId } from './mcp-id.js';
import { isValidJsonPointer } from './json-pointer.js';

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
 * Permitted character set + length for storage/cookie key names declared
 * in a server hello. Strict enough to round-trip safely in `chrome.cookies.get`,
 * `localStorage.getItem`, and the popup UI without escaping shenanigans.
 */
const SCOPE_KEY_RE = /^[A-Za-z0-9_.\-]{1,256}$/;
/**
 * 0.4.0+: glob-aware variant. Matches a literal scope key OR a glob
 * pattern with a non-empty literal prefix followed by `*`. Bare `*`
 * and `*foo` (no leading literal) are rejected; the `*` must come
 * AFTER at least one literal char so the popup can render something
 * meaningful and the user can recognise the prefix.
 *
 *   `feh--*`    → match (prefix=`feh--`)
 *   `auth_*`    → match
 *   `*`         → reject
 *   `*foo`      → reject
 *   `foo*bar`   → reject (only trailing `*` allowed)
 */
const SCOPE_KEY_GLOB_RE = /^[A-Za-z0-9_.\-]{1,256}\*?$/;
/**
 * Permitted character set + length for HTTP header names declared in
 * `captureHeaders`. RFC 7230 tchar is wider, but for declared scope
 * we keep it tight; this excludes whitespace + special chars that would
 * be ambiguous in the popup or in storage.
 */
const HEADER_NAME_RE = /^[A-Za-z0-9_\-]{1,128}$/;
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

function assertHttpsOriginOnly(x: unknown, label: string): asserts x is string {
  // Storage reads happen against the credentials of a tab on `origin`. We
  // refuse http:// origins to keep this from being usable on plaintext
  // surfaces that aren't a meaningful session anyway.
  assertString(x, label);
  let u: URL;
  try {
    u = new URL(x);
  } catch {
    throw new ProtocolError(`${label}: not a valid URL`);
  }
  if (u.protocol !== 'https:') {
    throw new ProtocolError(`${label}: must be https, got ${u.protocol}`);
  }
  if (u.pathname !== '/' && u.pathname !== '') {
    throw new ProtocolError(`${label}: must be a bare origin (no path)`);
  }
  if (u.search || u.hash) {
    throw new ProtocolError(`${label}: must be a bare origin (no query or fragment)`);
  }
}

function assertScopeKeyArray(value: unknown, label: string): void {
  if (!Array.isArray(value)) {
    throw new ProtocolError(`${label}: expected array, got ${typeof value}`);
  }
  const seen = new Set<string>();
  for (const k of value) {
    if (typeof k !== 'string') {
      throw new ProtocolError(`${label}: entry must be string, got ${typeof k}`);
    }
    if (!SCOPE_KEY_GLOB_RE.test(k)) {
      throw new ProtocolError(`${label}: invalid key ${JSON.stringify(k)}`);
    }
    if (seen.has(k)) {
      throw new ProtocolError(`${label}: duplicate ${JSON.stringify(k)}`);
    }
    seen.add(k);
  }
}

function assertCaptureHeadersArray(value: unknown, label: string): void {
  if (!Array.isArray(value)) {
    throw new ProtocolError(`${label}: expected array, got ${typeof value}`);
  }
  const seen = new Set<string>();
  for (let i = 0; i < value.length; i++) {
    const entry = value[i] as unknown;
    assertObject(entry, `${label}[${i}]`);
    if (entry.urlPattern === undefined) {
      throw new ProtocolError(`${label}[${i}].urlPattern: missing`);
    }
    if (entry.headerName === undefined) {
      throw new ProtocolError(`${label}[${i}].headerName: missing`);
    }
    if (typeof entry.urlPattern !== 'string') {
      throw new ProtocolError(
        `${label}[${i}].urlPattern: expected string, got ${typeof entry.urlPattern}`,
      );
    }
    if (typeof entry.headerName !== 'string') {
      throw new ProtocolError(
        `${label}[${i}].headerName: expected string, got ${typeof entry.headerName}`,
      );
    }
    if (!HEADER_NAME_RE.test(entry.headerName)) {
      throw new ProtocolError(
        `${label}[${i}].headerName: invalid name ${JSON.stringify(entry.headerName)}`,
      );
    }
    assertCaptureUrlPattern(entry.urlPattern, `${label}[${i}].urlPattern`);
    const key = `${entry.urlPattern}\x00${entry.headerName}`;
    if (seen.has(key)) {
      throw new ProtocolError(
        `${label}: duplicate ${JSON.stringify({ urlPattern: entry.urlPattern, headerName: entry.headerName })}`,
      );
    }
    seen.add(key);
    for (const k of Object.keys(entry)) {
      if (k !== 'urlPattern' && k !== 'headerName') {
        throw new ProtocolError(`${label}[${i}]: unexpected field ${JSON.stringify(k)}`);
      }
    }
  }
}

function assertStoragePointersArray(
  value: unknown,
  label: string,
  declaredKeys: readonly string[] | undefined,
): void {
  if (!Array.isArray(value)) {
    throw new ProtocolError(`${label}: expected array, got ${typeof value}`);
  }
  const seen = new Set<string>();
  for (let i = 0; i < value.length; i++) {
    const entry = value[i] as unknown;
    assertObject(entry, `${label}[${i}]`);
    if (entry.key === undefined) {
      throw new ProtocolError(`${label}[${i}].key: missing`);
    }
    if (entry.jsonPointer === undefined) {
      throw new ProtocolError(`${label}[${i}].jsonPointer: missing`);
    }
    if (typeof entry.key !== 'string' || !SCOPE_KEY_RE.test(entry.key)) {
      throw new ProtocolError(`${label}[${i}].key: invalid key ${JSON.stringify(entry.key)}`);
    }
    if (typeof entry.jsonPointer !== 'string' || !isValidJsonPointer(entry.jsonPointer)) {
      throw new ProtocolError(
        `${label}[${i}].jsonPointer: invalid pointer ${JSON.stringify(entry.jsonPointer)}`,
      );
    }
    if (declaredKeys && !declaredKeys.includes(entry.key)) {
      throw new ProtocolError(
        `${label}[${i}].key: ${JSON.stringify(entry.key)} not in declared storage key set`,
      );
    }
    const dedupe = `${entry.key}\x00${entry.jsonPointer}`;
    if (seen.has(dedupe)) {
      throw new ProtocolError(
        `${label}: duplicate (${entry.key}, ${entry.jsonPointer})`,
      );
    }
    seen.add(dedupe);
    for (const k of Object.keys(entry)) {
      if (k !== 'key' && k !== 'jsonPointer') {
        throw new ProtocolError(`${label}[${i}]: unexpected field ${JSON.stringify(k)}`);
      }
    }
  }
}

function assertIndexedDbScopesArray(value: unknown, label: string): void {
  if (!Array.isArray(value)) {
    throw new ProtocolError(`${label}: expected array, got ${typeof value}`);
  }
  const seen = new Set<string>();
  for (let i = 0; i < value.length; i++) {
    const entry = value[i] as unknown;
    assertObject(entry, `${label}[${i}]`);
    if (entry.origin === undefined) {
      throw new ProtocolError(`${label}[${i}].origin: missing`);
    }
    if (entry.database === undefined) {
      throw new ProtocolError(`${label}[${i}].database: missing`);
    }
    if (entry.store === undefined) {
      throw new ProtocolError(`${label}[${i}].store: missing`);
    }
    if (entry.keys === undefined) {
      throw new ProtocolError(`${label}[${i}].keys: missing`);
    }
    assertHttpsOriginOnly(entry.origin, `${label}[${i}].origin`);
    if (typeof entry.database !== 'string' || !SCOPE_KEY_RE.test(entry.database)) {
      throw new ProtocolError(
        `${label}[${i}].database: invalid name ${JSON.stringify(entry.database)}`,
      );
    }
    if (typeof entry.store !== 'string' || !SCOPE_KEY_RE.test(entry.store)) {
      throw new ProtocolError(
        `${label}[${i}].store: invalid name ${JSON.stringify(entry.store)}`,
      );
    }
    if (!Array.isArray(entry.keys) || entry.keys.length === 0) {
      throw new ProtocolError(`${label}[${i}].keys: must be non-empty array`);
    }
    const keysSeen = new Set<string>();
    for (const k of entry.keys) {
      if (typeof k !== 'string' || !SCOPE_KEY_RE.test(k)) {
        throw new ProtocolError(
          `${label}[${i}].keys: invalid key ${JSON.stringify(k)}`,
        );
      }
      if (keysSeen.has(k)) {
        throw new ProtocolError(`${label}[${i}].keys: duplicate ${JSON.stringify(k)}`);
      }
      keysSeen.add(k);
    }
    const dedupe = `${entry.origin}\x00${entry.database}\x00${entry.store}\x00${[...entry.keys]
      .sort()
      .join(',')}`;
    if (seen.has(dedupe)) {
      throw new ProtocolError(
        `${label}: duplicate scope (${entry.origin} ${entry.database}/${entry.store})`,
      );
    }
    seen.add(dedupe);
    for (const k of Object.keys(entry)) {
      if (k !== 'origin' && k !== 'database' && k !== 'store' && k !== 'keys') {
        throw new ProtocolError(`${label}[${i}]: unexpected field ${JSON.stringify(k)}`);
      }
    }
  }
}

function assertCaptureUrlPattern(pattern: string, label: string): void {
  // `https://host/path/*` — host fully-qualified, no wildcards in host,
  // wildcards only in path/query/fragment. We deliberately reject `http:`
  // (same argument as `assertHttpsOriginOnly`).
  if (!pattern.startsWith('https://')) {
    throw new ProtocolError(`${label}: must start with https:// (got ${JSON.stringify(pattern)})`);
  }
  const afterScheme = pattern.slice('https://'.length);
  const slash = afterScheme.indexOf('/');
  const host = slash === -1 ? afterScheme : afterScheme.slice(0, slash);
  if (host.length === 0) {
    throw new ProtocolError(`${label}: missing host (got ${JSON.stringify(pattern)})`);
  }
  if (host.includes('*')) {
    throw new ProtocolError(
      `${label}: wildcards not permitted in host (got ${JSON.stringify(pattern)})`,
    );
  }
  if (!HOSTNAME_RE.test(host)) {
    throw new ProtocolError(
      `${label}: invalid host ${JSON.stringify(host)} in ${JSON.stringify(pattern)}`,
    );
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
  if (t === 'pair-pending') return validatePairPending(raw);
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
    // 0.3.0: optional scope decls. Each may be absent (older MCPs) or an
    // array — empty arrays are allowed (declares "no keys"). When present
    // we validate every entry so a malformed scope can't sneak through.
    if (raw.cookieKeys !== undefined) {
      assertScopeKeyArray(raw.cookieKeys, 'hello.cookieKeys');
    }
    if (raw.localStorageKeys !== undefined) {
      assertScopeKeyArray(raw.localStorageKeys, 'hello.localStorageKeys');
    }
    if (raw.sessionStorageKeys !== undefined) {
      assertScopeKeyArray(raw.sessionStorageKeys, 'hello.sessionStorageKeys');
    }
    if (raw.captureHeaders !== undefined) {
      assertCaptureHeadersArray(raw.captureHeaders, 'hello.captureHeaders');
    }
    if (raw.indexedDbScopes !== undefined) {
      assertIndexedDbScopesArray(raw.indexedDbScopes, 'hello.indexedDbScopes');
    }
    if (raw.localStoragePointers !== undefined) {
      assertStoragePointersArray(
        raw.localStoragePointers,
        'hello.localStoragePointers',
        raw.localStorageKeys as string[] | undefined,
      );
    }
    if (raw.sessionStoragePointers !== undefined) {
      assertStoragePointersArray(
        raw.sessionStoragePointers,
        'hello.sessionStoragePointers',
        raw.sessionStorageKeys as string[] | undefined,
      );
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
    // 0.4.0+: extension identity. PROTOCOL_VERSION 2 requires the
    // identity pubs and a session nonce; the binding signature lives
    // on the subsequent ReadyFrame (which is when the extension has
    // the MCP's nonce to sign over).
    assertBase64(raw.identityX25519Pub, 'hello.identityX25519Pub');
    assertBase64(raw.identityEd25519Pub, 'hello.identityEd25519Pub');
    assertBase64(raw.sessionNonce, 'hello.sessionNonce');
    return raw as unknown as HelloFrame;
  }
  throw new ProtocolError(`hello.role: must be 'server' or 'extension', got ${String(role)}`);
}

function validateReady(raw: Record<string, unknown>): ReadyFrame {
  assertString(raw.mcpId, 'ready.mcpId');
  if (!isValidMcpId(raw.mcpId)) throw new ProtocolError('ready.mcpId: invalid format');
  assertBase64(raw.extensionSessionPub, 'ready.extensionSessionPub');
  // 0.4.0+: ready frame carries the mutual-auth signature over
  // `(mcpHelloSessionNonce || extHello.sessionNonce)`. The host verifies
  // this against the extension's claimed identityEd25519Pub before
  // deriving the session key.
  assertBase64(raw.sessionSig, 'ready.sessionSig');
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

const PAIR_CODE_RE = /^\d{3}-\d{3}$/;

function validatePairPending(raw: Record<string, unknown>): import('./frames.js').PairPendingFrame {
  assertString(raw.mcpId, 'pair-pending.mcpId');
  if (!isValidMcpId(raw.mcpId)) throw new ProtocolError('pair-pending.mcpId: invalid format');
  assertString(raw.pairCode, 'pair-pending.pairCode');
  if (!PAIR_CODE_RE.test(raw.pairCode)) {
    throw new ProtocolError(`pair-pending.pairCode: must match XXX-XXX, got ${String(raw.pairCode)}`);
  }
  return { type: 'pair-pending', mcpId: raw.mcpId, pairCode: raw.pairCode };
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
    // Two shapes accepted (back-compat through 0.3.0):
    //   - Legacy 0.2.0: { tabUrl } (returns raw document.cookie string)
    //   - New 0.3.0:    { origin, keys } (returns values map; HttpOnly visible)
    // Reject anything that's neither (or both — a hybrid would be a confused-deputy
    // attack surface).
    const hasTabUrl = raw.init.tabUrl !== undefined;
    const hasOrigin = raw.init.origin !== undefined;
    const hasKeys = raw.init.keys !== undefined;
    if (hasTabUrl && (hasOrigin || hasKeys)) {
      throw new ProtocolError(
        'inner.init: read_cookies cannot mix legacy tabUrl with origin/keys',
      );
    }
    if (hasTabUrl) {
      assertHttpUrl(raw.init.tabUrl, 'inner.init.tabUrl');
      for (const k of Object.keys(raw.init)) {
        if (k !== 'tabUrl') {
          throw new ProtocolError(`inner.init: unexpected field ${JSON.stringify(k)} on read_cookies`);
        }
      }
      return raw as unknown as InnerFrame;
    }
    if (!hasOrigin || !hasKeys) {
      throw new ProtocolError(
        'inner.init: read_cookies must carry { origin, keys } (or legacy { tabUrl })',
      );
    }
    assertHttpsOriginOnly(raw.init.origin, 'inner.init.origin');
    assertNonEmptyKeyArray(raw.init.keys, 'inner.init.keys');
    for (const k of Object.keys(raw.init)) {
      if (k !== 'origin' && k !== 'keys') {
        throw new ProtocolError(`inner.init: unexpected field ${JSON.stringify(k)} on read_cookies`);
      }
    }
    return raw as unknown as InnerFrame;
  }
  if (raw.op === 'read_local_storage' || raw.op === 'read_session_storage') {
    assertObject(raw.init, 'inner.init');
    if (raw.init.origin === undefined) {
      throw new ProtocolError('inner.init.origin: missing');
    }
    if (raw.init.keys === undefined) {
      throw new ProtocolError('inner.init.keys: missing');
    }
    assertHttpsOriginOnly(raw.init.origin, 'inner.init.origin');
    assertNonEmptyKeyArray(raw.init.keys, 'inner.init.keys');
    if (raw.init.pointers !== undefined) {
      assertObject(raw.init.pointers, 'inner.init.pointers');
      for (const [outKey, ptr] of Object.entries(raw.init.pointers)) {
        if (FORBIDDEN_KEYS.has(outKey)) {
          throw new ProtocolError(
            `inner.init.pointers: forbidden output key ${outKey}`,
          );
        }
        assertObject(ptr, `inner.init.pointers[${outKey}]`);
        if (typeof (ptr as Record<string, unknown>).storageKey !== 'string') {
          throw new ProtocolError(
            `inner.init.pointers[${outKey}].storageKey: must be string`,
          );
        }
        const storageKey = (ptr as Record<string, unknown>).storageKey as string;
        if (!SCOPE_KEY_RE.test(storageKey)) {
          throw new ProtocolError(
            `inner.init.pointers[${outKey}].storageKey: invalid key ${JSON.stringify(storageKey)}`,
          );
        }
        const jsonPointer = (ptr as Record<string, unknown>).jsonPointer;
        if (typeof jsonPointer !== 'string' || !isValidJsonPointer(jsonPointer)) {
          throw new ProtocolError(
            `inner.init.pointers[${outKey}].jsonPointer: invalid pointer ${JSON.stringify(jsonPointer)}`,
          );
        }
        // The pointer's storageKey must reference a key the caller
        // ALSO asked to read (`init.keys`) — the extension reads the
        // value once and applies all pointers against it.
        if (!(raw.init.keys as string[]).includes(storageKey)) {
          throw new ProtocolError(
            `inner.init.pointers[${outKey}].storageKey: ${JSON.stringify(storageKey)} not in init.keys`,
          );
        }
        for (const k of Object.keys(ptr as Record<string, unknown>)) {
          if (k !== 'storageKey' && k !== 'jsonPointer') {
            throw new ProtocolError(
              `inner.init.pointers[${outKey}]: unexpected field ${JSON.stringify(k)}`,
            );
          }
        }
      }
    }
    for (const k of Object.keys(raw.init)) {
      if (k !== 'origin' && k !== 'keys' && k !== 'pointers') {
        throw new ProtocolError(
          `inner.init: unexpected field ${JSON.stringify(k)} on ${raw.op}`,
        );
      }
    }
    return raw as unknown as InnerFrame;
  }
  if (raw.op === 'capture_request_header') {
    assertObject(raw.init, 'inner.init');
    if (raw.init.urlPattern === undefined) {
      throw new ProtocolError('inner.init.urlPattern: missing');
    }
    if (raw.init.headerName === undefined) {
      throw new ProtocolError('inner.init.headerName: missing');
    }
    assertString(raw.init.urlPattern, 'inner.init.urlPattern');
    assertString(raw.init.headerName, 'inner.init.headerName');
    if (raw.init.timeoutMs !== undefined) {
      assertPositiveInt(raw.init.timeoutMs, 'inner.init.timeoutMs');
    }
    for (const k of Object.keys(raw.init)) {
      if (k !== 'urlPattern' && k !== 'headerName' && k !== 'timeoutMs') {
        throw new ProtocolError(
          `inner.init: unexpected field ${JSON.stringify(k)} on capture_request_header`,
        );
      }
    }
    return raw as unknown as InnerFrame;
  }
  if (raw.op === 'read_indexed_db') {
    assertObject(raw.init, 'inner.init');
    if (raw.init.origin === undefined) throw new ProtocolError('inner.init.origin: missing');
    if (raw.init.database === undefined) throw new ProtocolError('inner.init.database: missing');
    if (raw.init.store === undefined) throw new ProtocolError('inner.init.store: missing');
    if (raw.init.keys === undefined) throw new ProtocolError('inner.init.keys: missing');
    assertHttpsOriginOnly(raw.init.origin, 'inner.init.origin');
    if (typeof raw.init.database !== 'string' || !SCOPE_KEY_RE.test(raw.init.database)) {
      throw new ProtocolError(
        `inner.init.database: invalid name ${JSON.stringify(raw.init.database)}`,
      );
    }
    if (typeof raw.init.store !== 'string' || !SCOPE_KEY_RE.test(raw.init.store)) {
      throw new ProtocolError(
        `inner.init.store: invalid name ${JSON.stringify(raw.init.store)}`,
      );
    }
    assertNonEmptyKeyArray(raw.init.keys, 'inner.init.keys');
    for (const k of Object.keys(raw.init)) {
      if (k !== 'origin' && k !== 'database' && k !== 'store' && k !== 'keys') {
        throw new ProtocolError(
          `inner.init: unexpected field ${JSON.stringify(k)} on read_indexed_db`,
        );
      }
    }
    return raw as unknown as InnerFrame;
  }
  throw new ProtocolError(
    `inner.op: must be one of "fetch", "read_cookies", "read_local_storage", "read_session_storage", "capture_request_header", "read_indexed_db"; got ${JSON.stringify(raw.op)}`,
  );
}

function assertNonEmptyKeyArray(value: unknown, label: string): void {
  if (!Array.isArray(value)) {
    throw new ProtocolError(`${label}: expected array, got ${typeof value}`);
  }
  if (value.length === 0) {
    throw new ProtocolError(`${label}: must be non-empty`);
  }
  const seen = new Set<string>();
  for (const k of value) {
    if (typeof k !== 'string') {
      throw new ProtocolError(`${label}: entry must be string, got ${typeof k}`);
    }
    if (k.length === 0) {
      throw new ProtocolError(`${label}: empty key not allowed`);
    }
    if (seen.has(k)) {
      throw new ProtocolError(`${label}: duplicate ${JSON.stringify(k)}`);
    }
    seen.add(k);
  }
}

function assertStringMap(value: unknown, label: string): void {
  assertObject(value, label);
  for (const [k, v] of Object.entries(value)) {
    if (typeof v !== 'string') {
      throw new ProtocolError(`${label}[${k}]: must be string, got ${typeof v}`);
    }
  }
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
      // Either legacy `cookies: string` or new `values: Record<string, string>`.
      // Reject both (would be ambiguous) and neither (no payload at all).
      const hasCookies = raw.cookies !== undefined;
      const hasValues = raw.values !== undefined;
      if (hasCookies && hasValues) {
        throw new ProtocolError(
          'inner.response: read_cookies cannot carry both cookies and values',
        );
      }
      if (!hasCookies && !hasValues) {
        throw new ProtocolError(
          'inner.response: read_cookies missing cookies or values',
        );
      }
      if (hasCookies) {
        assertString(raw.cookies, 'inner.cookies');
      } else {
        assertStringMap(raw.values, 'inner.values');
      }
      return raw as unknown as InnerFrame;
    }
    if (op === 'read_local_storage' || op === 'read_session_storage') {
      if (raw.values === undefined) {
        throw new ProtocolError(`inner.values: missing on ${String(op)} response`);
      }
      assertStringMap(raw.values, 'inner.values');
      return raw as unknown as InnerFrame;
    }
    if (op === 'capture_request_header') {
      if (raw.value === undefined) {
        throw new ProtocolError('inner.value: missing on capture_request_header response');
      }
      assertString(raw.value, 'inner.value');
      return raw as unknown as InnerFrame;
    }
    if (op === 'read_indexed_db') {
      if (raw.values === undefined) {
        throw new ProtocolError('inner.values: missing on read_indexed_db response');
      }
      // IDB values can be any JSON-serializable type (objects, arrays,
      // strings, numbers, booleans, null). We don't deep-walk the
      // values here — at this point they're already a parsed JSON
      // object on the receiving side. Reject only non-plain-object
      // outer container + prototype-pollution keys (assertObject does
      // both).
      assertObject(raw.values, 'inner.values');
      return raw as unknown as InnerFrame;
    }
    throw new ProtocolError(
      `inner.op: unknown success-response op ${JSON.stringify(raw.op)}`,
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
