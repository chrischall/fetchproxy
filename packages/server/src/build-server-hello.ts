import {
  PROTOCOL_VERSION,
  concatBytes,
  ed25519Sign,
  toB64,
  type Capability,
  type CaptureHeaderDecl,
  type IndexedDbScopeDecl,
  type DomSelectorDecl,
  type GraphqlOpDeclaration,
  type StoragePointerDecl,
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
  /** 0.3.0+: declared scope. Omitted from the wire when empty/absent. */
  cookieKeys?: string[];
  localStorageKeys?: string[];
  sessionStorageKeys?: string[];
  captureHeaders?: CaptureHeaderDecl[];
  /** 0.4.0+: declared IndexedDB scopes for `read_indexed_db`. */
  indexedDbScopes?: IndexedDbScopeDecl[];
  /** 0.4.0+: declared JSON-pointer extractions over storage. */
  localStoragePointers?: StoragePointerDecl[];
  sessionStoragePointers?: StoragePointerDecl[];
  /** 1.4.0+: declared DOM selectors for `read_dom`. */
  domSelectors?: DomSelectorDecl[];
  /** 1.x+: declared GraphQL operations for the `graphql` capability. */
  graphqlOps?: GraphqlOpDeclaration[];
  /** 2.5.0: extra host→peer frame types this server accepts (peers only). */
  accepts?: string[];
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
  const hello: HelloFrameFromServer = {
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
  // 2.5.0: a peer advertises the host→peer frames it can take. Emitted
  // only when non-empty — the host's own hello (and every pre-2.5 peer)
  // carries no such field.
  if (opts.accepts && opts.accepts.length > 0) hello.accepts = [...opts.accepts];
  // Only emit non-empty scope fields. Keeps the wire compact for the
  // fetch-only common case and makes the security-significant decls
  // (which the popup shows the user) obvious by their presence.
  if (opts.cookieKeys && opts.cookieKeys.length > 0) {
    hello.cookieKeys = [...opts.cookieKeys];
  }
  if (opts.localStorageKeys && opts.localStorageKeys.length > 0) {
    hello.localStorageKeys = [...opts.localStorageKeys];
  }
  if (opts.sessionStorageKeys && opts.sessionStorageKeys.length > 0) {
    hello.sessionStorageKeys = [...opts.sessionStorageKeys];
  }
  if (opts.captureHeaders && opts.captureHeaders.length > 0) {
    hello.captureHeaders = opts.captureHeaders.map((d) => ({
      host: d.host,
      ...(d.path !== undefined ? { path: d.path } : {}),
      headerName: d.headerName,
    }));
  }
  if (opts.indexedDbScopes && opts.indexedDbScopes.length > 0) {
    hello.indexedDbScopes = opts.indexedDbScopes.map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    }));
  }
  if (opts.localStoragePointers && opts.localStoragePointers.length > 0) {
    hello.localStoragePointers = opts.localStoragePointers.map((d) => ({
      key: d.key,
      jsonPointer: d.jsonPointer,
    }));
  }
  if (opts.sessionStoragePointers && opts.sessionStoragePointers.length > 0) {
    hello.sessionStoragePointers = opts.sessionStoragePointers.map((d) => ({
      key: d.key,
      jsonPointer: d.jsonPointer,
    }));
  }
  if (opts.domSelectors && opts.domSelectors.length > 0) {
    hello.domSelectors = opts.domSelectors.map((d) => ({
      name: d.name,
      selector: d.selector,
      ...(d.attribute !== undefined ? { attribute: d.attribute } : {}),
    }));
  }
  if (opts.graphqlOps && opts.graphqlOps.length > 0) {
    hello.graphqlOps = opts.graphqlOps.map((d) => ({
      name: d.name,
      operationName: d.operationName,
    }));
  }
  return hello;
}
