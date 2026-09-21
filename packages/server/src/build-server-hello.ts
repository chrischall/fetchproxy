import {
  PROTOCOL_VERSION,
  ed25519Sign,
  helloSignaturePayload,
  toB64,
  type Capability,
  type CaptureHeaderDecl,
  type IndexedDbScopeDecl,
  type DomSelectorDecl,
  type DomListSelectorDecl,
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
  /** 3.1.0+: declared REPEATED DOM selectors for `read_dom_list`. */
  domListSelectors?: DomListSelectorDecl[];
  /** 1.x+: declared GraphQL operations for the `graphql` capability. */
  graphqlOps?: GraphqlOpDeclaration[];
  /** 2.5.0: extra host→peer frame types this server accepts (peers only). */
  accepts?: string[];
  /**
   * 3.0.0+ (protocol 4): the PUBLIC half of the X25519 ephemeral this hello
   * offers. Required, and deliberately not minted in here: the caller holds
   * the private half, so the caller is the only thing that can mint it, hold
   * it for exactly the extension session it was minted for, and zero it when
   * that session ends (§1a).
   */
  sessionPub: Uint8Array;
  /**
   * 3.0.0+ (protocol 4): the `sessionNonce` of the EXTENSION hello this hello
   * was minted against, or {@link ANSWERS_NO_EXT_SESSION} (32 zero bytes) for
   * a hello that answers none — a peer's registration hello at dial.
   *
   * Always 32 bytes, never absent: the host's forwarding gate reads it as a
   * fixed comparison against the live extension nonce, and it rides inside
   * the signed payload so a relay cannot re-point a hello at whichever
   * extension session it would like the frame delivered to.
   */
  answersExtNonce: Uint8Array;
}

/**
 * Build a `HelloFrameFromServer` frame, including a fresh 32-byte session
 * nonce and the Ed25519 signature over
 * `helloSignaturePayload(mcpId, sessionNonce, sessionPub, answersExtNonce)`.
 *
 * Both `startHost` (concentrator path) and `startPeer` (joiner path) emit
 * this frame with identical structure; consolidating the construction here
 * keeps the nonce length, signing payload, and field defaults in one place.
 * Callers should NOT cache the result — `sessionNonce` is fresh per call and
 * must remain fresh per session, and under v4 so must the `sessionPub` the
 * caller hands in.
 *
 * 3.0.0+: the payload goes through {@link helloSignaturePayload} rather than
 * being concatenated here. That is not tidiness — it is the only thing that
 * makes the signature cover the ephemeral the session key is derived from,
 * and the compiler applies no pressure to it: adding the two new fields to
 * the object literal below compiles perfectly well beside a v3 signature.
 */
export async function buildServerHello(
  opts: BuildServerHelloOpts,
): Promise<HelloFrameFromServer> {
  const sessionNonce = new Uint8Array(32);
  (globalThis.crypto as Crypto).getRandomValues(sessionNonce);
  const sig = await ed25519Sign(
    opts.identity.ed25519Priv,
    helloSignaturePayload(opts.mcpId, sessionNonce, opts.sessionPub, opts.answersExtNonce),
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
    sessionPub: toB64(opts.sessionPub),
    answersExtNonce: toB64(opts.answersExtNonce),
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
  if (opts.domListSelectors && opts.domListSelectors.length > 0) {
    hello.domListSelectors = opts.domListSelectors.map((d) => ({
      name: d.name,
      itemSelector: d.itemSelector,
      fields: d.fields.map((f) => ({
        name: f.name,
        ...(f.selector !== undefined ? { selector: f.selector } : {}),
        ...(f.attribute !== undefined ? { attribute: f.attribute } : {}),
      })),
      ...(d.maxItems !== undefined ? { maxItems: d.maxItems } : {}),
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
