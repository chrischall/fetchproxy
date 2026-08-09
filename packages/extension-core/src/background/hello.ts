/**
 * The security-critical hello decision (`handleServerHello`) plus its
 * private helpers, moved verbatim out of `background.ts`.
 *
 * Pure: no chrome APIs, no module-level mutable state, no transport. The
 * trust store arrives via `deps.trust` rather than the background module's
 * singleton, which is what keeps this a leaf.
 */

import {
  ed25519Verify,
  ecdhX25519,
  hkdfSha256,
  derivePairCodeFromIds,
  sha256,
  generateX25519,
  toB64,
  fromB64,
  toHex,
  concatBytes,
  HKDF_SESSION_INFO,
  type Capability,
  type GraphqlOpDeclaration,
  type IndexedDbScopeDecl,
  type DomSelectorDecl,
  type StoragePointerDecl,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import type { TrustStore } from '../trust-store.js';
import { intersectScope, isScopeSubset } from '../lib/scope.js';
import { enc } from '../lib/text.js';

// -------------------------------------------------------------------
// 1. Pure decision function (handleServerHello)
// -------------------------------------------------------------------

export interface HandleHelloDeps {
  trust: TrustStore;
  /**
   * 0.4.0+: the extension's long-term X25519 identity pub. Used to
   * derive the joint pair code (`SHA256(mcpPub || extPub)`) so the
   * popup and the MCP terminal both compute the same code. Required.
   */
  extensionIdentityX25519Pub: Uint8Array;
}

export type HandleHelloResult =
  | { kind: 'reject'; reason: string }
  | {
      kind: 'needs-pair';
      pairCode: string;
      identityHash: string;
      mcpId: string;
      serverName: string;
      domains: string[];
      capabilities: string[];
      cookieKeys: string[];
      localStorageKeys: string[];
      sessionStorageKeys: string[];
      captureHeaders: { host: string; path?: string; headerName: string }[];
      indexedDbScopes: IndexedDbScopeDecl[];
      domSelectors: DomSelectorDecl[];
      graphqlOps: GraphqlOpDeclaration[];
      localStoragePointers: StoragePointerDecl[];
      sessionStoragePointers: StoragePointerDecl[];
      version: string;
      identityX25519Pub: string;
      identityEd25519Pub: string;
      sessionNonce: Uint8Array;
      /**
       * 0.4.0+: the previously approved scope, when this is a re-pair
       * (a trust record exists but the scope changed). Used by the
       * popup to render an "update" diff rather than a fresh pair.
       * Absent on a brand-new pair.
       */
      previousScope?: {
        capabilities: string[];
        cookieKeys: string[];
        localStorageKeys: string[];
        sessionStorageKeys: string[];
        captureHeaders: { host: string; path?: string; headerName: string }[];
        indexedDbScopes: IndexedDbScopeDecl[];
        domSelectors: DomSelectorDecl[];
        graphqlOps: GraphqlOpDeclaration[];
        localStoragePointers: StoragePointerDecl[];
        sessionStoragePointers: StoragePointerDecl[];
      };
    }
  | {
      kind: 'auto-trust';
      mcpId: string;
      domains: string[];
      /**
       * The GRANTED (intersection of approved and declared) capabilities.
       * When declared ⊆ approved, this equals declared. When declared
       * grows beyond approved, this equals approved ∩ declared (a subset
       * of declared). The request handler MUST enforce these, not declared.
       */
      capabilities: string[];
      cookieKeys: string[];
      localStorageKeys: string[];
      sessionStorageKeys: string[];
      captureHeaders: { host: string; path?: string; headerName: string }[];
      indexedDbScopes: IndexedDbScopeDecl[];
      domSelectors: DomSelectorDecl[];
      graphqlOps: GraphqlOpDeclaration[];
      localStoragePointers: StoragePointerDecl[];
      sessionStoragePointers: StoragePointerDecl[];
      sessionKey: Uint8Array;
      extensionSessionPub: Uint8Array;
      /**
       * 0.4.0+: signing nonce (the MCP-side hello nonce). The caller
       * uses this together with the extension's per-WS nonce to
       * produce a `ReadyFrame.sessionSig`.
       */
      mcpSessionNonce: Uint8Array;
      /**
       * Part 2 (scope-growth): present when declared scope exceeds
       * approved scope. The caller should queue a non-blocking
       * `scope-update` offer so the user can Grant the wider scope
       * at their leisure. Absent when declared ⊆ approved.
       */
      pendingScopeUpdate?: {
        identityHash: string;
        declaredCapabilities: string[];
        declaredCookieKeys: string[];
        declaredLocalStorageKeys: string[];
        declaredSessionStorageKeys: string[];
        declaredCaptureHeaders: { host: string; path?: string; headerName: string }[];
        declaredIndexedDbScopes: IndexedDbScopeDecl[];
        declaredDomSelectors: DomSelectorDecl[];
        declaredGraphqlOps: GraphqlOpDeclaration[];
        declaredLocalStoragePointers: StoragePointerDecl[];
        declaredSessionStoragePointers: StoragePointerDecl[];
        approvedCapabilities: string[];
        approvedCookieKeys: string[];
        approvedLocalStorageKeys: string[];
        approvedSessionStorageKeys: string[];
        approvedCaptureHeaders: { host: string; path?: string; headerName: string }[];
        approvedIndexedDbScopes: IndexedDbScopeDecl[];
        approvedDomSelectors: DomSelectorDecl[];
        approvedGraphqlOps: GraphqlOpDeclaration[];
        approvedLocalStoragePointers: StoragePointerDecl[];
        approvedSessionStoragePointers: StoragePointerDecl[];
      };
    };

/**
 * Order-insensitive equality for two domain lists. The trust record's
 * `domains` and the server hello's `domains` must declare the same set
 * (the user approved THIS set); a permutation is fine.
 */
function sameDomainSet(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const sa = [...a].map((s) => s.toLowerCase()).sort();
  const sb = [...b].map((s) => s.toLowerCase()).sort();
  for (let i = 0; i < sa.length; i++) if (sa[i] !== sb[i]) return false;
  return true;
}

/** Default capability set when the server hello doesn't carry one. */
const DEFAULT_CAPABILITIES: readonly Capability[] = ['fetch'];

function effectiveCapabilities(hello: HelloFrameFromServer): Capability[] {
  return hello.capabilities && hello.capabilities.length > 0
    ? [...hello.capabilities]
    : [...DEFAULT_CAPABILITIES];
}

interface DeclaredScope {
  cookieKeys: string[];
  localStorageKeys: string[];
  sessionStorageKeys: string[];
  captureHeaders: { host: string; path?: string; headerName: string }[];
  indexedDbScopes: IndexedDbScopeDecl[];
  domSelectors: DomSelectorDecl[];
  graphqlOps: GraphqlOpDeclaration[];
  localStoragePointers: StoragePointerDecl[];
  sessionStoragePointers: StoragePointerDecl[];
}

function declaredScope(hello: HelloFrameFromServer): DeclaredScope {
  return {
    cookieKeys: [...(hello.cookieKeys ?? [])],
    localStorageKeys: [...(hello.localStorageKeys ?? [])],
    sessionStorageKeys: [...(hello.sessionStorageKeys ?? [])],
    captureHeaders: (hello.captureHeaders ?? []).map((d) => ({
      host: d.host,
      ...(d.path !== undefined ? { path: d.path } : {}),
      headerName: d.headerName,
    })),
    indexedDbScopes: (hello.indexedDbScopes ?? []).map((d) => ({
      origin: d.origin,
      database: d.database,
      store: d.store,
      keys: [...d.keys],
    })),
    domSelectors: (hello.domSelectors ?? []).map((d) => ({ ...d })),
    graphqlOps: (hello.graphqlOps ?? []).map((d) => ({
      name: d.name,
      operationName: d.operationName,
    })),
    localStoragePointers: (hello.localStoragePointers ?? []).map((d) => ({
      key: d.key,
      jsonPointer: d.jsonPointer,
    })),
    sessionStoragePointers: (hello.sessionStoragePointers ?? []).map((d) => ({
      key: d.key,
      jsonPointer: d.jsonPointer,
    })),
  };
}

export async function handleServerHello(
  hello: HelloFrameFromServer,
  deps: HandleHelloDeps,
): Promise<HandleHelloResult> {
  const identityX25519Pub = fromB64(hello.identityX25519Pub);
  const identityEd25519Pub = fromB64(hello.identityEd25519Pub);
  const sessionNonce = fromB64(hello.sessionNonce);
  const sessionSig = fromB64(hello.sessionSig);

  // 1. Verify signature.
  let sigOk = false;
  try {
    sigOk = await ed25519Verify(
      identityEd25519Pub,
      concatBytes(enc.encode(hello.mcpId), sessionNonce),
      sessionSig,
    );
  } catch {
    return { kind: 'reject', reason: 'sessionSig verification threw' };
  }
  if (!sigOk) return { kind: 'reject', reason: 'sessionSig invalid' };

  // 2. Look up trust.
  const hash = toHex(await sha256(identityX25519Pub));
  const record = await deps.trust.get(hash);
  const capabilities = effectiveCapabilities(hello);

  const scope = declaredScope(hello);

  if (record) {
    if (
      record.serverName !== hello.serverName ||
      !sameDomainSet(record.domains, hello.domains)
    ) {
      return { kind: 'reject', reason: 'serverName/domains mismatch with trust record' };
    }
    // 0.4.0: if the stored trust record's extension identity differs
    // from this extension's current identity, force re-pair. This
    // catches a wholesale extension reinstall as well as legacy 0.3.0
    // records (no extensionIdentityX25519Pub field, normalised to '').
    const recordedExtPubB64 = record.extensionIdentityX25519Pub ?? '';
    if (recordedExtPubB64 !== toB64(deps.extensionIdentityX25519Pub)) {
      // Fall through to needs-pair path.
    } else {
      // Part 2 (scope-growth): instead of blocking on any scope change,
      // compute the intersection of approved and declared scope. If
      // declared ⊆ approved, serve declared as-is (no change to the user).
      // If declared GROWS beyond approved, serve the intersection (approved
      // ∩ declared) so the MCP keeps working, and queue a non-blocking
      // `scope-update` offer so the user can grant the wider scope later.
      // Only changes to domains/serverName still force needs-pair (above).
      const approvedScope = {
        capabilities: [...record.capabilities],
        cookieKeys: [...(record.cookieKeys ?? [])],
        localStorageKeys: [...(record.localStorageKeys ?? [])],
        sessionStorageKeys: [...(record.sessionStorageKeys ?? [])],
        captureHeaders: (record.captureHeaders ?? []).map((d) => ({ ...d })),
        indexedDbScopes: (record.indexedDbScopes ?? []).map((d) => ({
          origin: d.origin,
          database: d.database,
          store: d.store,
          keys: [...d.keys],
        })),
        domSelectors: (record.domSelectors ?? []).map((d) => ({ ...d })),
        graphqlOps: (record.graphqlOps ?? []).map((d) => ({ ...d })),
        localStoragePointers: (record.localStoragePointers ?? []).map((d) => ({ ...d })),
        sessionStoragePointers: (record.sessionStoragePointers ?? []).map((d) => ({ ...d })),
      };
      const declaredScopeObj = { capabilities, ...scope };
      const granted = intersectScope(approvedScope, declaredScopeObj);
      const scopeGrew = !isScopeSubset(declaredScopeObj, approvedScope);
      // Derive session key with fresh ephemeral keypair.
      const ephemeral = await generateX25519();
      const shared = await ecdhX25519(ephemeral.privateKey, identityX25519Pub);
      const sessionKey = await hkdfSha256(
        shared,
        sessionNonce,
        enc.encode(HKDF_SESSION_INFO),
        32,
      );
      return {
        kind: 'auto-trust',
        mcpId: hello.mcpId,
        domains: [...hello.domains],
        // GRANTED scope (intersection): never exceeds approved scope.
        capabilities: [...granted.capabilities],
        cookieKeys: [...granted.cookieKeys],
        localStorageKeys: [...granted.localStorageKeys],
        sessionStorageKeys: [...granted.sessionStorageKeys],
        captureHeaders: [...granted.captureHeaders],
        indexedDbScopes: [...granted.indexedDbScopes],
        domSelectors: [...granted.domSelectors],
        graphqlOps: [...granted.graphqlOps],
        localStoragePointers: [...granted.localStoragePointers],
        sessionStoragePointers: [...granted.sessionStoragePointers],
        sessionKey,
        extensionSessionPub: ephemeral.publicKey,
        mcpSessionNonce: sessionNonce,
        // Signal the caller to queue a scope-update offer only when growth occurred.
        ...(scopeGrew ? {
          pendingScopeUpdate: {
            identityHash: hash,
            declaredCapabilities: [...capabilities],
            declaredCookieKeys: [...scope.cookieKeys],
            declaredLocalStorageKeys: [...scope.localStorageKeys],
            declaredSessionStorageKeys: [...scope.sessionStorageKeys],
            declaredCaptureHeaders: scope.captureHeaders.map((d) => ({ ...d })),
            declaredIndexedDbScopes: scope.indexedDbScopes.map((d) => ({
              origin: d.origin,
              database: d.database,
              store: d.store,
              keys: [...d.keys],
            })),
            declaredDomSelectors: scope.domSelectors.map((d) => ({ ...d })),
            declaredGraphqlOps: scope.graphqlOps.map((d) => ({ ...d })),
            declaredLocalStoragePointers: scope.localStoragePointers.map((d) => ({ ...d })),
            declaredSessionStoragePointers: scope.sessionStoragePointers.map((d) => ({ ...d })),
            approvedCapabilities: [...approvedScope.capabilities],
            approvedCookieKeys: [...approvedScope.cookieKeys],
            approvedLocalStorageKeys: [...approvedScope.localStorageKeys],
            approvedSessionStorageKeys: [...approvedScope.sessionStorageKeys],
            approvedCaptureHeaders: approvedScope.captureHeaders.map((d) => ({ ...d })),
            approvedIndexedDbScopes: approvedScope.indexedDbScopes.map((d) => ({
              origin: d.origin,
              database: d.database,
              store: d.store,
              keys: [...d.keys],
            })),
            approvedDomSelectors: approvedScope.domSelectors.map((d) => ({ ...d })),
            approvedGraphqlOps: approvedScope.graphqlOps.map((d) => ({ ...d })),
            approvedLocalStoragePointers: approvedScope.localStoragePointers.map((d) => ({ ...d })),
            approvedSessionStoragePointers: approvedScope.sessionStoragePointers.map((d) => ({ ...d })),
          },
        } : {}),
      };
    }
  }

  // 3. Need pairing.
  const pairCode = await derivePairCodeFromIds(
    identityX25519Pub,
    deps.extensionIdentityX25519Pub,
  );
  return {
    kind: 'needs-pair',
    pairCode,
    identityHash: hash,
    mcpId: hello.mcpId,
    serverName: hello.serverName,
    domains: [...hello.domains],
    capabilities,
    ...scope,
    version: hello.version,
    identityX25519Pub: hello.identityX25519Pub,
    identityEd25519Pub: hello.identityEd25519Pub,
    sessionNonce,
  };
}
