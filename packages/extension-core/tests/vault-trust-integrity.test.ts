import { describe, it, expect, beforeEach } from 'vitest';
import {
  generateX25519,
  generateEd25519,
  ed25519Sign,
  helloSignaturePayload,
  sha256,
  toB64,
  toHex,
  PROTOCOL_VERSION,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import { handleServerHello } from '../src/background.js';
import { TrustStore, type TrustRecord } from '../src/trust-store.js';
import { loadOrCreateExtensionIdentity } from '../src/extension-identity.js';
import {
  loadRemoteTargets,
  saveRemoteTargets,
  loadDismissedScopeHashes,
  recordDismissedScopeHash,
} from '../src/vault-records.js';
import { vaultInitIfAbsent } from '../src/vault.js';
import { generateExtensionIdentity } from '../src/identity-keys.js';
import { noteInstalled } from '../src/vault-migration.js';
import { freshVault, installChromeLocal, type LocalArea } from './helpers/vault.js';

/**
 * FOLLOWUP-1 (fleet-audit #252): trust records (`trustedMcps`), remote bridge
 * targets (`remoteBridges`) and dismissed scope-update hashes
 * (`dismissedScopeHashes`) lived in `chrome.storage.local`, which the content
 * script on every site can WRITE. A compromised renderer could forge a trust
 * record for an MCP identity of its choosing (skipping the pair prompt),
 * revoke a legitimate one, add a bridge, or suppress a scope-update offer.
 *
 * They now live in the extension-origin IndexedDB vault. `local.data` below is
 * the attacker's reach — a content script can put anything there or delete
 * anything from it — and every test asserts that doing so changes nothing the
 * extension decides.
 */

const EXT_VERSION = '3.2.0';
const EXT_NONCE = new Uint8Array(32).fill(0xcd);

async function mcpHello(
  serverName: string,
  domains: string[],
): Promise<{
  hello: HelloFrameFromServer;
  identityHash: string;
}> {
  const x = await generateX25519();
  const ed = await generateEd25519();
  const session = await generateX25519();
  const nonce = new Uint8Array(32).fill(9);
  const mcpId = `${serverName}:1.0.0:0123456789abcdef`;
  const sig = await ed25519Sign(
    ed.privateKey,
    helloSignaturePayload(mcpId, nonce, session.publicKey, EXT_NONCE),
  );
  return {
    identityHash: toHex(await sha256(x.publicKey)),
    hello: {
      type: 'hello',
      protocolVersion: PROTOCOL_VERSION,
      role: 'server',
      mcpId,
      serverName,
      version: '1.0.0',
      domains: [...domains],
      capabilities: ['fetch'],
      identityX25519Pub: toB64(x.publicKey),
      identityEd25519Pub: toB64(ed.publicKey),
      sessionNonce: toB64(nonce),
      sessionPub: toB64(session.publicKey),
      answersExtNonce: toB64(EXT_NONCE),
      sessionSig: toB64(sig),
    },
  };
}

/** A complete, well-formed trust record — exactly what `put` would write. */
function recordFor(hello: HelloFrameFromServer, extPubB64: string): TrustRecord {
  return {
    serverName: hello.serverName,
    domains: [...hello.domains],
    capabilities: ['fetch'],
    cookieKeys: [],
    localStorageKeys: [],
    sessionStorageKeys: [],
    captureHeaders: [],
    indexedDbScopes: [],
    domSelectors: [],
    domListSelectors: [],
    graphqlOps: [],
    localStoragePointers: [],
    sessionStoragePointers: [],
    identityX25519Pub: hello.identityX25519Pub,
    identityEd25519Pub: hello.identityEd25519Pub,
    extensionIdentityX25519Pub: extPubB64,
    extensionIdentityEd25519Pub: extPubB64,
    pairedAt: 1,
    extensionVersionAtPair: EXT_VERSION,
  };
}

async function decide(trust: TrustStore, hello: HelloFrameFromServer, extPub: Uint8Array) {
  return handleServerHello(hello, {
    trust,
    extensionIdentityX25519Pub: extPub,
    extensionSessionNonce: EXT_NONCE,
  });
}

const BRIDGE = {
  id: 'b1',
  url: 'wss://relay.example.com/bridge',
  token: 'tok-1',
  enabled: true,
};

describe('trust records cannot be forged or revoked through chrome.storage.local', () => {
  let local: LocalArea;
  let extPub: Uint8Array;
  let extPubB64: string;
  beforeEach(async () => {
    freshVault();
    local = installChromeLocal();
    extPub = (await loadOrCreateExtensionIdentity()).x25519Pub;
    extPubB64 = toB64(extPub);
  });

  it('control: the same record written through TrustStore IS trusted', async () => {
    const { hello, identityHash } = await mcpHello('good-mcp', ['good.example']);
    const trust = new TrustStore(EXT_VERSION);
    const { pairedAt: _p, extensionVersionAtPair: _v, ...input } = recordFor(hello, extPubB64);
    await trust.put(identityHash, input);
    expect((await decide(trust, hello, extPub)).kind).toBe('auto-trust');
  });

  it('a record a content script writes to storage.local["trustedMcps"] is NOT trusted', async () => {
    const { hello, identityHash } = await mcpHello('evil-mcp', ['bank.example']);
    local.data['trustedMcps'] = { records: { [identityHash]: recordFor(hello, extPubB64) } };
    const trust = new TrustStore(EXT_VERSION);
    expect(await trust.get(identityHash)).toBeNull();
    expect(Object.keys(await trust.list())).not.toContain(identityHash);
    expect((await decide(trust, hello, extPub)).kind).toBe('needs-pair');
  });

  it('wiping or overwriting storage.local does NOT revoke a real pairing', async () => {
    const { hello, identityHash } = await mcpHello('good-mcp', ['good.example']);
    const trust = new TrustStore(EXT_VERSION);
    const { pairedAt: _p, extensionVersionAtPair: _v, ...input } = recordFor(hello, extPubB64);
    await trust.put(identityHash, input);
    local.data['trustedMcps'] = { records: {} };
    expect((await decide(trust, hello, extPub)).kind).toBe('auto-trust');
    for (const k of Object.keys(local.data)) delete local.data[k];
    expect((await decide(new TrustStore(EXT_VERSION), hello, extPub)).kind).toBe('auto-trust');
  });

  it('trust records are not readable from storage.local at all', async () => {
    const { hello, identityHash } = await mcpHello('good-mcp', ['good.example']);
    const { pairedAt: _p, extensionVersionAtPair: _v, ...input } = recordFor(hello, extPubB64);
    await new TrustStore(EXT_VERSION).put(identityHash, input);
    expect(JSON.stringify(local.data)).not.toContain(identityHash);
    expect(local.data).toEqual({});
  });

  it('revocation still works from the popup (TrustStore.remove)', async () => {
    const { hello, identityHash } = await mcpHello('good-mcp', ['good.example']);
    const trust = new TrustStore(EXT_VERSION);
    const { pairedAt: _p, extensionVersionAtPair: _v, ...input } = recordFor(hello, extPubB64);
    await trust.put(identityHash, input);
    await trust.remove(identityHash);
    expect((await decide(trust, hello, extPub)).kind).toBe('needs-pair');
  });
});

describe('remoteBridges and dismissedScopeHashes cannot be written through storage.local', () => {
  let local: LocalArea;
  beforeEach(async () => {
    freshVault();
    local = installChromeLocal();
    await loadOrCreateExtensionIdentity();
  });

  it('a bridge a content script adds to storage.local is never dialled', async () => {
    local.data['remoteBridges'] = [BRIDGE];
    expect(await loadRemoteTargets()).toEqual([]);
  });

  it('a bridge the user saved survives storage.local being cleared', async () => {
    await saveRemoteTargets([BRIDGE]);
    expect(local.data).toEqual({});
    local.data['remoteBridges'] = [];
    expect(await loadRemoteTargets()).toEqual([BRIDGE]);
  });

  it('saveRemoteTargets persists only rows the background would dial', async () => {
    await saveRemoteTargets([BRIDGE, { ...BRIDGE, id: 'b2', url: 'ws://evil.example/' }]);
    expect(await loadRemoteTargets()).toEqual([BRIDGE]);
  });

  it('a dismissal a content script writes to storage.local suppresses nothing', async () => {
    local.data['dismissedScopeHashes'] = { idhash: ['scopehash'] };
    expect(await loadDismissedScopeHashes()).toEqual({});
  });

  it('a real dismissal is recorded in the vault, idempotently', async () => {
    await recordDismissedScopeHash('idhash', 'scopehash');
    await recordDismissedScopeHash('idhash', 'scopehash');
    await recordDismissedScopeHash('idhash', 'other');
    expect(await loadDismissedScopeHashes()).toEqual({ idhash: ['scopehash', 'other'] });
    expect(local.data).toEqual({});
  });
});

describe('migration from storage.local keeps existing pairings (one time only)', () => {
  let local: LocalArea;
  beforeEach(() => {
    freshVault();
    local = installChromeLocal();
  });

  async function seedLegacyInstall(): Promise<{
    hello: HelloFrameFromServer;
    identityHash: string;
    extPub: Uint8Array;
  }> {
    const x = await generateX25519();
    const ed = await generateEd25519();
    local.data['extensionIdentity'] = {
      x25519Priv: toB64(x.privateKey),
      x25519Pub: toB64(x.publicKey),
      ed25519Priv: toB64(ed.privateKey),
      ed25519Pub: toB64(ed.publicKey),
      createdAt: 1,
    };
    const { hello, identityHash } = await mcpHello('good-mcp', ['good.example']);
    local.data['trustedMcps'] = {
      records: { [identityHash]: recordFor(hello, toB64(x.publicKey)) },
    };
    local.data['remoteBridges'] = [BRIDGE];
    local.data['dismissedScopeHashes'] = { [identityHash]: ['s1'] };
    // Chrome's onInstalled for an update from 3.2.0 — the upgrade signal.
    await noteInstalled({ reason: 'update', previousVersion: '3.2.0' });
    return { hello, identityHash, extPub: x.publicKey };
  }

  it('an upgraded install keeps its pairings, bridges and dismissals, and storage.local is emptied', async () => {
    const { hello, identityHash, extPub } = await seedLegacyInstall();
    const trust = new TrustStore(EXT_VERSION);
    expect((await decide(trust, hello, extPub)).kind).toBe('auto-trust');
    expect(await loadRemoteTargets()).toEqual([BRIDGE]);
    expect(await loadDismissedScopeHashes()).toEqual({ [identityHash]: ['s1'] });
    for (const k of ['extensionIdentity', 'trustedMcps', 'remoteBridges', 'dismissedScopeHashes']) {
      expect(k in local.data).toBe(false);
    }
  });

  it('after migration, a record planted in storage.local is ignored', async () => {
    await seedLegacyInstall();
    const trust = new TrustStore(EXT_VERSION);
    await trust.list();
    const id = await loadOrCreateExtensionIdentity();
    const evil = await mcpHello('evil-mcp', ['bank.example']);
    local.data['trustedMcps'] = {
      records: { [evil.identityHash]: recordFor(evil.hello, toB64(id.x25519Pub)) },
    };
    expect((await decide(new TrustStore(EXT_VERSION), evil.hello, id.x25519Pub)).kind).toBe(
      'needs-pair',
    );
  });

  it('a FRESH install imports nothing from storage.local (no legacy identity = nothing to migrate)', async () => {
    const evil = await mcpHello('evil-mcp', ['bank.example']);
    local.data['trustedMcps'] = {
      records: { [evil.identityHash]: recordFor(evil.hello, 'irrelevant') },
    };
    local.data['remoteBridges'] = [BRIDGE];
    local.data['dismissedScopeHashes'] = { x: ['y'] };
    const trust = new TrustStore(EXT_VERSION);
    expect(await trust.list()).toEqual({});
    expect(await loadRemoteTargets()).toEqual([]);
    expect(await loadDismissedScopeHashes()).toEqual({});
    expect(local.data).toEqual({});
  });

  it('an identity already in the vault never pulls trust out of storage.local', async () => {
    // No released build moved the keys without the stores, so a vault with an
    // identity and trust rows still in storage.local means those rows were
    // planted. They are discarded.
    const id = await generateExtensionIdentity();
    await vaultInitIfAbsent('identity', { identity: id });
    const { hello, identityHash } = await mcpHello('good-mcp', ['good.example']);
    local.data['trustedMcps'] = {
      records: { [identityHash]: recordFor(hello, toB64(id.x25519Pub)) },
    };
    const trust = new TrustStore(EXT_VERSION);
    expect((await decide(trust, hello, id.x25519Pub)).kind).toBe('needs-pair');
    expect('trustedMcps' in local.data).toBe(false);
  });

  it('an evicted vault does NOT re-import: a planted identity + trust record buys nothing', async () => {
    // Normal first run, then a content script plants a legacy identity (whose
    // private key it knows) and a trust record pinned to it, then the vault is
    // lost (quota eviction, corruption, a manual wipe).
    await loadOrCreateExtensionIdentity();
    const x = await generateX25519();
    const ed = await generateEd25519();
    local.data['extensionIdentity'] = {
      x25519Priv: toB64(x.privateKey),
      x25519Pub: toB64(x.publicKey),
      ed25519Priv: toB64(ed.privateKey),
      ed25519Pub: toB64(ed.publicKey),
      createdAt: 1,
    };
    const evil = await mcpHello('evil-mcp', ['bank.example']);
    local.data['trustedMcps'] = {
      records: { [evil.identityHash]: recordFor(evil.hello, toB64(x.publicKey)) },
    };
    freshVault();
    const id = await loadOrCreateExtensionIdentity();
    expect(toB64(id.ed25519Pub)).not.toBe(toB64(ed.publicKey));
    expect(toB64(id.x25519Pub)).not.toBe(toB64(x.publicKey));
    const trust = new TrustStore(EXT_VERSION);
    expect(await trust.list()).toEqual({});
    expect((await decide(trust, evil.hello, x.publicKey)).kind).not.toBe('auto-trust');
    expect(local.data).toEqual({});
  });

  it('drops malformed legacy rows rather than importing them', async () => {
    await seedLegacyInstall();
    local.data['trustedMcps'] = { records: { a: 'not a record', b: null } };
    local.data['remoteBridges'] = [{ id: 'x', url: 'http://nope', token: 't' }];
    local.data['dismissedScopeHashes'] = { a: 'nope', b: ['ok', 3] };
    expect(await new TrustStore(EXT_VERSION).list()).toEqual({});
    expect(await loadRemoteTargets()).toEqual([]);
    expect(await loadDismissedScopeHashes()).toEqual({ b: ['ok'] });
  });
});
