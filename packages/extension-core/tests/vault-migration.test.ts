import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { generateEd25519, generateX25519, toB64 } from '@fetchproxy/protocol';
import { loadOrCreateExtensionIdentity } from '../src/extension-identity.js';
import {
  armInstallSignal,
  isLegacyUpgrade,
  noteInstalled,
  LEGACY_MIGRATION_FLAG,
  __resetInstallSignalForTests,
} from '../src/vault-migration.js';
import { vaultInitIfAbsent, vaultGet } from '../src/vault.js';
import { generateExtensionIdentity } from '../src/identity-keys.js';
import { loadRemoteTargets } from '../src/vault-records.js';
import { chromeSession, freshVault, installChromeLocal, type LocalArea } from './helpers/vault.js';

/**
 * The legacy import out of `chrome.storage.local` is gated on an UNFORGEABLE
 * upgrade signal — `chrome.runtime.onInstalled` with reason `update` from
 * 3.2.0 or earlier — never on the vault merely being empty. An empty vault is
 * also what quota eviction, corruption or a wipe of the extension's IndexedDB
 * leaves, and `storage.local` is writable by every site's content script: if
 * emptiness alone authorised the import, a renderer that planted an identity
 * (whose private key it knows) and trust records ahead of time would get both
 * installed the next time the vault was lost.
 */

async function legacyIdentity(): Promise<{ stored: Record<string, unknown>; edPub: string }> {
  const x = await generateX25519();
  const ed = await generateEd25519();
  return {
    edPub: toB64(ed.publicKey),
    stored: {
      x25519Priv: toB64(x.privateKey),
      x25519Pub: toB64(x.publicKey),
      ed25519Priv: toB64(ed.privateKey),
      ed25519Pub: toB64(ed.publicKey),
      createdAt: 1,
    },
  };
}

const BRIDGE = { id: 'b1', url: 'wss://relay.example.com/bridge', token: 't', enabled: true };

describe('isLegacyUpgrade — what counts as an upgrade from a storage.local build', () => {
  it('an update from 3.2.0 or earlier', () => {
    expect(isLegacyUpgrade({ reason: 'update', previousVersion: '3.2.0' })).toBe(true);
    expect(isLegacyUpgrade({ reason: 'update', previousVersion: '3.1.9' })).toBe(true);
    expect(isLegacyUpgrade({ reason: 'update', previousVersion: '2.10.4' })).toBe(true);
    expect(isLegacyUpgrade({ reason: 'update', previousVersion: '0.4.0' })).toBe(true);
  });

  it('NOT an update from a vault build, an install, a Chrome update, or an unknown version', () => {
    expect(isLegacyUpgrade({ reason: 'update', previousVersion: '3.2.1' })).toBe(false);
    expect(isLegacyUpgrade({ reason: 'update', previousVersion: '3.3.0' })).toBe(false);
    expect(isLegacyUpgrade({ reason: 'update', previousVersion: '4.0.0' })).toBe(false);
    expect(isLegacyUpgrade({ reason: 'install' })).toBe(false);
    expect(isLegacyUpgrade({ reason: 'chrome_update', previousVersion: '3.2.0' })).toBe(false);
    expect(isLegacyUpgrade({ reason: 'update' })).toBe(false);
    expect(isLegacyUpgrade({ reason: 'update', previousVersion: 'garbage' })).toBe(false);
  });
});

describe('vault loss never re-opens the storage.local import', () => {
  let local: LocalArea;
  beforeEach(() => {
    freshVault();
    local = installChromeLocal();
  });
  afterEach(() => __resetInstallSignalForTests());

  it('an evicted vault mints a FRESH identity and ignores a planted one', async () => {
    const first = await loadOrCreateExtensionIdentity();
    const planted = await legacyIdentity();
    local.data['extensionIdentity'] = planted.stored;
    local.data['remoteBridges'] = [BRIDGE];
    freshVault(); // quota eviction / corruption / manual wipe of the vault
    const after = await loadOrCreateExtensionIdentity();
    expect(toB64(after.ed25519Pub)).not.toBe(planted.edPub);
    expect(toB64(after.ed25519Pub)).not.toBe(toB64(first.ed25519Pub));
    expect(await loadRemoteTargets()).toEqual([]);
    // The planted rows are discarded, not left to be imported later.
    expect(local.data).toEqual({});
  });

  it('an authorised upgrade imports once; a LATER eviction does not import again', async () => {
    const legacy = await legacyIdentity();
    local.data['extensionIdentity'] = legacy.stored;
    await noteInstalled({ reason: 'update', previousVersion: '3.2.0' });
    expect(toB64((await loadOrCreateExtensionIdentity()).ed25519Pub)).toBe(legacy.edPub);
    // The authorisation is consumed by the import.
    expect(LEGACY_MIGRATION_FLAG in chromeSession().data).toBe(false);

    const planted = await legacyIdentity();
    local.data['extensionIdentity'] = planted.stored;
    freshVault();
    const after = await loadOrCreateExtensionIdentity();
    expect(toB64(after.ed25519Pub)).not.toBe(planted.edPub);
  });

  it('an update from a vault build (3.2.1+) does not authorise the import', async () => {
    const planted = await legacyIdentity();
    local.data['extensionIdentity'] = planted.stored;
    await noteInstalled({ reason: 'update', previousVersion: '3.3.0' });
    const id = await loadOrCreateExtensionIdentity();
    expect(toB64(id.ed25519Pub)).not.toBe(planted.edPub);
  });

  it('a flag a content script could NOT write is what authorises: storage.local cannot', async () => {
    const planted = await legacyIdentity();
    local.data['extensionIdentity'] = planted.stored;
    local.data[LEGACY_MIGRATION_FLAG] = true; // wrong area: content-script writable
    const id = await loadOrCreateExtensionIdentity();
    expect(toB64(id.ed25519Pub)).not.toBe(planted.edPub);
  });

  it('an import interrupted by a service-worker restart is retried from the session flag', async () => {
    // The worker that saw onInstalled set the flag and died before importing.
    const legacy = await legacyIdentity();
    local.data['extensionIdentity'] = legacy.stored;
    chromeSession().data[LEGACY_MIGRATION_FLAG] = true;
    const id = await loadOrCreateExtensionIdentity();
    expect(toB64(id.ed25519Pub)).toBe(legacy.edPub);
    expect(LEGACY_MIGRATION_FLAG in chromeSession().data).toBe(false);
  });

  it('a vault that already has an identity never imports, even with the flag set', async () => {
    const id = await generateExtensionIdentity();
    await vaultInitIfAbsent('identity', { identity: id });
    local.data['remoteBridges'] = [BRIDGE];
    chromeSession().data[LEGACY_MIGRATION_FLAG] = true;
    expect(await loadRemoteTargets()).toEqual([]);
    expect(await vaultGet('legacyStoresMigrated')).toBe(true);
    expect(local.data).toEqual({});
    expect(LEGACY_MIGRATION_FLAG in chromeSession().data).toBe(false);
  });
});

describe('the service worker waits for onInstalled before initialising an empty vault', () => {
  let local: LocalArea;
  beforeEach(() => {
    freshVault();
    local = installChromeLocal();
  });
  afterEach(() => __resetInstallSignalForTests());

  it('an upgrade whose onInstalled arrives AFTER the first vault access still migrates', async () => {
    const legacy = await legacyIdentity();
    local.data['extensionIdentity'] = legacy.stored;
    armInstallSignal(10_000);
    const pending = loadOrCreateExtensionIdentity();
    await new Promise((r) => setTimeout(r, 20));
    await noteInstalled({ reason: 'update', previousVersion: '3.2.0' });
    expect(toB64((await pending).ed25519Pub)).toBe(legacy.edPub);
  });

  it('a fresh install resolves the wait at once and imports nothing', async () => {
    const planted = await legacyIdentity();
    local.data['extensionIdentity'] = planted.stored;
    armInstallSignal(10_000);
    const pending = loadOrCreateExtensionIdentity();
    await noteInstalled({ reason: 'install' });
    expect(toB64((await pending).ed25519Pub)).not.toBe(planted.edPub);
  });

  it('no onInstalled at all (a wake after eviction) times out and mints fresh', async () => {
    const planted = await legacyIdentity();
    local.data['extensionIdentity'] = planted.stored;
    armInstallSignal(30);
    const id = await loadOrCreateExtensionIdentity();
    expect(toB64(id.ed25519Pub)).not.toBe(planted.edPub);
    expect(local.data).toEqual({});
  });
});
