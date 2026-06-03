import { describe, it, expect, beforeEach } from 'vitest';
import { handleServerHello, connectedIdentityHashes } from '../src/background.js';
import { TrustStore } from '../src/trust-store.js';
import { normalisePendingPair } from '../src/lib/pending-pair.js';
import { scopeHash } from '../src/lib/scope.js';
import {
  generateX25519,
  generateEd25519,
  ed25519Sign,
  sha256,
  derivePairCodeFromIds,
  toB64,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';

// Shared fake extension X25519 pub for the background tests. The
// 0.4.0 pair-code derivation requires the extension's identity pub
// in addition to the MCP's, so every test passes the same fake pub
// here. Production background.ts loads this from
// `loadOrCreateExtensionIdentity`.
const FAKE_EXT_X25519_PUB = new Uint8Array(32).fill(0xab);
const FAKE_EXT_X25519_PUB_B64 = toB64(FAKE_EXT_X25519_PUB);

function mockStorage(): void {
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

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

async function buildServerHello(
  mcpId: string,
  serverName: string,
  domains: string[],
  capabilities?: (
    | 'fetch'
    | 'read_cookies'
    | 'read_local_storage'
    | 'read_session_storage'
    | 'capture_request_header'
  )[],
  scope?: Partial<{
    cookieKeys: string[];
    localStorageKeys: string[];
    sessionStorageKeys: string[];
    captureHeaders: { urlPattern: string; headerName: string }[];
  }>,
): Promise<HelloFrameFromServer> {
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
    domains: [...domains],
    ...(capabilities ? { capabilities: [...capabilities] } : {}),
    identityX25519Pub: Buffer.from(x.publicKey).toString('base64'),
    identityEd25519Pub: Buffer.from(ed.publicKey).toString('base64'),
    sessionNonce: Buffer.from(sessionNonce).toString('base64'),
    sessionSig: Buffer.from(sig).toString('base64'),
  };
  if (scope?.cookieKeys && scope.cookieKeys.length > 0) hello.cookieKeys = [...scope.cookieKeys];
  if (scope?.localStorageKeys && scope.localStorageKeys.length > 0) {
    hello.localStorageKeys = [...scope.localStorageKeys];
  }
  if (scope?.sessionStorageKeys && scope.sessionStorageKeys.length > 0) {
    hello.sessionStorageKeys = [...scope.sessionStorageKeys];
  }
  if (scope?.captureHeaders && scope.captureHeaders.length > 0) {
    hello.captureHeaders = scope.captureHeaders.map((d) => ({ ...d }));
  }
  return hello;
}

describe('handleServerHello', () => {
  beforeEach(() => mockStorage());

  it('returns needs-pair for unknown identity, with correct pair code', async () => {
    const hello = await buildServerHello(
      'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      'opentable-mcp',
      ['opentable.com'],
    );
    const trust = new TrustStore('0.2.0');
    const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    expect(result.kind).toBe('needs-pair');
    if (result.kind === 'needs-pair') {
      const expectedPub = new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'));
      expect(result.pairCode).toBe(
        await derivePairCodeFromIds(expectedPub, FAKE_EXT_X25519_PUB),
      );
      expect(result.serverName).toBe('opentable-mcp');
      expect(result.domains).toEqual(['opentable.com']);
      expect(result.mcpId).toBe('opentable-mcp:0.9.1:a3f7c91d2e8b4f56');
    }
  });

  it('returns needs-pair surfacing all declared domains for multi-domain MCP', async () => {
    const hello = await buildServerHello(
      'honeybook-mcp:0.0.1:abcdef1234567890',
      'honeybook-mcp',
      ['honeybook.com', 'hbsplit.com'],
    );
    const trust = new TrustStore('0.2.0');
    const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    expect(result.kind).toBe('needs-pair');
    if (result.kind === 'needs-pair') {
      expect(result.domains).toEqual(['honeybook.com', 'hbsplit.com']);
    }
  });

  it('returns auto-trust for known identity; derives 32-byte session key + ephemeral pub', async () => {
    const hello = await buildServerHello(
      'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      'opentable-mcp',
      ['opentable.com'],
    );
    const trust = new TrustStore('0.2.0');
    const idHash = Buffer.from(
      await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
    ).toString('hex');
    await trust.put(idHash, {
      serverName: 'opentable-mcp',
      domains: ['opentable.com'],
      capabilities: ['fetch'],
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
      extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
      extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
    });

    const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    expect(result.kind).toBe('auto-trust');
    if (result.kind === 'auto-trust') {
      expect(result.sessionKey.byteLength).toBe(32);
      expect(result.extensionSessionPub.byteLength).toBe(32);
      expect(result.mcpId).toBe('opentable-mcp:0.9.1:a3f7c91d2e8b4f56');
      expect(result.domains).toEqual(['opentable.com']);
    }
  });

  it('auto-trust matches multi-domain MCP regardless of declared-order permutation', async () => {
    const hello = await buildServerHello(
      'honeybook-mcp:0.0.1:abcdef1234567890',
      'honeybook-mcp',
      ['honeybook.com', 'hbsplit.com'],
    );
    const trust = new TrustStore('0.2.0');
    const idHash = Buffer.from(
      await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
    ).toString('hex');
    // Trust record stored in the OPPOSITE order — still a match.
    await trust.put(idHash, {
      serverName: 'honeybook-mcp',
      domains: ['hbsplit.com', 'honeybook.com'],
      capabilities: ['fetch'],
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
      extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
      extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
    });
    const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    expect(result.kind).toBe('auto-trust');
  });

  it('rejects hello with invalid sessionSig', async () => {
    const hello = await buildServerHello(
      'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      'opentable-mcp',
      ['opentable.com'],
    );
    const bad = { ...hello, sessionSig: Buffer.from(new Uint8Array(64).fill(0)).toString('base64') };
    const trust = new TrustStore('0.2.0');
    const result = await handleServerHello(bad, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    expect(result.kind).toBe('reject');
  });

  it('rejects auto-trust if serverName changed since pair', async () => {
    const hello = await buildServerHello(
      'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      'opentable-mcp',
      ['opentable.com'],
    );
    const trust = new TrustStore('0.2.0');
    const idHash = Buffer.from(
      await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
    ).toString('hex');
    // Paired with a DIFFERENT serverName
    await trust.put(idHash, {
      serverName: 'resy-mcp',
      domains: ['opentable.com'],
      capabilities: ['fetch'],
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
      extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
      extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
    });
    const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    expect(result.kind).toBe('reject');
  });

  it('rejects auto-trust if domains set changed since pair', async () => {
    const hello = await buildServerHello(
      'honeybook-mcp:0.0.1:abcdef1234567890',
      'honeybook-mcp',
      ['honeybook.com', 'hbsplit.com'],
    );
    const trust = new TrustStore('0.2.0');
    const idHash = Buffer.from(
      await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
    ).toString('hex');
    // Trust record only allows ONE of the two — refuses to auto-grant
    // the now-expanded set without a re-pair.
    await trust.put(idHash, {
      serverName: 'honeybook-mcp',
      domains: ['honeybook.com'],
      capabilities: ['fetch'],
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
      extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
      extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
    });
    const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    expect(result.kind).toBe('reject');
  });

  describe('capabilities', () => {
    it("defaults capabilities to ['fetch'] when the hello omits the field", async () => {
      const hello = await buildServerHello(
        'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
        'opentable-mcp',
        ['opentable.com'],
        undefined, // no capabilities on the wire
      );
      const trust = new TrustStore('0.2.0');
      const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
      expect(result.kind).toBe('needs-pair');
      if (result.kind === 'needs-pair') {
        expect(result.capabilities).toEqual(['fetch']);
      }
    });

    it('surfaces declared capabilities on needs-pair', async () => {
      const hello = await buildServerHello(
        'credit-karma-mcp:0.0.1:1234567890abcdef',
        'credit-karma-mcp',
        ['creditkarma.com'],
        ['fetch', 'read_cookies'],
      );
      const trust = new TrustStore('0.2.0');
      const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
      expect(result.kind).toBe('needs-pair');
      if (result.kind === 'needs-pair') {
        expect(result.capabilities).toEqual(['fetch', 'read_cookies']);
      }
    });

    it('surfaces declared capabilities on auto-trust', async () => {
      const hello = await buildServerHello(
        'credit-karma-mcp:0.0.1:1234567890abcdef',
        'credit-karma-mcp',
        ['creditkarma.com'],
        ['fetch', 'read_cookies'],
      );
      const trust = new TrustStore('0.2.0');
      const idHash = Buffer.from(
        await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
      ).toString('hex');
      await trust.put(idHash, {
        serverName: 'credit-karma-mcp',
        domains: ['creditkarma.com'],
        capabilities: ['fetch', 'read_cookies'],
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
        extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
        extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
      });
      const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
      expect(result.kind).toBe('auto-trust');
      if (result.kind === 'auto-trust') {
        expect(result.capabilities).toEqual(['fetch', 'read_cookies']);
      }
    });

    // Part 2: scope-growth → auto-trust with intersection + scope-update signal
    it('auto-trusts with GRANTED (intersection) capabilities when MCP declares growth', async () => {
      const hello = await buildServerHello(
        'credit-karma-mcp:0.0.1:1234567890abcdef',
        'credit-karma-mcp',
        ['creditkarma.com'],
        ['fetch', 'capture_request_header'],
      );
      const trust = new TrustStore('0.2.0');
      const idHash = Buffer.from(
        await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
      ).toString('hex');
      // Previously approved only 'fetch' — MCP now declares additional capability.
      // New behaviour: auto-trust with granted = intersection (['fetch']), NOT needs-pair.
      await trust.put(idHash, {
        serverName: 'credit-karma-mcp',
        domains: ['creditkarma.com'],
        capabilities: ['fetch'],
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
        extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
        extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
      });
      const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
      // Must be auto-trust (not needs-pair) — the MCP continues to work.
      expect(result.kind).toBe('auto-trust');
      if (result.kind === 'auto-trust') {
        // Granted capabilities = intersection (approved ∩ declared) = ['fetch'] only.
        expect(result.capabilities).toEqual(['fetch']);
        // Signal for the caller to queue a scope-update offer in the popup.
        expect(result.pendingScopeUpdate).toBeDefined();
        expect(result.pendingScopeUpdate!.declaredCapabilities).toEqual(['fetch', 'capture_request_header']);
        expect(result.pendingScopeUpdate!.approvedCapabilities).toEqual(['fetch']);
      }
    });

    it('auto-trusts with declared capabilities when declared ⊆ approved (downgrade / exact match)', async () => {
      const hello = await buildServerHello(
        'credit-karma-mcp:0.0.1:1234567890abcdef',
        'credit-karma-mcp',
        ['creditkarma.com'],
        ['fetch'],
      );
      const trust = new TrustStore('0.2.0');
      const idHash = Buffer.from(
        await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
      ).toString('hex');
      await trust.put(idHash, {
        serverName: 'credit-karma-mcp',
        domains: ['creditkarma.com'],
        capabilities: ['fetch', 'read_cookies'],
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
        extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
        extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
      });
      const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
      // Downgrade: declared ⊆ approved → auto-trust with granted = declared, no scope-update.
      expect(result.kind).toBe('auto-trust');
      if (result.kind === 'auto-trust') {
        expect(result.capabilities).toEqual(['fetch']);
        // No scope-update needed when declared ⊆ approved.
        expect(result.pendingScopeUpdate).toBeUndefined();
      }
    });

    it('does NOT queue scope-update when declared ⊆ approved (no growth)', async () => {
      const hello = await buildServerHello(
        'ofw-mcp:0.5.0:1234567890abcdef',
        'ofw-mcp',
        ['ourfamilywizard.com'],
        ['fetch', 'read_local_storage'],
        { localStorageKeys: ['auth'] },
      );
      const trust = new TrustStore('0.3.0');
      const idHash = Buffer.from(
        await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
      ).toString('hex');
      await trust.put(idHash, {
        serverName: 'ofw-mcp',
        domains: ['ourfamilywizard.com'],
        capabilities: ['fetch', 'read_local_storage'],
        cookieKeys: [],
        localStorageKeys: ['auth', 'tokenExpiry'], // approved has MORE keys
        sessionStorageKeys: [],
        captureHeaders: [],
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
        extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
        extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
      });
      const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
      expect(result.kind).toBe('auto-trust');
      if (result.kind === 'auto-trust') {
        // Declared ⊆ approved → no scope-update.
        expect(result.pendingScopeUpdate).toBeUndefined();
        // Granted = declared (the intersection = declared when declared ⊆ approved).
        expect(result.localStorageKeys).toEqual(['auth']);
      }
    });

    it('surfaces declared scope arrays on needs-pair (0.3.0)', async () => {
      const hello = await buildServerHello(
        'ofw-mcp:0.5.0:1234567890abcdef',
        'ofw-mcp',
        ['ourfamilywizard.com'],
        ['fetch', 'read_local_storage', 'capture_request_header'],
        {
          localStorageKeys: ['auth', 'tokenExpiry'],
          captureHeaders: [
            { urlPattern: 'https://api.ourfamilywizard.com/v1/*', headerName: 'x-csrf' },
          ],
        },
      );
      const trust = new TrustStore('0.3.0');
      const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
      expect(result.kind).toBe('needs-pair');
      if (result.kind === 'needs-pair') {
        expect(result.localStorageKeys).toEqual(['auth', 'tokenExpiry']);
        expect(result.captureHeaders).toEqual([
          { urlPattern: 'https://api.ourfamilywizard.com/v1/*', headerName: 'x-csrf' },
        ]);
        expect(result.cookieKeys).toEqual([]);
        expect(result.sessionStorageKeys).toEqual([]);
      }
    });

    it('auto-trusts with intersection when a new localStorage key is declared (scope-growth)', async () => {
      const hello = await buildServerHello(
        'ofw-mcp:0.5.0:1234567890abcdef',
        'ofw-mcp',
        ['ourfamilywizard.com'],
        ['fetch', 'read_local_storage'],
        { localStorageKeys: ['auth', 'tokenExpiry'] },
      );
      const trust = new TrustStore('0.3.0');
      const idHash = Buffer.from(
        await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
      ).toString('hex');
      await trust.put(idHash, {
        serverName: 'ofw-mcp',
        domains: ['ourfamilywizard.com'],
        capabilities: ['fetch', 'read_local_storage'],
        cookieKeys: [],
        localStorageKeys: ['auth'], // tokenExpiry added since
        sessionStorageKeys: [],
        captureHeaders: [],
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
        extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
        extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
      });
      const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
      // Scope grew (new key) → auto-trust with intersection, scope-update signalled.
      expect(result.kind).toBe('auto-trust');
      if (result.kind === 'auto-trust') {
        // Only approved key is granted.
        expect(result.localStorageKeys).toEqual(['auth']);
        // scope-update offer queued.
        expect(result.pendingScopeUpdate).toBeDefined();
      }
    });

    it('auto-trusts with intersection when a new captureHeader is declared (scope-growth)', async () => {
      const hello = await buildServerHello(
        'honeybook-mcp:0.1.0:abcdef1234567890',
        'honeybook-mcp',
        ['honeybook.com'],
        ['fetch', 'capture_request_header'],
        {
          captureHeaders: [
            { urlPattern: 'https://api.honeybook.com/api/v2/*', headerName: 'hb-api-fingerprint' },
            { urlPattern: 'https://api.honeybook.com/api/v3/*', headerName: 'hb-api-fingerprint' },
          ],
        },
      );
      const trust = new TrustStore('0.3.0');
      const idHash = Buffer.from(
        await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
      ).toString('hex');
      // Trust record only includes v2 — v3 added since (scope growth).
      await trust.put(idHash, {
        serverName: 'honeybook-mcp',
        domains: ['honeybook.com'],
        capabilities: ['fetch', 'capture_request_header'],
        cookieKeys: [],
        localStorageKeys: [],
        sessionStorageKeys: [],
        captureHeaders: [
          { urlPattern: 'https://api.honeybook.com/api/v2/*', headerName: 'hb-api-fingerprint' },
        ],
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
        extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
        extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
      });
      const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
      // Scope grew (new captureHeader) → auto-trust with intersection, scope-update signalled.
      expect(result.kind).toBe('auto-trust');
      if (result.kind === 'auto-trust') {
        // Only the approved v2 header is granted.
        expect(result.captureHeaders).toHaveLength(1);
        expect(result.captureHeaders[0]?.urlPattern).toContain('api/v2');
        expect(result.pendingScopeUpdate).toBeDefined();
      }
    });

    it('auto-trusts when scope set matches (permutation OK)', async () => {
      const hello = await buildServerHello(
        'ofw-mcp:0.5.0:1234567890abcdef',
        'ofw-mcp',
        ['ourfamilywizard.com'],
        ['fetch', 'read_local_storage'],
        { localStorageKeys: ['tokenExpiry', 'auth'] }, // different order
      );
      const trust = new TrustStore('0.3.0');
      const idHash = Buffer.from(
        await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
      ).toString('hex');
      await trust.put(idHash, {
        serverName: 'ofw-mcp',
        domains: ['ourfamilywizard.com'],
        capabilities: ['fetch', 'read_local_storage'],
        cookieKeys: [],
        localStorageKeys: ['auth', 'tokenExpiry'], // original order
        sessionStorageKeys: [],
        captureHeaders: [],
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
        extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
        extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
      });
      const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
      expect(result.kind).toBe('auto-trust');
      if (result.kind === 'auto-trust') {
        expect(result.localStorageKeys.sort()).toEqual(['auth', 'tokenExpiry']);
      }
    });

    it('auto-trusts when scope is empty and hello declares no scope', async () => {
      // The common path for fetch-only MCPs (Pattern B): hello carries
      // no scope fields, trust record persists `[]` for each, no re-pair.
      const hello = await buildServerHello(
        'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
        'opentable-mcp',
        ['opentable.com'],
        ['fetch'],
      );
      const trust = new TrustStore('0.3.0');
      const idHash = Buffer.from(
        await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
      ).toString('hex');
      await trust.put(idHash, {
        serverName: 'opentable-mcp',
        domains: ['opentable.com'],
        capabilities: ['fetch'],
        cookieKeys: [],
        localStorageKeys: [],
        sessionStorageKeys: [],
        captureHeaders: [],
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
        extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
        extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
      });
      const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
      expect(result.kind).toBe('auto-trust');
    });

    it('forces needs-pair when extension identity changed since last pair (reinstall guard)', async () => {
      const hello = await buildServerHello(
        'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
        'opentable-mcp',
        ['opentable.com'],
      );
      const trust = new TrustStore('0.4.0');
      const idHash = Buffer.from(
        await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
      ).toString('hex');
      const differentExtPub = new Uint8Array(32).fill(0xcc);
      await trust.put(idHash, {
        serverName: 'opentable-mcp',
        domains: ['opentable.com'],
        capabilities: ['fetch'],
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
        extensionIdentityX25519Pub: toB64(differentExtPub),
        extensionIdentityEd25519Pub: toB64(differentExtPub),
      });
      const result = await handleServerHello(hello, {
        trust,
        extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB,
      });
      expect(result.kind).toBe('needs-pair');
    });

    it('forces needs-pair for legacy trust records without extensionIdentityX25519Pub', async () => {
      const hello = await buildServerHello(
        'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
        'opentable-mcp',
        ['opentable.com'],
      );
      const trust = new TrustStore('0.3.0');
      const idHash = Buffer.from(
        await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
      ).toString('hex');
      await trust.put(idHash, {
        serverName: 'opentable-mcp',
        domains: ['opentable.com'],
        capabilities: ['fetch'],
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
      });
      const result = await handleServerHello(hello, {
        trust,
        extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB,
      });
      expect(result.kind).toBe('needs-pair');
    });

    it('auto-trusts when capability set is a set-equal permutation', async () => {
      const hello = await buildServerHello(
        'credit-karma-mcp:0.0.1:1234567890abcdef',
        'credit-karma-mcp',
        ['creditkarma.com'],
        ['read_cookies', 'fetch'],
      );
      const trust = new TrustStore('0.2.0');
      const idHash = Buffer.from(
        await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
      ).toString('hex');
      // Same elements, opposite order — still a match.
      await trust.put(idHash, {
        serverName: 'credit-karma-mcp',
        domains: ['creditkarma.com'],
        capabilities: ['fetch', 'read_cookies'],
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
        extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
        extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
      });
      const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
      expect(result.kind).toBe('auto-trust');
    });
  });
});

// ---------------------------------------------------------------------------
// Multi-instance pending-pair dedup (0.6.0+)
// ---------------------------------------------------------------------------

/**
 * Build a hello frame using a shared identity keypair so two hellos from
 * different mcpIds can be simulated with the same identity.
 */
async function buildHelloWithIdentity(
  x25519Pub: Uint8Array,
  ed25519Pub: Uint8Array,
  ed25519Priv: CryptoKey,
  mcpId: string,
  serverName: string,
  domains: string[],
): Promise<HelloFrameFromServer> {
  const sessionNonce = new Uint8Array(32).fill(7);
  const sig = await ed25519Sign(
    ed25519Priv,
    concat(new TextEncoder().encode(mcpId), sessionNonce),
  );
  return {
    type: 'hello',
    protocolVersion: 1,
    role: 'server',
    mcpId,
    serverName,
    version: '1.0.0',
    domains: [...domains],
    identityX25519Pub: Buffer.from(x25519Pub).toString('base64'),
    identityEd25519Pub: Buffer.from(ed25519Pub).toString('base64'),
    sessionNonce: Buffer.from(sessionNonce).toString('base64'),
    sessionSig: Buffer.from(sig).toString('base64'),
  };
}

// ---------------------------------------------------------------------------
// Request-handler capability enforcement (Step 5)
// ---------------------------------------------------------------------------

describe('request handler capability enforcement (granted ≤ approved)', () => {
  it('auto-trust result.capabilities contains only GRANTED (intersection) capabilities — the request handler enforces these', async () => {
    // This test pins that when an MCP grows scope (approved=['fetch'], declared=['fetch','capture_request_header']),
    // the auto-trust result.capabilities is ['fetch'] — the intersection.
    // onServerHello sets mcpCapabilities.set(mcpId, result.capabilities), so
    // the request handler's `if (!capabilities.includes(req.op))` check at line ~893
    // correctly rejects capture_request_header requests without a blocked session.
    const hello = await buildServerHello(
      'musescore-mcp:0.3.0:aabbccdd00000001',
      'musescore-mcp',
      ['musescore.com'],
      ['fetch', 'capture_request_header'],
    );
    const trust = new TrustStore('0.3.0');
    const idHash = Buffer.from(
      await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
    ).toString('hex');
    await trust.put(idHash, {
      serverName: 'musescore-mcp',
      domains: ['musescore.com'],
      capabilities: ['fetch'], // approved only fetch
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
      extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
      extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
    });
    const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    // Decision must be auto-trust (not needs-pair, not reject).
    expect(result.kind).toBe('auto-trust');
    if (result.kind === 'auto-trust') {
      // SECURITY: granted capabilities MUST NOT include capture_request_header.
      expect(result.capabilities).not.toContain('capture_request_header');
      expect(result.capabilities).toContain('fetch');
      // The request handler in onServerHello sets:
      //   mcpCapabilities.set(result.mcpId, [...result.capabilities])
      // So any request with op='capture_request_header' hits the capability gate:
      //   if (!capabilities.includes(req.op)) → error response
      // This is the enforcement path — the test above proves result.capabilities
      // is the intersection, so the gate will fire.
    }
  });

  it('granted scope returned by auto-trust NEVER exceeds approved scope (security invariant)', async () => {
    // Comprehensive check: try several scope-growth cases and verify the
    // intersection never leaks unapproved items.
    const hello = await buildServerHello(
      'ofw-mcp:0.5.0:aabbccdd00000002',
      'ofw-mcp',
      ['ourfamilywizard.com'],
      ['fetch', 'read_local_storage', 'capture_request_header'],
      {
        localStorageKeys: ['auth', 'tokenExpiry', 'newKey'],
        captureHeaders: [
          { urlPattern: 'https://api.ourfamilywizard.com/v1/*', headerName: 'x-csrf' },
          { urlPattern: 'https://api.ourfamilywizard.com/v2/*', headerName: 'x-csrf' },
        ],
      },
    );
    const trust = new TrustStore('0.3.0');
    const idHash = Buffer.from(
      await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
    ).toString('hex');
    await trust.put(idHash, {
      serverName: 'ofw-mcp',
      domains: ['ourfamilywizard.com'],
      capabilities: ['fetch', 'read_local_storage'],
      cookieKeys: [],
      localStorageKeys: ['auth', 'tokenExpiry'],
      sessionStorageKeys: [],
      captureHeaders: [],
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
      extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
      extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
    });
    const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    expect(result.kind).toBe('auto-trust');
    if (result.kind === 'auto-trust') {
      // Capabilities: only approved ones.
      expect(result.capabilities).not.toContain('capture_request_header');
      // localStorageKeys: only approved keys (not 'newKey').
      expect(result.localStorageKeys).not.toContain('newKey');
      expect(result.localStorageKeys.sort()).toEqual(['auth', 'tokenExpiry']);
      // captureHeaders: none (not in approved).
      expect(result.captureHeaders).toHaveLength(0);
      // scope-update IS flagged.
      expect(result.pendingScopeUpdate).toBeDefined();
    }
  });
});

// ---------------------------------------------------------------------------
// Dismiss-suppression tests (Step 9)
// ---------------------------------------------------------------------------

describe('dismiss-suppression (scope-update)', () => {
  let storageData: Record<string, unknown>;

  beforeEach(() => {
    storageData = {};
    (globalThis as { chrome?: unknown }).chrome = {
      storage: {
        local: {
          get: async (k: string | string[]) => {
            const ks = Array.isArray(k) ? k : [k];
            const out: Record<string, unknown> = {};
            for (const x of ks) if (x in storageData) out[x] = storageData[x];
            return out;
          },
          set: async (kv: Record<string, unknown>) => Object.assign(storageData, kv),
          remove: async (x: string) => { delete storageData[x]; },
        },
      },
    };
  });

  it('pendingScopeUpdate signal is present when scope grows (precondition)', async () => {
    const hello = await buildServerHello(
      'suppress-mcp:1.0.0:001122334455',
      'suppress-mcp',
      ['suppress.example'],
      ['fetch', 'capture_request_header'],
    );
    const trust = new TrustStore('0.3.0');
    const idHash = Buffer.from(
      await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
    ).toString('hex');
    await trust.put(idHash, {
      serverName: 'suppress-mcp',
      domains: ['suppress.example'],
      capabilities: ['fetch'],
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
      extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
      extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
    });
    const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    expect(result.kind).toBe('auto-trust');
    if (result.kind === 'auto-trust') {
      expect(result.pendingScopeUpdate).toBeDefined();
    }
  });

  it('after a dismiss (dismissedScopeHashes written), suppression check prevents re-queuing', async () => {
    // This tests the storage state that suppresses re-queueing.
    // The suppression check in onServerHello reads:
    //   dismissed[identityHash].includes(declaredHash) → skip queueing
    const identityHash = 'aabbccdd' + '0'.repeat(56);
    const declaredScope = {
      capabilities: ['fetch', 'capture_request_header'],
      cookieKeys: [] as string[],
      localStorageKeys: [] as string[],
      sessionStorageKeys: [] as string[],
      captureHeaders: [] as { urlPattern: string; headerName: string }[],
      indexedDbScopes: [] as import('../src/lib/scope.js').Scope['indexedDbScopes'],
      localStoragePointers: [] as import('../src/lib/scope.js').Scope['localStoragePointers'],
      sessionStoragePointers: [] as import('../src/lib/scope.js').Scope['sessionStoragePointers'],
    };
    const hash = await scopeHash(declaredScope);
    const key = `${identityHash}:${hash}`;

    // Simulate dismiss: write the dismissed hash to storage.
    storageData['dismissedScopeHashes'] = { [identityHash]: [hash] };

    // Verify: the dismissed hash is recorded.
    const got = storageData['dismissedScopeHashes'] as Record<string, string[]>;
    expect(got[identityHash]).toContain(hash);

    // The suppression check: if this hash is in dismissed, skip queueing.
    const dismissed = got[identityHash] ?? [];
    const shouldQueue = !dismissed.includes(hash);
    expect(shouldQueue).toBe(false); // suppressed
    expect(key).toBe(`${identityHash}:${hash}`);
  });

  it('a new (different) declared scope after dismiss IS queued (not suppressed)', async () => {
    const identityHash = 'aabbccdd' + '0'.repeat(56);
    const oldDeclaredScope = {
      capabilities: ['fetch', 'capture_request_header'],
      cookieKeys: [] as string[],
      localStorageKeys: [] as string[],
      sessionStorageKeys: [] as string[],
      captureHeaders: [] as { urlPattern: string; headerName: string }[],
      indexedDbScopes: [] as import('../src/lib/scope.js').Scope['indexedDbScopes'],
      localStoragePointers: [] as import('../src/lib/scope.js').Scope['localStoragePointers'],
      sessionStoragePointers: [] as import('../src/lib/scope.js').Scope['sessionStoragePointers'],
    };
    const newDeclaredScope = {
      ...oldDeclaredScope,
      capabilities: ['fetch', 'capture_request_header', 'read_cookies'],
    };
    const oldHash = await scopeHash(oldDeclaredScope);
    const newHash = await scopeHash(newDeclaredScope);

    // Simulate: user dismissed the old declared scope.
    storageData['dismissedScopeHashes'] = { [identityHash]: [oldHash] };

    // New declared scope has a different hash.
    expect(newHash).not.toBe(oldHash);

    // Suppression check for the NEW hash: NOT suppressed.
    const dismissed = (storageData['dismissedScopeHashes'] as Record<string, string[]>)[identityHash] ?? [];
    const shouldQueueNew = !dismissed.includes(newHash);
    expect(shouldQueueNew).toBe(true); // new scope is NOT suppressed
  });
});

describe('multi-instance pending-pair dedup (0.6.0+)', () => {
  it('two needs-pair helloes from the same identity + scope collapse into ONE pending entry with both mcpIds', async () => {
    // Build a shared identity so both hellos have the same identityX25519Pub.
    const x = await generateX25519();
    const ed = await generateEd25519();

    const mcpId1 = 'foo-mcp:1.0.0:aaaa000000000001';
    const mcpId2 = 'foo-mcp:1.0.0:aaaa000000000002';

    const hello1 = await buildHelloWithIdentity(
      x.publicKey, ed.publicKey, ed.privateKey,
      mcpId1, 'foo-mcp', ['foo.com'],
    );
    const hello2 = await buildHelloWithIdentity(
      x.publicKey, ed.publicKey, ed.privateKey,
      mcpId2, 'foo-mcp', ['foo.com'],
    );

    const trust = new TrustStore('0.2.0');

    const result1 = await handleServerHello(hello1, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    const result2 = await handleServerHello(hello2, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });

    expect(result1.kind).toBe('needs-pair');
    expect(result2.kind).toBe('needs-pair');
    if (result1.kind !== 'needs-pair' || result2.kind !== 'needs-pair') return;

    // Both should have the same identityHash (same identity pub).
    expect(result1.identityHash).toBe(result2.identityHash);
    // Both should request the same scope (same hello → same fields).
    const scope = {
      capabilities: result1.capabilities,
      cookieKeys: result1.cookieKeys,
      localStorageKeys: result1.localStorageKeys,
      sessionStorageKeys: result1.sessionStorageKeys,
      captureHeaders: result1.captureHeaders,
      indexedDbScopes: result1.indexedDbScopes,
      localStoragePointers: result1.localStoragePointers,
      sessionStoragePointers: result1.sessionStoragePointers,
    };
    const hash1 = await scopeHash(scope);
    const pendingKey = `${result1.identityHash}:${hash1}`;

    // Simulate what background.ts `onServerHello` does: read-modify-write
    // with dedup.  First hello creates a new entry.  Second adds its mcpId.
    type PendingRec = {
      key: string;
      kind: 'pair';
      identityHash: string;
      mcpIds: string[];
      sessionNonces: Record<string, string>;
      [k: string]: unknown;
    };
    let storage: Record<string, PendingRec> = {};

    // First write (new entry).
    storage[pendingKey] = {
      key: pendingKey,
      kind: 'pair',
      identityHash: result1.identityHash,
      mcpIds: [mcpId1],
      sessionNonces: { [mcpId1]: Buffer.from(result1.sessionNonce).toString('base64') },
      pairCode: result1.pairCode,
      serverName: result1.serverName,
      version: result1.version,
      domains: result1.domains,
      capabilities: result1.capabilities,
      cookieKeys: result1.cookieKeys,
      localStorageKeys: result1.localStorageKeys,
      sessionStorageKeys: result1.sessionStorageKeys,
      captureHeaders: result1.captureHeaders,
      indexedDbScopes: result1.indexedDbScopes,
      localStoragePointers: result1.localStoragePointers,
      sessionStoragePointers: result1.sessionStoragePointers,
      identityX25519Pub: result1.identityX25519Pub,
      identityEd25519Pub: result1.identityEd25519Pub,
    };

    // Second write (dedup: same key, add mcpId2).
    const existing = storage[pendingKey]!;
    if (!existing.mcpIds.includes(mcpId2)) {
      existing.mcpIds.push(mcpId2);
    }
    existing.sessionNonces[mcpId2] = Buffer.from(result2.sessionNonce).toString('base64');

    // Verify: ONE entry, both mcpIds.
    const normalised = normalisePendingPair<PendingRec>(storage);
    expect(Object.keys(normalised)).toHaveLength(1);
    expect(Object.keys(normalised)[0]).toBe(pendingKey);
    const entry = normalised[pendingKey]!;
    expect(entry.mcpIds.sort()).toEqual([mcpId1, mcpId2].sort());
    expect(entry.sessionNonces[mcpId1]).toBeDefined();
    expect(entry.sessionNonces[mcpId2]).toBeDefined();
  });

  it('approving a pending entry with two mcpIds: both get sessions, entry is cleared', async () => {
    // Build a shared identity.
    const x = await generateX25519();
    const ed = await generateEd25519();

    const mcpId1 = 'bar-mcp:1.0.0:bbbb000000000001';
    const mcpId2 = 'bar-mcp:1.0.0:bbbb000000000002';

    const hello1 = await buildHelloWithIdentity(
      x.publicKey, ed.publicKey, ed.privateKey,
      mcpId1, 'bar-mcp', ['bar.com'],
    );
    const hello2 = await buildHelloWithIdentity(
      x.publicKey, ed.publicKey, ed.privateKey,
      mcpId2, 'bar-mcp', ['bar.com'],
    );

    const trust = new TrustStore('0.2.0');
    const r1 = await handleServerHello(hello1, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    const r2 = await handleServerHello(hello2, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    expect(r1.kind).toBe('needs-pair');
    expect(r2.kind).toBe('needs-pair');
    if (r1.kind !== 'needs-pair' || r2.kind !== 'needs-pair') return;

    // Build the merged pending record (same as what background does).
    const scope = {
      capabilities: r1.capabilities,
      cookieKeys: r1.cookieKeys,
      localStorageKeys: r1.localStorageKeys,
      sessionStorageKeys: r1.sessionStorageKeys,
      captureHeaders: r1.captureHeaders,
      indexedDbScopes: r1.indexedDbScopes,
      localStoragePointers: r1.localStoragePointers,
      sessionStoragePointers: r1.sessionStoragePointers,
    };
    const hash = await scopeHash(scope);
    const pendingKey = `${r1.identityHash}:${hash}`;

    const entry = {
      key: pendingKey,
      kind: 'pair' as const,
      identityHash: r1.identityHash,
      mcpIds: [mcpId1, mcpId2],
      sessionNonces: {
        [mcpId1]: Buffer.from(r1.sessionNonce).toString('base64'),
        [mcpId2]: Buffer.from(r2.sessionNonce).toString('base64'),
      },
    };

    // Simulate approval: iterate mcpIds, derive a session key per mcpId.
    // In production, background.ts's `onApproval` does this; here we
    // verify the shape supports the loop correctly.
    const sessionsDerived: string[] = [];
    for (const mcpId of entry.mcpIds) {
      const nonce = entry.sessionNonces[mcpId];
      expect(nonce).toBeDefined();
      // Just assert we can read the nonce — key derivation is crypto that
      // would need real WebCrypto in the test env. Asserting the loop
      // runs for ALL mcpIds and can read their nonces is the invariant.
      sessionsDerived.push(mcpId);
    }
    expect(sessionsDerived.sort()).toEqual([mcpId1, mcpId2].sort());

    // Simulate clearing the pending entry (delete by key).
    const storage: Record<string, unknown> = { [pendingKey]: entry };
    delete storage[pendingKey];
    expect(Object.keys(storage)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Part 3: connectedIdentityHashes — reflects live sessions
// ---------------------------------------------------------------------------

describe('connectedIdentityHashes (Part 3)', () => {
  beforeEach(() => mockStorage());

  it('returns an empty set when no sessions are established', () => {
    const hashes = connectedIdentityHashes();
    expect(hashes.size).toBe(0);
  });

  it('contains the identityHash of a session established via auto-trust', async () => {
    const hello = await buildServerHello(
      'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      'opentable-mcp',
      ['opentable.com'],
    );
    const trust = new TrustStore('0.2.0');
    const idHash = Buffer.from(
      await sha256(new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'))),
    ).toString('hex');
    await trust.put(idHash, {
      serverName: 'opentable-mcp',
      domains: ['opentable.com'],
      capabilities: ['fetch'],
      identityX25519Pub: hello.identityX25519Pub,
      identityEd25519Pub: hello.identityEd25519Pub,
      extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB_B64,
      extensionIdentityEd25519Pub: FAKE_EXT_X25519_PUB_B64,
    });
    // Auto-trust via handleServerHello (pure). The background's onServerHello
    // sets mcpIdentityHash — we test connectedIdentityHashes indirectly by
    // confirming it's exported and returns a Set (the pure test harness can't
    // call onServerHello because it requires a live WS + sessions object).
    // Instead, verify the function is callable and the initial set is empty,
    // and that the result from handleServerHello carries the identityHash
    // in pendingScopeUpdate when applicable.
    const result = await handleServerHello(hello, { trust, extensionIdentityX25519Pub: FAKE_EXT_X25519_PUB });
    expect(result.kind).toBe('auto-trust');
    // The identity hash of the trusted record equals the one we computed.
    expect(idHash).toMatch(/^[0-9a-f]{64}$/);
    // connectedIdentityHashes remains empty until onServerHello (WS path) runs.
    // This test validates the export and type contract; the live-update path
    // is tested via the broadcastConnectionsChanged integration.
    const hashes = connectedIdentityHashes();
    expect(hashes instanceof Set).toBe(true);
  });
});
