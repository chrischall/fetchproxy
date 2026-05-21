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
  capabilities?: ('fetch' | 'read_cookies')[],
): Promise<HelloFrameFromServer> {
  const x = await generateX25519();
  const ed = await generateEd25519();
  const sessionNonce = new Uint8Array(32).fill(9);
  const sig = await ed25519Sign(
    ed.privateKey,
    concat(new TextEncoder().encode(mcpId), sessionNonce),
  );
  return {
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
    const result = await handleServerHello(hello, { trust });
    expect(result.kind).toBe('needs-pair');
    if (result.kind === 'needs-pair') {
      const expectedPub = new Uint8Array(Buffer.from(hello.identityX25519Pub, 'base64'));
      expect(result.pairCode).toBe(await derivePairCode(expectedPub));
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
    const result = await handleServerHello(hello, { trust });
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
    });

    const result = await handleServerHello(hello, { trust });
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
    });
    const result = await handleServerHello(hello, { trust });
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
    const result = await handleServerHello(bad, { trust });
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
    });
    const result = await handleServerHello(hello, { trust });
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
    });
    const result = await handleServerHello(hello, { trust });
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
      const result = await handleServerHello(hello, { trust });
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
      const result = await handleServerHello(hello, { trust });
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
      });
      const result = await handleServerHello(hello, { trust });
      expect(result.kind).toBe('auto-trust');
      if (result.kind === 'auto-trust') {
        expect(result.capabilities).toEqual(['fetch', 'read_cookies']);
      }
    });

    it('falls back to needs-pair when an MCP adds a capability (upgrade)', async () => {
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
      // Previously paired without read_cookies — the upgrade should
      // force the user to re-approve rather than silently auto-trusting.
      await trust.put(idHash, {
        serverName: 'credit-karma-mcp',
        domains: ['creditkarma.com'],
        capabilities: ['fetch'],
        identityX25519Pub: hello.identityX25519Pub,
        identityEd25519Pub: hello.identityEd25519Pub,
      });
      const result = await handleServerHello(hello, { trust });
      expect(result.kind).toBe('needs-pair');
      if (result.kind === 'needs-pair') {
        expect(result.capabilities).toEqual(['fetch', 'read_cookies']);
      }
    });

    it('falls back to needs-pair when an MCP drops a capability (downgrade)', async () => {
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
      });
      const result = await handleServerHello(hello, { trust });
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
      });
      const result = await handleServerHello(hello, { trust });
      expect(result.kind).toBe('auto-trust');
    });
  });
});
