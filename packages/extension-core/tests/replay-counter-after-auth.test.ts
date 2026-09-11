import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ecdhX25519,
  ed25519Sign,
  generateEd25519,
  generateX25519,
  hkdfSha256,
  openEncryptedFrame,
  sealInnerFrame,
  sha256,
  toB64,
  fromB64,
  toHex,
  concatBytes,
  HKDF_SESSION_INFO,
  PROTOCOL_VERSION,
  type EncryptedFrame,
  type RawKeyPair,
} from '@fetchproxy/protocol';

/**
 * The extension's replay counter advances for a frame that AUTHENTICATED,
 * never for one that merely arrived.
 *
 * `onEncryptedFrame` used to call `acceptInboundSeq` before the AES-GCM open,
 * so a single unauthenticated frame carrying a high `seq` set `lastInbound`
 * out of reach and every genuine frame after it was dropped as a replay —
 * with the socket kept open and the MCP's calls simply never answered. The
 * seq gate is now a question asked before the open (`isFreshInboundSeq`) and
 * an answer recorded after it (`commitInboundSeq`).
 */

class FakeSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  static opened: FakeSocket[] = [];

  readyState = 0;
  sent: string[] = [];
  private listeners = new Map<string, ((ev: unknown) => void)[]>();

  constructor(
    readonly url: string,
    readonly protocols?: string[],
  ) {
    FakeSocket.opened.push(this);
  }

  addEventListener(type: string, cb: (ev: unknown) => void): void {
    const list = this.listeners.get(type) ?? [];
    list.push(cb);
    this.listeners.set(type, list);
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(): void {
    this.readyState = 3;
  }

  private emit(type: string, ev: unknown): void {
    for (const cb of this.listeners.get(type) ?? []) cb(ev);
  }

  open(): void {
    this.readyState = 1;
    this.emit('open', {});
  }

  message(payload: unknown): void {
    this.emit('message', { data: JSON.stringify(payload) });
  }

  frames<T = Record<string, unknown>>(type: string): T[] {
    return this.sent
      .map((s) => JSON.parse(s) as T)
      .filter((f) => (f as { type: string }).type === type);
  }
}

const storage = new Map<string, unknown>();

vi.stubGlobal('WebSocket', FakeSocket);
vi.stubGlobal('chrome', {
  runtime: { getManifest: () => ({ version: '2.1.0' }), sendMessage: () => {} },
  storage: {
    local: {
      get: async (k: string | string[]) => {
        const keys = Array.isArray(k) ? k : [k];
        const out: Record<string, unknown> = {};
        for (const key of keys) if (storage.has(key)) out[key] = storage.get(key);
        return out;
      },
      set: async (kv: Record<string, unknown>) => {
        for (const [k, v] of Object.entries(kv)) storage.set(k, v);
      },
      remove: async (k: string) => void storage.delete(k),
    },
  },
  tabs: { query: async () => [], create: async () => ({ id: 1 }) },
});

const { connect } = await import('../src/background/socket.js');
const { state } = await import('../src/background/state.js');
const { links, unbindAll } = await import('../src/background/links.js');
const { TrustStore } = await import('../src/trust-store.js');
const { SessionKeys } = await import('../src/session-keys.js');
const { mcpDomains, mcpCapabilities } = await import('../src/background/session-scope.js');

interface ScriptedMcp {
  mcpId: string;
  x: RawKeyPair;
  ed: RawKeyPair;
  sessionNonce: Uint8Array;
}

async function scriptedMcp(mcpId: string): Promise<ScriptedMcp> {
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);
  return { mcpId, x: await generateX25519(), ed: await generateEd25519(), sessionNonce: nonce };
}

async function helloFrom(mcp: ScriptedMcp): Promise<Record<string, unknown>> {
  const sessionSig = await ed25519Sign(
    mcp.ed.privateKey,
    concatBytes(new TextEncoder().encode(mcp.mcpId), mcp.sessionNonce),
  );
  return {
    type: 'hello',
    role: 'server',
    protocolVersion: PROTOCOL_VERSION,
    mcpId: mcp.mcpId,
    serverName: 'alltrails-mcp',
    version: '2.1.3',
    domains: ['alltrails.com'],
    capabilities: ['fetch'],
    identityX25519Pub: toB64(mcp.x.publicKey),
    identityEd25519Pub: toB64(mcp.ed.publicKey),
    sessionNonce: toB64(mcp.sessionNonce),
    sessionSig: toB64(sessionSig),
  };
}

async function trustMcp(mcp: ScriptedMcp): Promise<void> {
  const hash = toHex(await sha256(mcp.x.publicKey));
  await state.trust!.put(hash, {
    serverName: 'alltrails-mcp',
    domains: ['alltrails.com'],
    capabilities: ['fetch'],
    identityX25519Pub: toB64(mcp.x.publicKey),
    identityEd25519Pub: toB64(mcp.ed.publicKey),
    extensionIdentityX25519Pub: toB64(state.extIdentity!.x25519Pub),
    extensionIdentityEd25519Pub: toB64(state.extIdentity!.ed25519Pub),
  });
}

async function sessionKeyFor(
  mcp: ScriptedMcp,
  ready: { extensionSessionPub: string },
): Promise<Uint8Array> {
  const shared = await ecdhX25519(mcp.x.privateKey, fromB64(ready.extensionSessionPub));
  return hkdfSha256(shared, mcp.sessionNonce, new TextEncoder().encode(HKDF_SESSION_INFO), 32);
}

/** A frame that passes `validateFrame` and fails AES-GCM authentication. */
function forgedFrame(mcpId: string, seq: number): Record<string, unknown> {
  return {
    type: 'frame',
    mcpId,
    seq,
    iv: toB64(new Uint8Array(12).fill(7)),
    ciphertext: toB64(new Uint8Array(48).fill(9)),
  };
}

describe('extension replay counter', () => {
  let localWs: FakeSocket;

  beforeEach(async () => {
    FakeSocket.opened = [];
    storage.clear();
    unbindAll();
    links.clear();
    mcpDomains.clear();
    mcpCapabilities.clear();
    state.trust = new TrustStore('2.1.0');
    state.sessions = new SessionKeys();
    const x = await generateX25519();
    const ed = await generateEd25519();
    state.extIdentity = {
      x25519Pub: x.publicKey,
      x25519Priv: x.privateKey,
      ed25519Pub: ed.publicKey,
      ed25519Priv: ed.privateKey,
    };
    connect();
    localWs = FakeSocket.opened.find((s) => s.url.startsWith('ws://127.0.0.1'))!;
    localWs.open();
  });

  it('a forged frame does not wedge the session behind its seq', async () => {
    const warns = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const mcp = await scriptedMcp('alltrails-mcp:2.1.3:8888888888888888');
    await trustMcp(mcp);
    localWs.message(await helloFrom(mcp));
    await vi.waitUntil(() => localWs.frames('ready').length > 0);
    const key = await sessionKeyFor(
      mcp,
      localWs.frames<{ extensionSessionPub: string }>('ready')[0]!,
    );

    // Anything that can put a frame on this socket claims seq 9 without
    // holding the key.
    localWs.message(forgedFrame(mcp.mcpId, 9));
    await vi.waitUntil(() => warns.mock.calls.length > 0);
    expect(localWs.frames('frame')).toHaveLength(0);

    // The genuine ping the MCP sends next carries seq 1 and must still be
    // answered.
    localWs.message(await sealInnerFrame(key, mcp.mcpId, 1, { type: 'ping' }));
    await vi.waitUntil(() => localWs.frames('frame').length > 0);
    const pong = localWs.frames<EncryptedFrame>('frame')[0]!;
    expect((await openEncryptedFrame(key, pong)).type).toBe('pong');

    // The counter DID move for the frame that authenticated: replaying it is
    // still refused.
    localWs.message(await sealInnerFrame(key, mcp.mcpId, 1, { type: 'ping' }));
    await new Promise((r) => setTimeout(r, 20));
    expect(localWs.frames('frame')).toHaveLength(1);
  });
});
