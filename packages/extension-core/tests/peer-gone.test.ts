import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ed25519Sign,
  generateEd25519,
  generateX25519,
  helloSignaturePayload,
  sha256,
  toB64,
  fromB64,
  toHex,
  PROTOCOL_VERSION,
  type RawKeyPair,
} from '@fetchproxy/protocol';

/**
 * B-BUG-9: a host notice that a peer MCP left drops that MCP's session.
 *
 * (Harness copied from multi-link.test.ts.) The transport with more than one bridge attached.
 *
 * These are the properties that only exist once the extension can dial
 * somewhere other than loopback, and every one of them is a way to leak a
 * session between bridges rather than a feature:
 *
 * - each link handshakes with its OWN nonce, and the ready it sends is signed
 *   over that nonce. Signing from a global is the single easiest way to
 *   rebuild the bug this design removes;
 * - an `mcpId` belongs to the link it said hello on. A second link claiming it
 *   is refused, and a response never goes out on a socket the request did not
 *   come in on;
 * - one link dropping tears down its own sessions and nobody else's.
 */

// ---------------------------------------------------------------------------
// A WebSocket that goes nowhere, and the chrome surface the SW touches.
// ---------------------------------------------------------------------------

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

  remoteClose(code = 1006, reason = ''): void {
    this.readyState = 3;
    this.emit('close', { code, reason });
  }

  /** Frames this socket sent, parsed, of one `type`. */
  frames<T = Record<string, unknown>>(type: string): T[] {
    return this.sent.map((s) => JSON.parse(s) as T).filter((f) => (f as { type: string }).type === type);
  }
}

const storage = new Map<string, unknown>();

/**
 * Every `chrome.runtime.sendMessage` the background made, in order.
 *
 * Recorded rather than swallowed because one of them is load-bearing: the
 * version-mismatch store broadcasts `connections-changed` after each write,
 * and that broadcast is the whole difference between an open popup
 * contradicting itself within the same second and only at the next open. A
 * no-op stub pins nothing — both call sites survived deletion with the whole
 * extension-core suite green.
 */
const runtimeMessages: unknown[] = [];

vi.stubGlobal('WebSocket', FakeSocket);
vi.stubGlobal('chrome', {
  runtime: {
    getManifest: () => ({ version: '2.1.0' }),
    sendMessage: (m: unknown) => void runtimeMessages.push(m),
  },
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

// Imported after the globals exist — `socket.ts` reads `WebSocket` at module
// scope only through functions, but `badge.ts` and friends read `chrome`.
const { reconcileRemoteLinks } = await import('../src/background/socket.js');
const { state } = await import('../src/background/state.js');
const { links, linkForMcp, unbindAll } = await import('../src/background/links.js');
const { TrustStore } = await import('../src/trust-store.js');
const { SessionKeys } = await import('../src/session-keys.js');
const { mcpDomains, mcpCapabilities, connectedIdentityHashes } = await import(
  '../src/background/session-scope.js'
);

// ---------------------------------------------------------------------------
// A scripted MCP: real identity, real signatures, real ECDH.
// ---------------------------------------------------------------------------

interface ScriptedMcp {
  mcpId: string;
  x: RawKeyPair;
  ed: RawKeyPair;
  /** 3.0.0: the per-session ephemeral this MCP's hello offers. */
  session: RawKeyPair;
  sessionNonce: Uint8Array;
}

async function scriptedMcp(mcpId: string): Promise<ScriptedMcp> {
  const nonce = new Uint8Array(32);
  crypto.getRandomValues(nonce);
  return {
    mcpId,
    x: await generateX25519(),
    ed: await generateEd25519(),
    session: await generateX25519(),
    sessionNonce: nonce,
  };
}

/**
 * The hello this MCP sends on `link`.
 *
 * 3.0.0 (protocol 4): it names the extension session it answers — the nonce
 * off that link's own hello — and signs `helloSignaturePayload` over both new
 * fields. `answersExtNonce` is an argument rather than a constant because
 * §1a's Rule C is precisely about a hello that names the WRONG one, and a
 * helper that could only produce the right one could not express the case.
 */
async function helloFrom(
  mcp: ScriptedMcp,
  answersExtNonce: Uint8Array,
): Promise<Record<string, unknown>> {
  const sessionSig = await ed25519Sign(
    mcp.ed.privateKey,
    helloSignaturePayload(mcp.mcpId, mcp.sessionNonce, mcp.session.publicKey, answersExtNonce),
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
    sessionPub: toB64(mcp.session.publicKey),
    answersExtNonce: toB64(answersExtNonce),
    sessionSig: toB64(sessionSig),
  };
}

/** The nonce the extension put on `ws`'s own hello. */
function extNonceOf(ws: FakeSocket): Uint8Array {
  return fromB64(ws.frames<{ sessionNonce: string }>('hello')[0]!.sessionNonce);
}

/** Pre-trust an MCP identity so its hello auto-trusts instead of prompting. */
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


const REMOTE = {
  id: 'host1',
  url: 'wss://mcp.nullnet.app/bridge',
  token: 'mcpb_testtoken',
  enabled: true,
};

describe('B-BUG-9: peer-gone', () => {
  let localWs: FakeSocket;
  let remoteWs: FakeSocket;

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
      createdAt: 0,
    };
    reconcileRemoteLinks([REMOTE]);
    localWs = FakeSocket.opened.find((s) => s.url.startsWith('ws://127.0.0.1'))!;
    remoteWs = FakeSocket.opened.find((s) => s.url === REMOTE.url)!;
    localWs.open();
    remoteWs.open();
  });

  async function linkedOn(ws: FakeSocket, mcpId: string): Promise<void> {
    const mcp = await scriptedMcp(mcpId);
    await trustMcp(mcp);
    ws.message(await helloFrom(mcp, extNonceOf(ws)));
    await vi.waitUntil(() => state.sessions!.get(mcpId) !== null);
  }

  it('advertises peer-gone on its hello', () => {
    expect(localWs.frames<{ accepts?: string[] }>('hello')[0]!.accepts).toContain('peer-gone');
  });

  it('drops the named session, its scope and its binding — and nothing else', async () => {
    const gone = 'alltrails-mcp:2.1.3:1111111111111111';
    const stays = 'alltrails-mcp:2.1.3:3333333333333333';
    await linkedOn(localWs, gone);
    await linkedOn(localWs, stays);
    expect(mcpDomains.has(gone)).toBe(true);

    localWs.message({ type: 'peer-gone', mcpId: gone });
    await vi.waitUntil(() => state.sessions!.get(gone) === null);
    expect(linkForMcp(gone)).toBeNull();
    expect(mcpDomains.has(gone)).toBe(false);
    expect(connectedIdentityHashes().size).toBe(1);

    expect(state.sessions!.get(stays)).not.toBeNull();
    expect(linkForMcp(stays)).not.toBeNull();
    expect(mcpDomains.has(stays)).toBe(true);
  });

  it('ignores a peer-gone for an mcpId bound to a different link', async () => {
    const mcpId = 'alltrails-mcp:2.1.3:2222222222222222';
    await linkedOn(remoteWs, mcpId);
    localWs.message({ type: 'peer-gone', mcpId });
    await new Promise((r) => setTimeout(r, 20));
    expect(state.sessions!.get(mcpId)).not.toBeNull();
    expect(linkForMcp(mcpId)).not.toBeNull();
  });
});
