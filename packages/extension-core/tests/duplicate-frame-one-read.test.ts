import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ecdhX25519,
  ed25519Sign,
  generateEd25519,
  generateX25519,
  hkdfSha256,
  openEncryptedFrame,
  helloSignaturePayload,
  transcriptHash,
  sealInnerFrame,
  sha256,
  toB64,
  fromB64,
  toHex,
  HKDF_SESSION_INFO,
  PROTOCOL_VERSION,
  type EncryptedFrame,
  type RawKeyPair,
} from '@fetchproxy/protocol';
import { generateExtensionIdentity } from '../src/identity-keys.js';

/**
 * One seq, one frame — including when the two copies arrive in the SAME read.
 *
 * The inbound gate asked `isFreshInboundSeq` before the AES-GCM open and
 * recorded `commitInboundSeq` after it, with an `await` in between. A question
 * changes nothing, so two identical frames delivered in one pass both got
 * their yes before either could commit. `onMessage` is dispatched
 * fire-and-forget here, so both then ran.
 *
 * On this side that is worse than the wedge the split was closing. The
 * extension is the RESPONDER: a duplicate that gets past the gate reaches
 * `handleRequest`, and `handlers/dispatch.ts` has no per-id guard of its own —
 * so a repeated `write_cookies` or non-GET `fetch` would EXECUTE twice. The
 * gate is now a synchronous claim taken before any await, which is the only
 * place a duplicate arriving in the same read can be told apart from the
 * original.
 *
 * The two frames are therefore delivered with nothing awaited between them. A
 * test that awaits the first would not reproduce the bug.
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

  /** Synchronous, exactly as a WS receiver emits each message of one read. */
  message(payload: unknown): void {
    this.emit('message', { data: JSON.stringify(payload) });
  }

  /** A message already serialised — so two copies are byte-identical. */
  raw(data: string): void {
    this.emit('message', { data });
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
  /** 3.0.0 (protocol 4): the per-session ephemeral its hello offers. */
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
 * 3.0.0 (protocol 4): the hello names the extension session it answers (the
 * nonce off that link's own hello) and signs `helloSignaturePayload` over both
 * new fields, which is what makes the ephemeral the session key comes from
 * unsubstitutable.
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

/**
 * 3.0.0 (protocol 4): ephemeral x ephemeral, salted with the transcript over
 * both nonces and both ephemerals. Under v3 the MCP's half was its long-term
 * identity key and the salt was its own nonce.
 */
async function sessionKeyFor(
  mcp: ScriptedMcp,
  ready: { extensionSessionPub: string },
  extNonce: Uint8Array,
): Promise<Uint8Array> {
  const extPub = fromB64(ready.extensionSessionPub);
  const shared = await ecdhX25519(mcp.session.privateKey, extPub);
  const salt = await transcriptHash(mcp.sessionNonce, extNonce, mcp.session.publicKey, extPub);
  return hkdfSha256(shared, salt, new TextEncoder().encode(HKDF_SESSION_INFO), 32);
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

describe('extension: a duplicate frame in one read is handled exactly once', () => {
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
    state.extIdentity = await generateExtensionIdentity();
    connect();
    localWs = FakeSocket.opened.find((s) => s.url.startsWith('ws://127.0.0.1'))!;
    localWs.open();
  });

  it('two copies delivered back to back are answered once', async () => {
    const mcp = await scriptedMcp('alltrails-mcp:2.1.3:5555555555555555');
    await trustMcp(mcp);
    localWs.message(await helloFrom(mcp, extNonceOf(localWs)));
    await vi.waitUntil(() => localWs.frames('ready').length > 0);
    const key = await sessionKeyFor(
      mcp,
      localWs.frames<{ extensionSessionPub: string }>('ready')[0]!,
      extNonceOf(localWs),
    );

    // Nothing is awaited between the two: one read of the socket, two
    // identical frames, exactly as a retransmit or a replaying relay delivers
    // them.
    const dup = JSON.stringify(await sealInnerFrame(key, mcp.mcpId, 1, { type: 'ping' }, 's2e'));
    localWs.raw(dup);
    localWs.raw(dup);

    await vi.waitUntil(() => localWs.frames('frame').length > 0);
    // Room for a second answer to appear, then the assertion that it did not.
    await new Promise((r) => setTimeout(r, 50));
    expect(localWs.frames('frame')).toHaveLength(1);
    const pong = localWs.frames<EncryptedFrame>('frame')[0]!;
    expect((await openEncryptedFrame(key, pong, 'e2s')).type).toBe('pong');

    // The claim did not wedge the session behind the seq it took.
    localWs.message(await sealInnerFrame(key, mcp.mcpId, 2, { type: 'ping' }, 's2e'));
    await vi.waitUntil(() => localWs.frames('frame').length > 1);
    expect(localWs.frames('frame')).toHaveLength(2);
  });

  it('a claim released by a failed open leaves the seq open to the genuine frame', async () => {
    const warns = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const mcp = await scriptedMcp('alltrails-mcp:2.1.3:6666666666666666');
    await trustMcp(mcp);
    localWs.message(await helloFrom(mcp, extNonceOf(localWs)));
    await vi.waitUntil(() => localWs.frames('ready').length > 0);
    const key = await sessionKeyFor(
      mcp,
      localWs.frames<{ extensionSessionPub: string }>('ready')[0]!,
      extNonceOf(localWs),
    );

    // A forged frame claims seq 4 and fails to authenticate. It never
    // happened, so the claim goes back and the counter does not move — the
    // property the two-call gate exists for, which the claim must not cost.
    localWs.message(forgedFrame(mcp.mcpId, 4));
    await vi.waitUntil(() => warns.mock.calls.length > 0);
    expect(localWs.frames('frame')).toHaveLength(0);

    localWs.message(await sealInnerFrame(key, mcp.mcpId, 4, { type: 'ping' }, 's2e'));
    await vi.waitUntil(() => localWs.frames('frame').length > 0);
    const pong = localWs.frames<EncryptedFrame>('frame')[0]!;
    expect((await openEncryptedFrame(key, pong, 'e2s')).type).toBe('pong');

    warns.mockRestore();
  });
});
