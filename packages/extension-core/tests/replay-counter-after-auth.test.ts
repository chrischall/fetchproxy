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
  type InnerFrame,
  type RawKeyPair,
} from '@fetchproxy/protocol';
import { loadOrCreateExtensionIdentity } from '../src/extension-identity.js';
import { freshVault } from './helpers/vault.js';
import { settle } from './helpers/settle.js';

/** Sleep at least `ms`, then until no socket has sent anything new. */
const settleFrames = (ms: number): Promise<void> =>
  settle(() => FakeSocket.opened.map((s) => s.sent.length).join(','), ms);

/**
 * The extension's replay counter advances for a frame that AUTHENTICATED,
 * never for one that merely arrived.
 *
 * `onEncryptedFrame` used to call `acceptInboundSeq` before the AES-GCM open,
 * so a single unauthenticated frame carrying a high `seq` set `lastInbound`
 * out of reach and every genuine frame after it was dropped as a replay —
 * with the socket kept open and the MCP's calls simply never answered. The
 * seq gate is now a claim taken before the open (`claimInboundSeq`) and an
 * answer recorded after it: `commitInboundSeq` when the frame authenticated,
 * `releaseInboundSeq` when it did not.
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
const { SessionKeys, SessionEntry } = await import('../src/session-keys.js');
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

describe('extension replay counter', () => {
  let localWs: FakeSocket;

  beforeEach(async () => {
    FakeSocket.opened = [];
    storage.clear();
    freshVault();
    unbindAll();
    links.clear();
    mcpDomains.clear();
    mcpCapabilities.clear();
    state.trust = new TrustStore('2.1.0');
    state.sessions = new SessionKeys();
    // Loaded through the vault, as boot does — which also primes it, so the
    // first vault access inside a test is not the one-time initialisation.
    state.extIdentity = await loadOrCreateExtensionIdentity();
    connect();
    localWs = FakeSocket.opened.find((s) => s.url.startsWith('ws://127.0.0.1'))!;
    localWs.open();
  });

  it('a forged frame does not wedge the session behind its seq', async () => {
    const warns = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const mcp = await scriptedMcp('alltrails-mcp:2.1.3:8888888888888888');
    await trustMcp(mcp);
    localWs.message(await helloFrom(mcp, extNonceOf(localWs)));
    await vi.waitUntil(() => localWs.frames('ready').length > 0);
    const key = await sessionKeyFor(
      mcp,
      localWs.frames<{ extensionSessionPub: string }>('ready')[0]!,
      extNonceOf(localWs),
    );

    // Anything that can put a frame on this socket claims seq 9 without
    // holding the key.
    localWs.message(forgedFrame(mcp.mcpId, 9));
    await vi.waitUntil(() => warns.mock.calls.length > 0);
    expect(localWs.frames('frame')).toHaveLength(0);

    // The genuine ping the MCP sends next carries seq 1 and must still be
    // answered.
    localWs.message(await sealInnerFrame(key, mcp.mcpId, 1, { type: 'ping' }, 's2e'));
    await vi.waitUntil(() => localWs.frames('frame').length > 0);
    const pong = localWs.frames<EncryptedFrame>('frame')[0]!;
    expect((await openEncryptedFrame(key, pong, 'e2s')).type).toBe('pong');

    // The counter DID move for the frame that authenticated: replaying it is
    // still refused.
    localWs.message(await sealInnerFrame(key, mcp.mcpId, 1, { type: 'ping' }, 's2e'));
    await settleFrames(20);
    expect(localWs.frames('frame')).toHaveLength(1);
  });

  // -------------------------------------------------------------------
  // Task 3.2 — the AAD, from the extension's side. `frameAad` binds every
  // frame to `(mcpId, seq, direction)`, and none of the three rides inside
  // the ciphertext, so until v4 nothing the tag covered committed to any of
  // them: a recorded frame could be replayed under a bumped counter, re-filed
  // under another MCP's id on the shared socket, or reflected at its sender.
  // -------------------------------------------------------------------
  it('seals its own frames as e2s, so one reflected back at it does not open', async () => {
    const mcp = await scriptedMcp('alltrails-mcp:2.1.3:3030303030303030');
    await trustMcp(mcp);
    localWs.message(await helloFrom(mcp, extNonceOf(localWs)));
    await vi.waitUntil(() => localWs.frames('ready').length > 0);
    const key = await sessionKeyFor(
      mcp,
      localWs.frames<{ extensionSessionPub: string }>('ready')[0]!,
      extNonceOf(localWs),
    );

    localWs.message(await sealInnerFrame(key, mcp.mcpId, 1, { type: 'ping' }, 's2e'));
    await vi.waitUntil(() => localWs.frames('frame').length > 0);
    const pong = localWs.frames<EncryptedFrame>('frame')[0]!;

    // It opens as what it is, and under nothing else. Each of these is the
    // tag failing — not a check downstream — which is the whole difference
    // v4 makes.
    expect((await openEncryptedFrame(key, pong, 'e2s')).type).toBe('pong');
    await expect(openEncryptedFrame(key, pong, 's2e')).rejects.toThrow();
    await expect(
      openEncryptedFrame(key, { ...pong, seq: pong.seq + 1 }, 'e2s'),
    ).rejects.toThrow();
    await expect(
      openEncryptedFrame(key, { ...pong, mcpId: 'alltrails-mcp:2.1.3:4040404040404040' }, 'e2s'),
    ).rejects.toThrow();
  });

  it('releases the claim when a replay under a bumped seq fails the tag', async () => {
    // The part that matters: a frame whose AAD does not match fails at
    // `decrypt-failed`, which RELEASES the claimed seq rather than committing
    // it — so the next genuine frame carrying that seq is still accepted.
    // Committing it would let anything able to reach this socket burn a seq
    // it does not hold the key for, and every genuine frame behind it would
    // be dropped as a replay while the socket looked healthy.
    const warns = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const mcp = await scriptedMcp('alltrails-mcp:2.1.3:5050505050505050');
    await trustMcp(mcp);
    localWs.message(await helloFrom(mcp, extNonceOf(localWs)));
    await vi.waitUntil(() => localWs.frames('ready').length > 0);
    const key = await sessionKeyFor(
      mcp,
      localWs.frames<{ extensionSessionPub: string }>('ready')[0]!,
      extNonceOf(localWs),
    );

    const genuine = await sealInnerFrame(key, mcp.mcpId, 1, { type: 'ping' }, 's2e');
    // The same ciphertext, re-labelled seq 2. Under v3 the tag did not cover
    // the seq, so this decrypted and was answered.
    localWs.message({ ...genuine, seq: 2 });
    await vi.waitUntil(() => warns.mock.calls.length > 0);
    expect(localWs.frames('frame')).toHaveLength(0);

    // seq 2 was released, so the MCP's own frame at seq 2 still lands. (1
    // first, because the counter is in order.)
    localWs.message(genuine);
    await vi.waitUntil(() => localWs.frames('frame').length > 0);
    localWs.message(await sealInnerFrame(key, mcp.mcpId, 2, { type: 'ping' }, 's2e'));
    await vi.waitUntil(() => localWs.frames('frame').length > 1);
    expect(localWs.frames('frame')).toHaveLength(2);
    warns.mockRestore();
  });

  it('an authenticated frame that fails validation still spends its seq', async () => {
    const warns = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    const mcp = await scriptedMcp('alltrails-mcp:2.1.3:7777777777777777');
    await trustMcp(mcp);
    localWs.message(await helloFrom(mcp, extNonceOf(localWs)));
    await vi.waitUntil(() => localWs.frames('ready').length > 0);
    const key = await sessionKeyFor(
      mcp,
      localWs.frames<{ extensionSessionPub: string }>('ready')[0]!,
      extNonceOf(localWs),
    );

    // Decrypts under the live session key — so whoever sent it holds the key
    // and this seq is genuinely spent — but the plaintext is not a frame this
    // protocol knows. `peer.ts` states the rule the extension has to agree
    // with: the counter moves once a frame AUTHENTICATES, whatever validation
    // then says about it.
    localWs.message(
      await sealInnerFrame(key, mcp.mcpId, 5, { type: 'bogus' } as unknown as InnerFrame, 's2e'),
    );
    await vi.waitUntil(() => warns.mock.calls.length + errors.mock.calls.length > 0);
    expect(localWs.frames('frame')).toHaveLength(0);
    // seq 5 is spent: a captured frame replayed at it is refused.
    localWs.message(await sealInnerFrame(key, mcp.mcpId, 5, { type: 'ping' }, 's2e'));
    await settleFrames(20);
    expect(localWs.frames('frame')).toHaveLength(0);

    // And the session is not wedged — the next seq is answered as usual.
    localWs.message(await sealInnerFrame(key, mcp.mcpId, 6, { type: 'ping' }, 's2e'));
    await vi.waitUntil(() => localWs.frames('frame').length > 0);
    const pong = localWs.frames<EncryptedFrame>('frame')[0]!;
    expect((await openEncryptedFrame(key, pong, 'e2s')).type).toBe('pong');

    // And it was said out loud, told apart from a stale-key drop: this frame
    // came from the live peer, so it is a protocol bug rather than a
    // straggler from a session that already rotated.
    expect(errors).toHaveBeenCalled();

    warns.mockRestore();
    errors.mockRestore();
  });

  it('a saturated claim is logged, and a replay is not logged as one', async () => {
    // Both refusals drop the frame unread; only the log can say which one it
    // was. Forced through the prototype because genuinely holding 1024 claims
    // open means 1024 frames parked mid-decrypt at once.
    const warns = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const saturated = () => warns.mock.calls.filter((c) => /saturat/i.test(String(c[0])));
    const mcp = await scriptedMcp('alltrails-mcp:2.1.3:6060606060606060');
    await trustMcp(mcp);
    localWs.message(await helloFrom(mcp, extNonceOf(localWs)));
    await vi.waitUntil(() => localWs.frames('ready').length > 0);
    const key = await sessionKeyFor(
      mcp,
      localWs.frames<{ extensionSessionPub: string }>('ready')[0]!,
      extNonceOf(localWs),
    );

    // Latched per session (#376): a run of saturated refusals logs ONCE, on
    // the transition into saturation — a line per dropped frame turned a flood
    // into a log flood. The next `'ok'` claim re-arms it. A replay neither logs
    // nor touches the latch.
    const claim = vi.spyOn(SessionEntry.prototype, 'claimInboundSeq');
    let seq = 0;
    const next = async (verdict?: 'replay' | 'saturated') => {
      if (verdict) claim.mockReturnValueOnce(verdict);
      seq += 1;
      const calls = claim.mock.calls.length + 1;
      localWs.message(await sealInnerFrame(key, mcp.mcpId, seq, { type: 'ping' }, 's2e'));
      await vi.waitUntil(() => claim.mock.calls.length === calls);
      await settleFrames(20);
    };

    await next('replay');
    expect(saturated()).toHaveLength(0);

    for (let i = 0; i < 5; i += 1) await next('saturated');
    expect(saturated()).toHaveLength(1);
    expect(String(saturated()[0]![0])).toContain(mcp.mcpId);
    expect(localWs.frames('frame')).toHaveLength(0);

    // The set drained: the next frame claims for real and is answered.
    await next();
    await vi.waitUntil(() => localWs.frames('frame').length === 1);

    for (let i = 0; i < 3; i += 1) await next('saturated');
    expect(saturated()).toHaveLength(2);

    await next('replay');
    expect(saturated()).toHaveLength(2);

    claim.mockRestore();
    warns.mockRestore();
  });
});
