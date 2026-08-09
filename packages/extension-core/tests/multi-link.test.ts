import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ecdhX25519,
  ed25519Sign,
  ed25519Verify,
  generateEd25519,
  generateX25519,
  hkdfSha256,
  openEncryptedFrame,
  readySignaturePayload,
  sealInnerFrame,
  sha256,
  toB64,
  fromB64,
  toHex,
  concatBytes,
  HKDF_SESSION_INFO,
  PROTOCOL_VERSION,
  type RawKeyPair,
} from '@fetchproxy/protocol';

/**
 * The transport with more than one bridge attached.
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

// Imported after the globals exist — `socket.ts` reads `WebSocket` at module
// scope only through functions, but `badge.ts` and friends read `chrome`.
const { connect, reconcileRemoteLinks } = await import('../src/background/socket.js');
const { state } = await import('../src/background/state.js');
const { links, linkForMcp, unbindAll } = await import('../src/background/links.js');
const { TrustStore } = await import('../src/trust-store.js');
const { SessionKeys } = await import('../src/session-keys.js');
const { mcpDomains, mcpCapabilities } = await import('../src/background/session-scope.js');

// ---------------------------------------------------------------------------
// A scripted MCP: real identity, real signatures, real ECDH.
// ---------------------------------------------------------------------------

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

/** The session key the MCP would derive from the ready frame it got back. */
async function sessionKeyFor(mcp: ScriptedMcp, ready: { extensionSessionPub: string }): Promise<Uint8Array> {
  const shared = await ecdhX25519(mcp.x.privateKey, fromB64(ready.extensionSessionPub));
  return hkdfSha256(shared, mcp.sessionNonce, new TextEncoder().encode(HKDF_SESSION_INFO), 32);
}

const REMOTE = {
  id: 'host1',
  url: 'wss://mcp.nullnet.app/bridge',
  token: 'mcpb_testtoken',
  enabled: true,
};

describe('two bridges at once', () => {
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
    };

    reconcileRemoteLinks([REMOTE]);
    localWs = FakeSocket.opened.find((s) => s.url.startsWith('ws://127.0.0.1'))!;
    remoteWs = FakeSocket.opened.find((s) => s.url === REMOTE.url)!;
    localWs.open();
    remoteWs.open();
  });

  it('dials loopback unconditionally and the remote target alongside it', () => {
    expect(FakeSocket.opened).toHaveLength(2);
    expect(localWs.url).toBe('ws://127.0.0.1:37149');
    expect(localWs.protocols).toBeUndefined();
    // The credential rides in the subprotocol list — a service worker cannot
    // set a request header.
    expect(remoteWs.protocols).toEqual(['fetchproxy.bridge.v1', 'fetchproxy.token.mcpb_testtoken']);
  });

  it('says hello on each link with a nonce of its own', () => {
    const local = localWs.frames<{ sessionNonce: string; role: string }>('hello');
    const remote = remoteWs.frames<{ sessionNonce: string; role: string }>('hello');
    expect(local).toHaveLength(1);
    expect(remote).toHaveLength(1);
    expect(local[0]!.role).toBe('extension');
    expect(local[0]!.sessionNonce).not.toBe(remote[0]!.sessionNonce);
  });

  it('is idempotent per link — a keepalive tick opens no second socket', () => {
    connect();
    connect();
    expect(FakeSocket.opened).toHaveLength(2);
  });

  it('signs each ready over the nonce of the link it answers on', async () => {
    const onLocal = await scriptedMcp('alltrails-mcp:2.1.3:1111111111111111');
    const onRemote = await scriptedMcp('alltrails-mcp:2.1.3:2222222222222222');
    await trustMcp(onLocal);
    await trustMcp(onRemote);

    localWs.message(await helloFrom(onLocal));
    remoteWs.message(await helloFrom(onRemote));
    await vi.waitUntil(() => localWs.frames('ready').length > 0 && remoteWs.frames('ready').length > 0);

    const localNonce = fromB64(localWs.frames<{ sessionNonce: string }>('hello')[0]!.sessionNonce);
    const remoteNonce = fromB64(remoteWs.frames<{ sessionNonce: string }>('hello')[0]!.sessionNonce);
    const localReady = localWs.frames<{ mcpId: string; extensionSessionPub: string; sessionSig: string }>('ready')[0]!;
    const remoteReady = remoteWs.frames<{ mcpId: string; extensionSessionPub: string; sessionSig: string }>('ready')[0]!;

    // Each ready goes back on the link that asked, for the id that asked.
    expect(localReady.mcpId).toBe(onLocal.mcpId);
    expect(remoteReady.mcpId).toBe(onRemote.mcpId);

    // And verifies ONLY against its own link's nonce. This is the assertion
    // that fails if the nonce ever goes global again.
    const verify = (ready: typeof localReady, mcp: ScriptedMcp, extNonce: Uint8Array) =>
      ed25519Verify(
        state.extIdentity!.ed25519Pub,
        readySignaturePayload(mcp.sessionNonce, extNonce, fromB64(ready.extensionSessionPub)),
        fromB64(ready.sessionSig),
      );
    expect(await verify(localReady, onLocal, localNonce)).toBe(true);
    expect(await verify(remoteReady, onRemote, remoteNonce)).toBe(true);
    expect(await verify(remoteReady, onRemote, localNonce)).toBe(false);
  });

  it('refuses a second link claiming an mcpId the first already holds', async () => {
    const mcp = await scriptedMcp('alltrails-mcp:2.1.3:3333333333333333');
    await trustMcp(mcp);

    localWs.message(await helloFrom(mcp));
    await vi.waitUntil(() => localWs.frames('ready').length > 0);

    remoteWs.message(await helloFrom(mcp));
    await new Promise((r) => setTimeout(r, 20));

    // No answer to the impostor, and the binding did not move.
    expect(remoteWs.frames('ready')).toHaveLength(0);
    expect(linkForMcp(mcp.mcpId)?.kind).toBe('local');
  });

  it('answers a request on the link it arrived on, and nowhere else', async () => {
    const mcp = await scriptedMcp('alltrails-mcp:2.1.3:4444444444444444');
    await trustMcp(mcp);
    remoteWs.message(await helloFrom(mcp));
    await vi.waitUntil(() => remoteWs.frames('ready').length > 0);
    const ready = remoteWs.frames<{ extensionSessionPub: string }>('ready')[0]!;
    const key = await sessionKeyFor(mcp, ready);

    remoteWs.message(await sealInnerFrame(key, mcp.mcpId, 1, { type: 'ping' }));
    await vi.waitUntil(() => remoteWs.frames('frame').length > 0);

    const pong = remoteWs.frames<Parameters<typeof openEncryptedFrame>[1]>('frame')[0]!;
    expect((await openEncryptedFrame(key, pong)).type).toBe('pong');
    // The loopback link saw nothing of it.
    expect(localWs.frames('frame')).toHaveLength(0);
  });

  it('drops a frame whose mcpId belongs to the other link, before decrypting it', async () => {
    const mcp = await scriptedMcp('alltrails-mcp:2.1.3:5555555555555555');
    await trustMcp(mcp);
    localWs.message(await helloFrom(mcp));
    await vi.waitUntil(() => localWs.frames('ready').length > 0);
    const key = await sessionKeyFor(mcp, localWs.frames<{ extensionSessionPub: string }>('ready')[0]!);

    // A well-formed, correctly sealed ping — arriving on the wrong bridge.
    remoteWs.message(await sealInnerFrame(key, mcp.mcpId, 1, { type: 'ping' }));
    await new Promise((r) => setTimeout(r, 20));

    expect(remoteWs.frames('frame')).toHaveLength(0);
    expect(localWs.frames('frame')).toHaveLength(0);
  });

  it('tears down only the dropped link’s sessions', async () => {
    const onLocal = await scriptedMcp('alltrails-mcp:2.1.3:6666666666666666');
    const onRemote = await scriptedMcp('alltrails-mcp:2.1.3:7777777777777777');
    await trustMcp(onLocal);
    await trustMcp(onRemote);
    localWs.message(await helloFrom(onLocal));
    remoteWs.message(await helloFrom(onRemote));
    await vi.waitUntil(() => localWs.frames('ready').length > 0 && remoteWs.frames('ready').length > 0);

    remoteWs.remoteClose(1008, 'token revoked');

    expect(state.sessions!.get(onRemote.mcpId)).toBeNull();
    expect(linkForMcp(onRemote.mcpId)).toBeNull();
    expect(mcpDomains.has(onRemote.mcpId)).toBe(false);

    expect(state.sessions!.get(onLocal.mcpId)).not.toBeNull();
    expect(linkForMcp(onLocal.mcpId)?.kind).toBe('local');
    expect(mcpDomains.get(onLocal.mcpId)).toEqual(['alltrails.com']);
  });

  it('removing a target closes its link and takes its sessions with it', async () => {
    const onRemote = await scriptedMcp('alltrails-mcp:2.1.3:8888888888888888');
    await trustMcp(onRemote);
    remoteWs.message(await helloFrom(onRemote));
    await vi.waitUntil(() => remoteWs.frames('ready').length > 0);

    reconcileRemoteLinks([]);

    expect(links.has('remote:host1')).toBe(false);
    expect(state.sessions!.get(onRemote.mcpId)).toBeNull();
    expect(remoteWs.readyState).toBe(3);
  });

  it('re-dials a target whose URL changed as a new bridge', () => {
    reconcileRemoteLinks([{ ...REMOTE, url: 'wss://other.example/bridge' }]);
    const opened = FakeSocket.opened.filter((s) => s.url === 'wss://other.example/bridge');
    expect(opened).toHaveLength(1);
    expect(remoteWs.readyState).toBe(3);
  });

  it('re-dials a target whose credential rotated — the old socket is authenticated as something the user stopped meaning', () => {
    reconcileRemoteLinks([{ ...REMOTE, token: 'mcpb_rotated' }]);
    const opened = FakeSocket.opened.filter((s) => s.url === REMOTE.url);
    expect(opened).toHaveLength(2);
    expect(opened[1]!.protocols).toEqual(['fetchproxy.bridge.v1', 'fetchproxy.token.mcpb_rotated']);
    expect(remoteWs.readyState).toBe(3);
  });

  it('holds a failing remote link to its backoff even when the keepalive ticks', () => {
    remoteWs.remoteClose(1006);
    const before = FakeSocket.opened.length;
    // The MV3 keepalive fires every 24s regardless of any timer we set, so
    // without a deadline on the link this is where a dead bridge would be
    // re-dialled forever.
    connect();
    connect();
    expect(FakeSocket.opened).toHaveLength(before);
  });

  it('re-dials the loopback link promptly — its failure just means the MCP is not up yet', () => {
    vi.useFakeTimers({ now: Date.now() });
    try {
      localWs.remoteClose(1006);
      const before = FakeSocket.opened.length;
      // Loopback backs off 500 ms, a remote link 1 s and up. Half a second on
      // and the local bridge is dialable again while the remote one is not.
      vi.setSystemTime(Date.now() + 600);
      remoteWs.remoteClose(1006);
      connect();
      const opened = FakeSocket.opened.slice(before);
      expect(opened.map((s) => s.url)).toEqual(['ws://127.0.0.1:37149']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('never dials a disabled target', () => {
    reconcileRemoteLinks([{ ...REMOTE, enabled: false }]);
    expect(links.has('remote:host1')).toBe(false);
    expect(FakeSocket.opened.filter((s) => s.url === REMOTE.url)).toHaveLength(1);
  });
});

describe('a refused hello', () => {
  it('gives its binding back, so the id is not held until the link drops', async () => {
    FakeSocket.opened = [];
    unbindAll();
    links.clear();
    reconcileRemoteLinks([REMOTE]);
    const localWs = FakeSocket.opened.find((s) => s.url.startsWith('ws://127.0.0.1'))!;
    localWs.open();

    const mcp = await scriptedMcp('alltrails-mcp:2.1.3:9999999999999999');
    // Not trusted, and with a broken signature: `handleServerHello` rejects.
    const hello = await helloFrom(mcp);
    localWs.message({ ...hello, sessionSig: toB64(new Uint8Array(64)) });
    await new Promise((r) => setTimeout(r, 20));

    // Held until the link dropped, a rejected id would let a hello flood grow
    // the table without bound — and would block a legitimate re-hello of the
    // same id behind a rejection.
    expect(linkForMcp(mcp.mcpId)).toBeNull();
  });
});
