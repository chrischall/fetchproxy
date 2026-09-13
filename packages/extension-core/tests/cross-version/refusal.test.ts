import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  ed25519Sign,
  ed25519Verify,
  generateEd25519,
  generateX25519,
  helloSignaturePayload,
  readySignaturePayload,
  sha256,
  toB64,
  fromB64,
  toHex,
  PROTOCOL_VERSION,
  type RawKeyPair,
} from '@fetchproxy/protocol';
import { v3ServerHello } from '../../../server/tests/cross-version/v3-fixtures.js';

/**
 * Case 2 of the plan's Group 5: a v3 MCP meeting a v4 extension, held to the
 * FROZEN corpus.
 *
 * The corpus lives in the server package
 * (`packages/server/tests/cross-version/v3-fixtures.ts`) and is imported here
 * rather than copied, because two frozen corpora are two things to let drift
 * and the whole point of the freeze is that both ends of the bridge are
 * refusing the same bytes. That module imports nothing, so pulling it across a
 * package boundary drags no version of anything with it — which is the same
 * property its own suite asserts on its source.
 *
 * Why the case is here and not beside cases 1, 3 and 4: the harness is the
 * extension's service worker — a fake `WebSocket`, a stubbed `chrome.*`, and
 * `background/socket.ts`'s module-level link table. Driving that from the
 * server package's tests would mean a published workspace's test suite
 * reaching into a private one's source. The suites are two files; the corpus
 * is one.
 *
 * Task 4.1 already pins this refusal, against a `v3Hello()` helper written on
 * this branch. That is the right test for the branch and not the one Group 5
 * asks for: a hand-built "old version" moves whenever the new one does, so it
 * cannot fail over a break it was rewritten alongside. These bytes were
 * captured from the published 2.11.3 and cannot be rewritten at all.
 */

// ---------------------------------------------------------------------------
// The service worker's world: a socket that goes nowhere and a stub chrome.
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

  /** Frames this socket sent, parsed, of one `type`. */
  frames<T = Record<string, unknown>>(type: string): T[] {
    return this.sent
      .map((s) => JSON.parse(s) as T)
      .filter((f) => (f as { type: string }).type === type);
  }
}

const storage = new Map<string, unknown>();

vi.stubGlobal('WebSocket', FakeSocket);
vi.stubGlobal('chrome', {
  runtime: {
    getManifest: () => ({ version: '3.0.0' }),
    sendMessage: () => {},
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

// Imported after the globals exist — `badge.ts` and the trust store read
// `chrome` on the way in.
const { connect } = await import('../../src/background/socket.js');
const { state } = await import('../../src/background/state.js');
const { links, linkForMcp, unbindAll } = await import('../../src/background/links.js');
const { TrustStore } = await import('../../src/trust-store.js');
const { SessionKeys } = await import('../../src/session-keys.js');
const { mcpDomains, mcpCapabilities } = await import('../../src/background/session-scope.js');

describe('cross-version: the frozen v3 MCP meets a v4 extension', () => {
  let ws: FakeSocket;

  beforeEach(async () => {
    FakeSocket.opened = [];
    storage.clear();
    unbindAll();
    links.clear();
    mcpDomains.clear();
    mcpCapabilities.clear();
    state.trust = new TrustStore('3.0.0');
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
    ws = FakeSocket.opened.find((s) => s.url.startsWith('ws://127.0.0.1'))!;
    ws.open();
  });

  // -------------------------------------------------------------------------
  // Case 2 — the frozen v3 server hello.
  // -------------------------------------------------------------------------

  it('answers exactly one hello-rejected, naming both versions, and grants nothing doing it', async () => {
    // The trust store is the observable proof that this is a REFUSAL and not a
    // handshake with a complaint attached: `handleServerHello` is its only
    // reader, and nothing on this path may reach it.
    const trustRead = vi.spyOn(state.trust!, 'get');
    const trustWrite = vi.spyOn(state.trust!, 'put');

    ws.message(v3ServerHello);
    // No timer stands between the hello and the answer, so this settles on the
    // first turn the refusal takes — the assertion is that it settles at all.
    await vi.waitFor(() =>
      expect(ws.frames('hello-rejected').length).toBeGreaterThanOrEqual(1),
    );

    const rejected = ws.frames<{ mcpId: string; reason: string }>('hello-rejected');
    // Exactly one: a refusal that answers twice is a send amplifier for
    // anything that can put a frame on the socket.
    expect(rejected).toHaveLength(1);
    expect(rejected[0]!.mcpId).toBe(v3ServerHello.mcpId);
    // Both numbers and the remedy. A refusal naming one version tells the
    // reader nothing they can act on, and the remedy is on the MCP's side.
    expect(rejected[0]!.reason).toBe(
      'protocol version mismatch: this browser extension speaks fetchproxy protocol 4, ' +
        'this MCP speaks 3 — upgrade @fetchproxy/server to >= 3.0.0',
    );
    expect(rejected[0]!.reason).toContain(String(PROTOCOL_VERSION));
    expect(rejected[0]!.reason).toContain(String(v3ServerHello.protocolVersion));

    // No session, no binding, no pair prompt, no trust record touched.
    expect(ws.frames('ready')).toHaveLength(0);
    expect(ws.frames('pair-pending')).toHaveLength(0);
    expect(linkForMcp(v3ServerHello.mcpId)).toBeNull();
    expect(state.sessions!.get(v3ServerHello.mcpId)).toBeNull();
    expect(trustRead).not.toHaveBeenCalled();
    expect(trustWrite).not.toHaveBeenCalled();

    trustRead.mockRestore();
    trustWrite.mockRestore();
  });

  // -------------------------------------------------------------------------
  // Case 3's half of the control. Without it, the case above proves only that
  // this rig cannot handshake with anything.
  // -------------------------------------------------------------------------

  it('and the same rig completes a v4 handshake — so the refusal is about the version', async () => {
    const mcp = {
      mcpId: 'opentable-mcp:3.0.0:abc1234567890def',
      x: (await generateX25519()) as RawKeyPair,
      ed: (await generateEd25519()) as RawKeyPair,
      session: (await generateX25519()) as RawKeyPair,
      sessionNonce: crypto.getRandomValues(new Uint8Array(32)),
    };
    // Pre-trusted, so the hello auto-trusts instead of queueing a pair prompt.
    await state.trust!.put(toHex(await sha256(mcp.x.publicKey)), {
      serverName: 'opentable-mcp',
      domains: ['opentable.com'],
      capabilities: ['fetch'],
      identityX25519Pub: toB64(mcp.x.publicKey),
      identityEd25519Pub: toB64(mcp.ed.publicKey),
      extensionIdentityX25519Pub: toB64(state.extIdentity!.x25519Pub),
      extensionIdentityEd25519Pub: toB64(state.extIdentity!.ed25519Pub),
    });

    const extNonce = fromB64(ws.frames<{ sessionNonce: string }>('hello')[0]!.sessionNonce);
    ws.message({
      type: 'hello',
      role: 'server',
      protocolVersion: PROTOCOL_VERSION,
      mcpId: mcp.mcpId,
      serverName: 'opentable-mcp',
      version: '3.0.0',
      domains: ['opentable.com'],
      capabilities: ['fetch'],
      identityX25519Pub: toB64(mcp.x.publicKey),
      identityEd25519Pub: toB64(mcp.ed.publicKey),
      sessionNonce: toB64(mcp.sessionNonce),
      sessionPub: toB64(mcp.session.publicKey),
      answersExtNonce: toB64(extNonce),
      sessionSig: toB64(
        await ed25519Sign(
          mcp.ed.privateKey,
          helloSignaturePayload(mcp.mcpId, mcp.sessionNonce, mcp.session.publicKey, extNonce),
        ),
      ),
    });

    await vi.waitFor(() => expect(ws.frames('ready')).toHaveLength(1));
    const ready = ws.frames<{
      mcpId: string;
      extensionSessionPub: string;
      mcpSessionPub: string;
      sessionSig: string;
    }>('ready')[0]!;
    expect(ready.mcpId).toBe(mcp.mcpId);
    // The ready is genuine v4: it echoes the MCP's ephemeral and signs all
    // four fields under the extension's own identity.
    expect(ready.mcpSessionPub).toBe(toB64(mcp.session.publicKey));
    expect(
      await ed25519Verify(
        state.extIdentity!.ed25519Pub,
        readySignaturePayload(
          mcp.sessionNonce,
          extNonce,
          fromB64(ready.extensionSessionPub),
          mcp.session.publicKey,
        ),
        fromB64(ready.sessionSig),
      ),
    ).toBe(true);
    expect(ws.frames('hello-rejected')).toHaveLength(0);
    expect(state.sessions!.get(mcp.mcpId)).not.toBeNull();
  });
});
