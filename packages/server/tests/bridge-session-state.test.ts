import { describe, it, expect } from 'vitest';
import {
  FetchproxyServer,
  FetchproxySessionNotReadyError,
  classifyBridgeError,
} from '../src/index.js';
import type { InnerFrame } from '@fetchproxy/protocol';

/**
 * 2.5.0: `bridgeHealth().session` names the leg of the extension link
 * that is missing. Before it, a healthcheck could say "the extension
 * last spoke at …" but not WHY it was silent — a port nobody dialled,
 * an extension that never attached, a pair code waiting in the popup,
 * or an attached extension that simply never answered the hello all
 * looked the same from outside (hemnet-mcp, 2026-09-02: a 30 s
 * "no confirmed browser session" with the browser attached).
 */
const baseOpts = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
};

interface FakeHandle {
  extensionConnected: boolean;
  sessionLinked: boolean;
  pairCode: string | null;
}

/** Install a minimal host handle reporting the given link state. */
function installHandle(server: FetchproxyServer, fake: FakeHandle): void {
  const handle = {
    close: async () => undefined,
    sendOwnInner: async (_inner: InnerFrame): Promise<void> => undefined,
    onOwnInner: () => undefined,
    onExtensionDisconnect: () => undefined,
    onPendingPair: () => undefined,
    pendingPairCode: () => fake.pairCode,
    extensionConnected: () => fake.extensionConnected,
    sessionLinked: () => fake.sessionLinked,
  };
  (server as unknown as { hostHandle: typeof handle }).hostHandle = handle;
  (server as unknown as { role: 'host' | 'peer' | null }).role = 'host';
}

describe('bridgeHealth().session', () => {
  it('is not_listening before listen()', () => {
    const s = new FetchproxyServer(baseOpts);
    expect(s.bridgeHealth().session).toEqual({
      state: 'not_listening',
      pairCode: null,
      extensionConnected: false,
    });
  });

  it('is extension_disconnected when the port is bound but no extension is attached', () => {
    const s = new FetchproxyServer(baseOpts);
    installHandle(s, { extensionConnected: false, sessionLinked: false, pairCode: null });
    expect(s.bridgeHealth().session).toEqual({
      state: 'extension_disconnected',
      pairCode: null,
      extensionConnected: false,
    });
  });

  it('is no_session when the extension is attached but never answered the hello', () => {
    // The hemnet-mcp shape: browser attached, 30 s session-ready timeout,
    // no ready and no pair-pending — the hello was dropped somewhere.
    const s = new FetchproxyServer(baseOpts);
    installHandle(s, { extensionConnected: true, sessionLinked: false, pairCode: null });
    expect(s.bridgeHealth().session).toEqual({
      state: 'no_session',
      pairCode: null,
      extensionConnected: true,
    });
  });

  it('is pair_pending, with the code, while the user has yet to approve', () => {
    const s = new FetchproxyServer(baseOpts);
    installHandle(s, { extensionConnected: true, sessionLinked: false, pairCode: '457-035' });
    expect(s.bridgeHealth().session).toEqual({
      state: 'pair_pending',
      pairCode: '457-035',
      extensionConnected: true,
    });
  });

  it('is pair_pending even when a peer cannot see the extension directly — the code proves it is there', () => {
    const s = new FetchproxyServer(baseOpts);
    installHandle(s, { extensionConnected: false, sessionLinked: false, pairCode: '457-035' });
    expect(s.bridgeHealth().session.state).toBe('pair_pending');
  });

  it('is linked once a session key exists', () => {
    const s = new FetchproxyServer(baseOpts);
    installHandle(s, { extensionConnected: true, sessionLinked: true, pairCode: null });
    expect(s.bridgeHealth().session).toEqual({
      state: 'linked',
      pairCode: null,
      extensionConnected: true,
    });
  });
});

describe('runProbe() session projection', () => {
  it('carries the session state, pair code, extension liveness and last message time', async () => {
    const s = new FetchproxyServer(baseOpts);
    installHandle(s, { extensionConnected: true, sessionLinked: false, pairCode: '457-035' });
    const result = await s.runProbe(async () => {
      throw new FetchproxySessionNotReadyError({ mcpId: 'test-mcp:0.0.1:abc', pairCode: '457-035' });
    }, '/robots.txt');
    expect(result.ok).toBe(false);
    expect(result.error?.kind).toBe('session_not_ready');
    expect(result.bridge).toMatchObject({
      session_state: 'pair_pending',
      pending_pair_code: '457-035',
      extension_connected: true,
      last_extension_message_at: null,
    });
  });
});

describe('classifyBridgeError() and session readiness', () => {
  it('classifies FetchproxySessionNotReadyError as session_not_ready, pairing or not', () => {
    expect(
      classifyBridgeError(new FetchproxySessionNotReadyError({ mcpId: 'x', pairCode: null })),
    ).toBe('session_not_ready');
    expect(
      classifyBridgeError(new FetchproxySessionNotReadyError({ mcpId: 'x', pairCode: '123-456' })),
    ).toBe('session_not_ready');
  });
});
