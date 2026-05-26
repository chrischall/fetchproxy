import { FetchproxyServer } from '../../src/index.js';
import type { InnerFrame, InnerRequest } from '@fetchproxy/protocol';

/**
 * Test harness that pretends `listen()` was called by installing a
 * minimal fake host handle on the FetchproxyServer instance, then
 * captures every inner request the server emits and lets the test
 * resolve the corresponding response by replying through `onInner`.
 */
export function installFakeHost(server: FetchproxyServer): {
  lastInner: () => InnerRequest | null;
  reply: (resp: InnerFrame) => void;
} {
  let lastInner: InnerRequest | null = null;
  const fakeHostHandle = {
    close: async () => undefined,
    sendOwnInner: async (inner: InnerFrame): Promise<void> => {
      if (inner.type === 'request') lastInner = inner;
    },
    onOwnInner: (_cb: (inner: InnerFrame) => void) => undefined,
    onExtensionDisconnect: (_cb: () => void) => undefined,
    // 0.5.2+: the fake never reports a pair-pending state — the tests
    // here are about post-handshake verb behavior, not the pairing UX.
    onPendingPair: (_cb: (code: string) => void) => undefined,
    pendingPairCode: (): string | null => null,
  };
  (server as unknown as { hostHandle: typeof fakeHostHandle }).hostHandle = fakeHostHandle;
  return {
    lastInner: () => lastInner,
    reply: (resp) => {
      (server as unknown as { onInner(i: InnerFrame): void }).onInner(resp);
    },
  };
}
