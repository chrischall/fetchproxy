import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest';

/**
 * The popup tells the service worker its remote bridge targets changed with a
 * `remote-targets-changed` runtime message, and the worker reconciles its
 * links by re-reading the vault.
 *
 * `chrome.runtime.onMessage` is reachable from content scripts too, which this
 * extension injects into every site. The handler therefore acts only on a
 * message with no `sender.tab` — i.e. one from an extension page such as the
 * popup — so a page cannot drive the bridge reconcile.
 */

const loadRemoteLinks = vi.fn(async () => {});
vi.mock('../src/background/socket.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../src/background/socket.js')>()),
  connect: vi.fn(),
  loadRemoteLinks,
}));

type MessageListener = (
  msg: unknown,
  sender: { tab?: unknown; id?: string } | undefined,
  sendResponse: (r: unknown) => void,
) => unknown;
const messageListeners: MessageListener[] = [];

function area() {
  const m = new Map<string, unknown>();
  return {
    get: async (k: string | string[]) => {
      const out: Record<string, unknown> = {};
      for (const key of Array.isArray(k) ? k : [k]) if (m.has(key)) out[key] = m.get(key);
      return out;
    },
    set: async (kv: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(kv)) m.set(k, v);
    },
    remove: async (k: string | string[]) => {
      for (const key of Array.isArray(k) ? k : [k]) m.delete(key);
    },
    onChanged: { addListener: () => {} },
  };
}

function dispatch(msg: unknown, sender: { tab?: unknown; id?: string } | undefined): void {
  for (const l of messageListeners) l(msg, sender, () => {});
}

beforeAll(async () => {
  vi.stubGlobal('chrome', {
    runtime: {
      getManifest: () => ({ version: '3.1.0' }),
      onMessage: { addListener: (cb: MessageListener) => void messageListeners.push(cb) },
    },
    storage: { local: area(), session: area() },
    tabs: { query: async () => [] },
    action: {},
  });
  const { maybeBoot } = await import('../src/background/boot.js');
  maybeBoot();
  await new Promise((r) => setTimeout(r, 10));
  expect(messageListeners).toHaveLength(1);
});

beforeEach(() => {
  loadRemoteLinks.mockClear();
});

describe('remote-targets-changed message', () => {
  it('reconciles the remote links when the popup (no sender.tab) sends it', () => {
    dispatch({ type: 'remote-targets-changed' }, { id: 'ext-id' });
    expect(loadRemoteLinks).toHaveBeenCalledTimes(1);
  });

  it('ignores the same message from a content script (sender.tab set)', () => {
    dispatch({ type: 'remote-targets-changed' }, { id: 'ext-id', tab: { id: 7, url: 'https://evil.example/' } });
    expect(loadRemoteLinks).not.toHaveBeenCalled();
  });

  it('ignores unrelated messages', () => {
    dispatch({ type: 'something-else' }, { id: 'ext-id' });
    dispatch(null, { id: 'ext-id' });
    expect(loadRemoteLinks).not.toHaveBeenCalled();
  });
});
