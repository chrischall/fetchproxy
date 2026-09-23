import { describe, it, expect, vi, beforeAll } from 'vitest';

/**
 * S-SEC-3 — approvals are only taken from a TRUSTED-context channel.
 *
 * `chrome.storage.local` is readable and writable by content scripts, which
 * this extension injects into every site. An `approvedPair` (or a forged
 * scope-update dismissal) appearing there must be ignored; the pending queue
 * and the popup's decisions travel through `chrome.storage.session`, which
 * is restricted to extension pages and the service worker by default.
 */

const onApproval = vi.fn(async () => {});
const onScopeUpdateDismiss = vi.fn(async () => {});
vi.mock('../src/background/approval.js', () => ({ onApproval, onScopeUpdateDismiss }));

type Listener = (changes: Record<string, { newValue?: unknown; oldValue?: unknown }>) => void;
const localListeners: Listener[] = [];
const sessionListeners: Listener[] = [];
const localData = new Map<string, unknown>([
  ['pendingPair', { stale: { key: 'stale' } }],
  ['approvedPair', { key: 'stale' }],
]);

function area(m: Map<string, unknown>, listeners: Listener[]) {
  return {
    get: async (k: string | string[]) => {
      const keys = Array.isArray(k) ? k : [k];
      const out: Record<string, unknown> = {};
      for (const key of keys) if (m.has(key)) out[key] = m.get(key);
      return out;
    },
    set: async (kv: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(kv)) m.set(k, v);
    },
    remove: async (k: string | string[]) => {
      for (const key of Array.isArray(k) ? k : [k]) m.delete(key);
    },
    onChanged: { addListener: (cb: Listener) => void listeners.push(cb) },
  };
}

class FakeSocket {
  readyState = 0;
  addEventListener(): void {}
  send(): void {}
  close(): void {}
}

beforeAll(async () => {
  vi.stubGlobal('WebSocket', FakeSocket);
  vi.stubGlobal('chrome', {
    runtime: { getManifest: () => ({ version: '3.1.0' }), onMessage: { addListener: () => {} } },
    storage: {
      local: area(localData, localListeners),
      session: area(new Map(), sessionListeners),
    },
    tabs: { query: async () => [] },
    action: {},
  });
  const { maybeBoot } = await import('../src/background/boot.js');
  maybeBoot();
  await new Promise((r) => setTimeout(r, 10));
});

const RECORD = { key: 'id:scope', kind: 'pair', identityHash: 'id' };

describe('approval channel (S-SEC-3)', () => {
  it('ignores an approvedPair written to chrome.storage.local', () => {
    for (const l of localListeners) l({ approvedPair: { newValue: RECORD } });
    expect(onApproval).not.toHaveBeenCalled();
  });

  it('ignores a scope-update dismissal written to chrome.storage.local', () => {
    for (const l of localListeners) {
      l({ dismissedScopeUpdate: { newValue: { key: 'k', identityHash: 'id', scopeHash: 's' } } });
    }
    expect(onScopeUpdateDismiss).not.toHaveBeenCalled();
  });

  it('acts on an approvedPair written to chrome.storage.session', () => {
    for (const l of sessionListeners) l({ approvedPair: { newValue: RECORD } });
    expect(onApproval).toHaveBeenCalledWith(RECORD);
  });

  it('drops the legacy pending queue left in chrome.storage.local', () => {
    expect(localData.has('pendingPair')).toBe(false);
    expect(localData.has('approvedPair')).toBe(false);
  });
});
