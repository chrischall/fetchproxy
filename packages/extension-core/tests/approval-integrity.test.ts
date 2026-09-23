import { describe, it, expect, beforeEach, vi } from 'vitest';
import { generateEd25519, generateX25519 } from '@fetchproxy/protocol';

/**
 * S-SEC-3 — an approval is only honoured for a pending record the BACKGROUND
 * wrote. `approvedPair` and `pendingPair` live in `chrome.storage.local`,
 * which content scripts (injected into every site) can write, so a renderer
 * compromise on any site could otherwise approve an identity of its choosing
 * with any domains and capabilities, with no popup interaction. The
 * background keeps its own copy of each pending record in
 * `chrome.storage.session` (trusted contexts only), and `onApproval` refuses
 * a record that has no such copy or that differs from it in anything the
 * user approved.
 */

const local = new Map<string, unknown>();
const session = new Map<string, unknown>();
function area(m: Map<string, unknown>) {
  return {
    get: async (k: string | string[]) => {
      const keys = Array.isArray(k) ? k : [k];
      const out: Record<string, unknown> = {};
      for (const key of keys) if (m.has(key)) out[key] = structuredClone(m.get(key));
      return out;
    },
    set: async (kv: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(kv)) m.set(k, structuredClone(v));
    },
    remove: async (k: string) => void m.delete(k),
  };
}
vi.stubGlobal('chrome', {
  runtime: { getManifest: () => ({ version: '3.1.0' }), sendMessage: () => {} },
  storage: { local: area(local), session: area(session) },
  tabs: { query: async () => [], create: async () => ({ id: 1 }) },
});

const { onApproval } = await import('../src/background/approval.js');
const { recordPendingAuthoritative, AUTHORITATIVE_PENDING_KEY } =
  await import('../src/background/pending-integrity.js');
const { state } = await import('../src/background/state.js');
const { TrustStore } = await import('../src/trust-store.js');
const { SessionKeys } = await import('../src/session-keys.js');
type AnyPendingRecord = import('../src/background/pending-records.js').AnyPendingRecord;

const IDENTITY = 'a'.repeat(64);

function record(over: Partial<Record<string, unknown>> = {}): AnyPendingRecord {
  return {
    key: `${IDENTITY}:scope`,
    kind: 'pair',
    identityHash: IDENTITY,
    serverName: 'alltrails-mcp',
    version: '2.1.3',
    mcpIds: ['alltrails-mcp:2.1.3:eeeeeeeeeeeeeeee'],
    sessionNonces: {},
    sessionPubs: {},
    domains: ['alltrails.com'],
    capabilities: ['fetch'],
    cookieKeys: [],
    localStorageKeys: [],
    sessionStorageKeys: [],
    captureHeaders: [],
    indexedDbScopes: [],
    domSelectors: [],
    domListSelectors: [],
    graphqlOps: [],
    localStoragePointers: [],
    sessionStoragePointers: [],
    pairCode: '1234-5678',
    identityX25519Pub: 'eA==',
    identityEd25519Pub: 'ZQ==',
    ...over,
  } as unknown as AnyPendingRecord;
}

beforeEach(async () => {
  local.clear();
  session.clear();
  state.trust = new TrustStore('3.1.0');
  state.sessions = new SessionKeys();
  const x = await generateX25519();
  const ed = await generateEd25519();
  state.extIdentity = {
    x25519Pub: x.publicKey,
    x25519Priv: x.privateKey,
    ed25519Pub: ed.publicKey,
    ed25519Priv: ed.privateKey,
  };
});

describe('onApproval only honours background-written pending records (S-SEC-3)', () => {
  it('refuses an approval with no background-written pending record', async () => {
    await onApproval(record());
    expect(await state.trust!.get(IDENTITY)).toBeNull();
  });

  it('refuses an approval whose scope differs from what the background queued', async () => {
    await recordPendingAuthoritative((dict) => {
      dict[record().key] = record();
    });
    await onApproval(
      record({
        domains: ['alltrails.com', 'bank.example'],
        capabilities: ['fetch', 'read_cookies'],
      }),
    );
    expect(await state.trust!.get(IDENTITY)).toBeNull();
  });

  it('refuses an approval that swaps the identity keys', async () => {
    await recordPendingAuthoritative((dict) => {
      dict[record().key] = record();
    });
    await onApproval(record({ identityEd25519Pub: 'ZXZpbA==' }));
    expect(await state.trust!.get(IDENTITY)).toBeNull();
  });

  it('honours an approval matching the background-written record and drops the copy', async () => {
    await recordPendingAuthoritative((dict) => {
      dict[record().key] = record();
    });
    await onApproval(record());
    const trusted = await state.trust!.get(IDENTITY);
    expect(trusted).not.toBeNull();
    expect(trusted!.domains).toEqual(['alltrails.com']);
    const mirror = (session.get(AUTHORITATIVE_PENDING_KEY) ?? {}) as Record<string, unknown>;
    expect(record().key in mirror).toBe(false);
  });
});
