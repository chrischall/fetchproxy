/**
 * Long-term identity keypair for the fetchproxy browser extension.
 *
 * 0.4.0+ mutual-auth design: the MCP verifies the `ready` frame's
 * `sessionSig` against the Ed25519 pub in this identity, so a
 * fake-extension process dialing the WS port can't forge a matching
 * signature and the MCP tears the WS down before any inner traffic flows.
 *
 * This docblock used to say the MCP "stores" those pubs and checks each
 * connection against the stored ones. It didn't — until 1.12.0 (#208) the
 * check was against the identity presented in the same connection, which is
 * freshness, not continuity. It stores them now, which is what makes this
 * identity's PERSISTENCE load-bearing rather than incidental: a re-install
 * mints a new one, and every MCP will refuse it until the user re-pairs
 * deliberately.
 *
 * Persisted in `chrome.storage.local` under `extensionIdentity`. Same
 * shape as MCP identity (raw 32-byte priv + pub for each algorithm,
 * base64-encoded on disk).
 *
 * Generated lazily on first read. Survives extension restarts because
 * MV3 service-worker state is wiped on every restart, but
 * chrome.storage.local persists.
 */

import { generateX25519, generateEd25519, toB64, fromB64 } from '@fetchproxy/protocol';

declare const chrome: {
  storage: {
    local: {
      get: (k: string) => Promise<Record<string, unknown>>;
      set: (kv: Record<string, unknown>) => Promise<void>;
    };
  };
};

const STORAGE_KEY = 'extensionIdentity';

export interface ExtensionIdentity {
  x25519Priv: Uint8Array;
  x25519Pub: Uint8Array;
  ed25519Priv: Uint8Array;
  ed25519Pub: Uint8Array;
  createdAt: number;
}

interface StoredShape {
  x25519Priv: string;
  x25519Pub: string;
  ed25519Priv: string;
  ed25519Pub: string;
  createdAt: number;
}

function isStored(x: unknown): x is StoredShape {
  if (!x || typeof x !== 'object') return false;
  const r = x as Record<string, unknown>;
  return (
    typeof r.x25519Priv === 'string' &&
    typeof r.x25519Pub === 'string' &&
    typeof r.ed25519Priv === 'string' &&
    typeof r.ed25519Pub === 'string' &&
    typeof r.createdAt === 'number'
  );
}

/**
 * Read the persisted extension identity from `chrome.storage.local`,
 * generating + persisting a fresh keypair on the first call. Subsequent
 * calls return the same identity bytes.
 *
 * The keys are stored base64-encoded; decoded back to `Uint8Array` here
 * so the rest of the extension's crypto code doesn't have to know about
 * the disk format.
 */
export async function loadOrCreateExtensionIdentity(): Promise<ExtensionIdentity> {
  const got = await chrome.storage.local.get(STORAGE_KEY);
  const raw = got[STORAGE_KEY];
  if (isStored(raw)) {
    return {
      x25519Priv: fromB64(raw.x25519Priv),
      x25519Pub: fromB64(raw.x25519Pub),
      ed25519Priv: fromB64(raw.ed25519Priv),
      ed25519Pub: fromB64(raw.ed25519Pub),
      createdAt: raw.createdAt,
    };
  }
  const x = await generateX25519();
  const ed = await generateEd25519();
  const id: ExtensionIdentity = {
    x25519Priv: x.privateKey,
    x25519Pub: x.publicKey,
    ed25519Priv: ed.privateKey,
    ed25519Pub: ed.publicKey,
    createdAt: Date.now(),
  };
  const stored: StoredShape = {
    x25519Priv: toB64(id.x25519Priv),
    x25519Pub: toB64(id.x25519Pub),
    ed25519Priv: toB64(id.ed25519Priv),
    ed25519Pub: toB64(id.ed25519Pub),
    createdAt: id.createdAt,
  };
  await chrome.storage.local.set({ [STORAGE_KEY]: stored });
  return id;
}
