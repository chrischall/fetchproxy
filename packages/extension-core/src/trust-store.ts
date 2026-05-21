/**
 * Persistent record of MCP servers the user has trusted, keyed by the
 * SHA-256 hash of the MCP's long-term X25519 identity public key.
 *
 * Trust is identity-bound, not port-bound — same MCP across restarts,
 * port changes, or identity-key re-issuance is the same trust record.
 *
 * Storage: chrome.storage.local key "trustedMcps".
 * Major-version invalidation: if the extension's major version changed
 * since the pair was approved, the record is treated as missing
 * (forces re-pair). Patch/minor bumps carry trust forward.
 */
declare const chrome: {
  storage: {
    local: {
      get: (k: string) => Promise<Record<string, unknown>>;
      set: (kv: Record<string, unknown>) => Promise<void>;
      remove: (k: string) => Promise<void>;
    };
  };
};

const STORAGE_KEY = 'trustedMcps';

export interface TrustRecord {
  serverName: string;
  /**
   * Non-empty array of hostnames the user approved this MCP to reach
   * at pair time. The extension's per-request allowlist check passes
   * any URL whose host matches (exactly or as a subdomain) any entry.
   */
  domains: string[];
  identityX25519Pub: string;
  identityEd25519Pub: string;
  pairedAt: number;
  extensionVersionAtPair: string;
}

export interface TrustInput {
  serverName: string;
  domains: string[];
  identityX25519Pub: string;
  identityEd25519Pub: string;
}

interface StoredShape {
  records: Record<string, TrustRecord>;
}

function majorOf(v: string): number {
  const head = v.split('.')[0];
  if (!head) return NaN;
  const n = Number(head);
  return Number.isFinite(n) ? n : NaN;
}

export class TrustStore {
  constructor(private extensionVersion: string) {}

  async get(identityHash: string): Promise<TrustRecord | null> {
    const stored = await this.load();
    const rec = stored.records[identityHash];
    if (!rec) return null;
    if (majorOf(rec.extensionVersionAtPair) !== majorOf(this.extensionVersion)) {
      return null;
    }
    return rec;
  }

  async put(identityHash: string, input: TrustInput): Promise<void> {
    const stored = await this.load();
    stored.records[identityHash] = {
      ...input,
      pairedAt: Date.now(),
      extensionVersionAtPair: this.extensionVersion,
    };
    await chrome.storage.local.set({ [STORAGE_KEY]: stored });
  }

  async remove(identityHash: string): Promise<void> {
    const stored = await this.load();
    delete stored.records[identityHash];
    await chrome.storage.local.set({ [STORAGE_KEY]: stored });
  }

  async list(): Promise<Record<string, TrustRecord>> {
    const stored = await this.load();
    return { ...stored.records };
  }

  private async load(): Promise<StoredShape> {
    const got = await chrome.storage.local.get(STORAGE_KEY);
    const raw = got[STORAGE_KEY] as StoredShape | undefined;
    return raw && raw.records ? raw : { records: {} };
  }
}
