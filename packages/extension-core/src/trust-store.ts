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
  /**
   * Non-empty list of inner-verb capabilities the user approved at pair
   * time. Compared as a set; if the MCP later declares a different set
   * (e.g. adds `'read_cookies'`), trust is treated as missing and the
   * user is prompted again. Older records that lack this field are
   * normalised to `['fetch']` on read.
   */
  capabilities: string[];
  /**
   * 0.3.0+: declared cookie names the user approved for `read_cookies`.
   * Compared as a set; any change forces re-pair. Pre-0.3.0 records
   * carry `[]`, which means no key-scoped cookie reads are permitted
   * (the legacy `tabUrl` cookie path is still available since it has
   * its own coarser trust gate via the capability).
   */
  cookieKeys: string[];
  /** 0.3.0+: declared localStorage key set. */
  localStorageKeys: string[];
  /** 0.3.0+: declared sessionStorage key set. */
  sessionStorageKeys: string[];
  /** 0.3.0+: declared (urlPattern, headerName) pairs for capture_request_header. */
  captureHeaders: { urlPattern: string; headerName: string }[];
  identityX25519Pub: string;
  identityEd25519Pub: string;
  /**
   * 0.4.0+: the extension's long-term X25519 identity pub at pair
   * time, base64. Records missing this field are 0.3.0 leftovers and
   * are treated as missing on read (force re-pair).
   */
  extensionIdentityX25519Pub: string;
  /**
   * 0.4.0+: the extension's long-term Ed25519 identity pub at pair
   * time, base64. The MCP host uses this to verify the extension's
   * ready-frame session signature on subsequent connections.
   */
  extensionIdentityEd25519Pub: string;
  pairedAt: number;
  extensionVersionAtPair: string;
}

export interface TrustInput {
  serverName: string;
  domains: string[];
  capabilities: string[];
  /**
   * 0.3.0+ scope arrays. Optional only so tests and pre-0.3.0 callers
   * compile; production `background.ts:onApproval` always provides
   * the empty array when nothing is declared.
   */
  cookieKeys?: string[];
  localStorageKeys?: string[];
  sessionStorageKeys?: string[];
  captureHeaders?: { urlPattern: string; headerName: string }[];
  identityX25519Pub: string;
  identityEd25519Pub: string;
  /**
   * 0.4.0+: pinned extension identity. Optional so callers from
   * tests and 0.3.0-era code paths compile. Production code in
   * `background.ts:onApproval` always provides both values; absence
   * is normalised to '' on read, which then mismatches any real
   * extension pub and forces re-pair.
   */
  extensionIdentityX25519Pub?: string;
  extensionIdentityEd25519Pub?: string;
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
    // Pre-capability records (paired before 0.2.0 added the field) carry no
    // `capabilities` array. Normalise to ['fetch'] so the caller can compare
    // without checking for undefined; the user only approved fetch back
    // then, so anything more requires a re-pair.
    // Pre-0.3.0 records lack the scope arrays; normalise to `[]` on read
    // so callers can compare without undefined checks. A new hello that
    // declares non-empty scope will then fall out as a set mismatch and
    // trigger re-pair, which is the correct behavior.
    const normalised: TrustRecord = {
      ...rec,
      capabilities: Array.isArray(rec.capabilities) ? rec.capabilities : ['fetch'],
      cookieKeys: Array.isArray(rec.cookieKeys) ? rec.cookieKeys : [],
      localStorageKeys: Array.isArray(rec.localStorageKeys) ? rec.localStorageKeys : [],
      sessionStorageKeys: Array.isArray(rec.sessionStorageKeys) ? rec.sessionStorageKeys : [],
      captureHeaders: Array.isArray(rec.captureHeaders) ? rec.captureHeaders : [],
      // 0.4.0: pre-0.4.0 records have no extension identity. Normalise
      // to '' so `background.ts:handleServerHello` sees a mismatch
      // against the current extension's pub and triggers re-pair.
      extensionIdentityX25519Pub:
        typeof rec.extensionIdentityX25519Pub === 'string'
          ? rec.extensionIdentityX25519Pub
          : '',
      extensionIdentityEd25519Pub:
        typeof rec.extensionIdentityEd25519Pub === 'string'
          ? rec.extensionIdentityEd25519Pub
          : '',
    };
    return normalised;
  }

  async put(identityHash: string, input: TrustInput): Promise<void> {
    const stored = await this.load();
    // Fill defaults for any optional 0.4.0 fields so the stored
    // record matches the canonical shape on read.
    const cookieKeys = input.cookieKeys ?? [];
    const localStorageKeys = input.localStorageKeys ?? [];
    const sessionStorageKeys = input.sessionStorageKeys ?? [];
    const captureHeaders = input.captureHeaders ?? [];
    stored.records[identityHash] = {
      serverName: input.serverName,
      domains: input.domains,
      capabilities: input.capabilities,
      cookieKeys,
      localStorageKeys,
      sessionStorageKeys,
      captureHeaders,
      identityX25519Pub: input.identityX25519Pub,
      identityEd25519Pub: input.identityEd25519Pub,
      extensionIdentityX25519Pub: input.extensionIdentityX25519Pub ?? '',
      extensionIdentityEd25519Pub: input.extensionIdentityEd25519Pub ?? '',
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
