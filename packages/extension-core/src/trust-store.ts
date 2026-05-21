/**
 * Persistent record of MCP servers the user has trusted. Keyed on
 * (port, server, domain). Major-version changes invalidate the
 * approval (T8 in the threat model — surface re-prompts on
 * meaningful identity drift); patch/minor changes carry the approval
 * forward to avoid prompt fatigue.
 *
 * Storage area is chrome.storage.local for production; tests inject
 * an in-memory mock.
 */

export type Approval = 'always' | 'once';

export interface McpIdentity {
  port: number;
  server: string;
  version: string;
  domain: string;
}

export interface TrustedMcp extends McpIdentity {
  approval: Approval;
  approved_at: number; // unix ms
}

const KEY_PREFIX = 'trustedMcp:';

function key(id: { port: number; server: string; domain: string }): string {
  return `${KEY_PREFIX}${id.port}|${id.server}|${id.domain}`;
}

/** Extract major version. `"0.9.1"` → `0`; `"1.2.3"` → `1`. Returns
 *  empty string if not parseable so we always re-prompt on garbage. */
function major(version: string): string {
  const m = version.match(/^(\d+)\./);
  return m?.[1] ?? '';
}

export class TrustStore {
  constructor(private readonly storage: chrome.storage.StorageArea) {}

  async lookup(id: McpIdentity): Promise<TrustedMcp | null> {
    const k = key(id);
    const got = await this.storage.get(k);
    const entry = got[k] as TrustedMcp | undefined;
    if (!entry) return null;
    // Major-version change invalidates the approval.
    if (major(entry.version) !== major(id.version)) return null;
    return entry;
  }

  async approve(id: McpIdentity, approval: Approval): Promise<void> {
    const k = key(id);
    const entry: TrustedMcp = {
      ...id,
      approval,
      approved_at: Date.now(),
    };
    await this.storage.set({ [k]: entry });
  }

  async revoke(id: { port: number; server: string; domain: string }): Promise<void> {
    await this.storage.remove(key(id));
  }

  async list(): Promise<TrustedMcp[]> {
    const all = await this.storage.get();
    const out: TrustedMcp[] = [];
    for (const [k, v] of Object.entries(all)) {
      if (k.startsWith(KEY_PREFIX)) out.push(v as TrustedMcp);
    }
    return out;
  }
}
