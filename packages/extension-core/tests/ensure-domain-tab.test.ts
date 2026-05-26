import { describe, it, expect, beforeEach } from 'vitest';
import { ensureDomainTab } from '../src/ensure-domain-tab.js';

interface FakeTab {
  id: number;
  url: string;
}

function mockTabs(initial: FakeTab[]): { tabs: FakeTab[]; created: FakeTab[] } {
  let nextId = 1000;
  const tabs: FakeTab[] = [...initial];
  const created: FakeTab[] = [];
  (globalThis as { chrome?: unknown }).chrome = {
    tabs: {
      query: async (q: { url?: string | string[] }) => {
        if (!q.url) return [...tabs];
        const patterns = Array.isArray(q.url) ? q.url : [q.url];
        return tabs.filter((t) =>
          patterns.some((p) => {
            // Translate `*://host/*` patterns to a hostname/subdomain match.
            const host = p.replace(/^\*:\/\//, '').replace(/\/\*$/, '').toLowerCase();
            try {
              const u = new URL(t.url);
              const h = u.hostname.toLowerCase();
              // host pattern can be "opentable.com" or "*.opentable.com"
              if (host.startsWith('*.')) {
                const bare = host.slice(2);
                return h === bare || h.endsWith('.' + bare);
              }
              return h === host || h.endsWith('.' + host);
            } catch {
              return false;
            }
          }),
        );
      },
      create: async (props: { url: string }) => {
        const tab: FakeTab = { id: nextId++, url: props.url };
        created.push(tab);
        tabs.push(tab);
        return tab;
      },
    },
  };
  return { tabs, created };
}

describe('ensureDomainTab', () => {
  it('does nothing when a matching tab already exists', async () => {
    const { created } = mockTabs([{ id: 1, url: 'https://www.opentable.com/somewhere' }]);
    const result = await ensureDomainTab('opentable.com');
    expect(result.opened).toBe(false);
    expect(created).toEqual([]);
  });

  it('opens a new tab when no tab matches', async () => {
    const { created } = mockTabs([{ id: 1, url: 'https://example.com/' }]);
    const result = await ensureDomainTab('opentable.com');
    expect(result.opened).toBe(true);
    expect(created).toHaveLength(1);
    expect(created[0]!.url).toBe('https://opentable.com/');
  });

  it('matches subdomains (www.opentable.com counts for opentable.com)', async () => {
    const { created } = mockTabs([{ id: 1, url: 'https://www.opentable.com/users' }]);
    const result = await ensureDomainTab('opentable.com');
    expect(result.opened).toBe(false);
    expect(created).toEqual([]);
  });

  it('matches root domain exactly', async () => {
    const { created } = mockTabs([{ id: 1, url: 'https://opentable.com/' }]);
    const result = await ensureDomainTab('opentable.com');
    expect(result.opened).toBe(false);
    expect(created).toEqual([]);
  });

  it('refuses to open if the domain is not a valid hostname', async () => {
    mockTabs([]);
    await expect(ensureDomainTab('not a domain')).rejects.toThrow();
    await expect(ensureDomainTab('')).rejects.toThrow();
    await expect(ensureDomainTab('opentable.com/path')).rejects.toThrow();
    await expect(ensureDomainTab('javascript:alert(1)')).rejects.toThrow();
  });

  it('accepts a multi-segment domain like co.uk', async () => {
    const { created } = mockTabs([]);
    const result = await ensureDomainTab('example.co.uk');
    expect(result.opened).toBe(true);
    expect(created[0]!.url).toBe('https://example.co.uk/');
  });

  it('opens tabs for all declared domains (multi-domain MCP pattern)', async () => {
    const { created } = mockTabs([]);
    const domains = ['honeybook.com', 'hbportal.co'];
    const results = await Promise.all(domains.map((d) => ensureDomainTab(d)));
    expect(results.every((r) => r.opened)).toBe(true);
    expect(created).toHaveLength(2);
    expect(created.map((t) => t.url)).toEqual([
      'https://honeybook.com/',
      'https://hbportal.co/',
    ]);
  });

  it('skips domains that already have a tab open (idempotent loop)', async () => {
    const { created } = mockTabs([
      { id: 1, url: 'https://vendor.hbportal.co/dashboard' },
    ]);
    const domains = ['honeybook.com', 'hbportal.co'];
    const results = await Promise.all(domains.map((d) => ensureDomainTab(d)));
    expect(results[0]!.opened).toBe(true);
    expect(results[1]!.opened).toBe(false);
    expect(created).toHaveLength(1);
    expect(created[0]!.url).toBe('https://honeybook.com/');
  });
});
