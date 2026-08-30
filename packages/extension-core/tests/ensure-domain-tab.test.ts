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

describe('background tab + relay tab group', () => {
  function mockWithGroups(initial: { id: number; url: string }[]) {
    let nextId = 2000;
    let nextGroup = 50;
    const tabs = [...initial];
    const created: { id: number; url: string; active?: boolean }[] = [];
    const groups: { id: number; title?: string }[] = [];
    const grouped: { tabIds: number | number[]; groupId?: number }[] = [];
    const updated: { groupId: number; props: { title?: string; color?: string } }[] = [];
    (globalThis as { chrome?: unknown }).chrome = {
      tabs: {
        query: async () => tabs.filter((t) => t.url.includes('example.com')),
        create: async (props: { url: string; active?: boolean }) => {
          const tab = { id: nextId++, url: props.url, active: props.active };
          created.push(tab);
          return tab;
        },
        group: async (opts: { tabIds: number | number[]; groupId?: number }) => {
          grouped.push(opts);
          if (opts.groupId !== undefined) return opts.groupId;
          const g = { id: nextGroup++ };
          groups.push(g);
          return g.id;
        },
      },
      tabGroups: {
        query: async (q: { title?: string }) => groups.filter((g) => g.title === q.title),
        update: async (groupId: number, props: { title?: string; color?: string }) => {
          updated.push({ groupId, props });
          const g = groups.find((x) => x.id === groupId);
          if (g) g.title = props.title;
          return {};
        },
      },
    };
    return { created, grouped, updated, groups };
  }

  it('opens the relay tab in the BACKGROUND, never stealing focus', async () => {
    const m = mockWithGroups([]);
    await ensureDomainTab('example.com');
    expect(m.created).toHaveLength(1);
    expect(m.created[0]!.active).toBe(false);
  });

  it('files the new tab into a titled fetchproxy group', async () => {
    const m = mockWithGroups([]);
    const r = await ensureDomainTab('example.com');
    expect(m.grouped).toHaveLength(1);
    expect(r.groupId).toBeDefined();
    expect(m.updated[0]!.props.title).toBe('fetchproxy');
  });

  it('reuses the existing group rather than making one per domain', async () => {
    const m = mockWithGroups([]);
    await ensureDomainTab('example.com');
    const firstGroup = m.grouped[0];
    await ensureDomainTab('other-example.com');
    // Second call must target the SAME group id, not create a second group.
    expect(m.grouped).toHaveLength(2);
    expect(m.grouped[1]!.groupId).toBeDefined();
    expect(m.grouped[1]!.groupId).toBe(m.updated[0]!.groupId);
    expect(firstGroup).toBeDefined();
  });

  // Grouping is cosmetic; the tab it files is load-bearing.
  it('still opens the tab when grouping is unavailable', async () => {
    (globalThis as { chrome?: unknown }).chrome = {
      tabs: {
        query: async () => [],
        create: async (props: { url: string; active?: boolean }) => ({ id: 9, url: props.url }),
        // no `group`, no `tabGroups` — an older Chrome or a build without the
        // tabGroups permission.
      },
    };
    const r = await ensureDomainTab('example.com');
    expect(r.opened).toBe(true);
    expect(r.groupId).toBeUndefined();
  });

  it('still opens the tab when grouping throws', async () => {
    (globalThis as { chrome?: unknown }).chrome = {
      tabs: {
        query: async () => [],
        create: async (props: { url: string }) => ({ id: 9, url: props.url }),
        group: async () => {
          throw new Error('permission denied');
        },
      },
      tabGroups: {
        query: async () => [],
        update: async () => ({}),
      },
    };
    const r = await ensureDomainTab('example.com');
    expect(r.opened).toBe(true);
    expect(r.groupId).toBeUndefined();
  });
});
