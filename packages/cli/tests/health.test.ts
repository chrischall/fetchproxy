import { describe, it, expect, vi } from 'vitest';
import { runHealth, runPair } from '../src/verbs/health.js';
import { emptyProfile } from '../src/profiles.js';
import { EXIT, type Io } from '../src/output.js';
import type { VerbServer } from '../src/verbs/fetch.js';

function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = []; const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}
function stubServer(overrides: Partial<VerbServer> = {}): VerbServer {
  return {
    listen: vi.fn(async () => {}), close: vi.fn(async () => {}),
    request: vi.fn(async () => ({ status: 405, body: '', url: 'https://x.com/' })),
    readCookies: vi.fn(async () => ''), readLocalStorage: vi.fn(async () => ({})),
    readSessionStorage: vi.fn(async () => ({})), readIndexedDb: vi.fn(async () => ({})),
    bridgeHealth: vi.fn(() => ({ role: 'host', consecutiveFailures: 0 })),
    ...overrides,
  } as never;
}

describe('health & pair', () => {
  it('health prints bridgeHealth JSON', async () => {
    const io = memIo();
    const code = await runHealth({ kind: 'health', profile: 'x' },
      emptyProfile(['x.com']), io, () => stubServer());
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs[0])).toEqual({ role: 'host', consecutiveFailures: 0 });
  });

  it('pair succeeds on ANY http status (405 included)', async () => {
    const io = memIo();
    const code = await runPair({ kind: 'pair', profile: 'x', domain: undefined },
      emptyProfile(['x.com']), io, () => stubServer());
    expect(code).toBe(EXIT.OK);
    expect(io.errs.join('\n')).toMatch(/paired ✓/);
    expect(io.outs).toEqual([]);
  });

  it('pair on a multi-domain profile without --domain is a UsageError', async () => {
    await expect(runPair({ kind: 'pair', profile: 'hb', domain: undefined },
      emptyProfile(['honeybook.com', 'hbportal.co']), memIo(), () => stubServer()))
      .rejects.toThrow(/--domain/);
  });

  it('pair maps bridge failure to exit 2', async () => {
    const io = memIo();
    const server = stubServer({ request: vi.fn(async () => { throw new Error('down'); }) });
    const code = await runPair({ kind: 'pair', profile: 'x', domain: undefined },
      emptyProfile(['x.com']), io, () => server);
    expect(code).toBe(EXIT.BRIDGE);
  });
});
