import { describe, it, expect, vi } from 'vitest';
import { runSession } from '../src/verbs/session.js';
import { emptyProfile } from '../src/profiles.js';
import { EXIT, type Io } from '../src/output.js';
import type { Session } from '@fetchproxy/bootstrap';

function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = []; const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}
const SESSION: Session = {
  cookies: { a: '1' }, localStorage: {}, sessionStorage: {}, capturedHeaders: {}, indexedDb: {},
};

describe('runSession', () => {
  it('maps profile → BootstrapOpts and prints the Session JSON', async () => {
    const io = memIo();
    const profile = { ...emptyProfile(['honeybook.com', 'hbportal.co']), cookies: ['a'] };
    const boot = vi.fn(async () => SESSION);
    const code = await runSession(
      { kind: 'session', profile: 'hb', storageDomain: 'hbportal.co', storageSubdomain: undefined },
      profile, io, boot as never);
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs[0])).toEqual(SESSION);
    const opts = boot.mock.calls[0][0] as Record<string, unknown>;
    expect(opts.serverName).toBe('fpx-hb');
    expect(opts.domains).toEqual(['honeybook.com', 'hbportal.co']);
    expect(opts.storageDomain).toBe('hbportal.co');
    expect((opts.declare as Record<string, unknown>).cookies).toEqual(['a']);
  });

  it('onPairCode and onWaiting go to stderr', async () => {
    const io = memIo();
    const boot = vi.fn(async (opts: { onPairCode?: (c: string) => void; onWaiting?: (h: string) => void }) => {
      opts.onPairCode?.('111-222');
      opts.onWaiting?.('trigger a request to api.x.com');
      return SESSION;
    });
    await runSession({ kind: 'session', profile: 'x', storageDomain: undefined, storageSubdomain: undefined },
      emptyProfile(['x.com']), io, boot as never);
    expect(io.errs.join('\n')).toMatch(/111-222/);
    expect(io.errs.join('\n')).toMatch(/waiting: trigger a request/);
  });

  it("rewrites the server's multi-domain error to name --storage-domain", async () => {
    const io = memIo();
    // `fpx session` can't pre-check like read/dom do: a captureHeaders-only
    // profile never does a domain-scoped read, so a multi-domain profile with
    // no --storage-domain is legitimate there. The server's message is what
    // reaches the user, and it speaks to library callers.
    const boot = vi.fn(async () => {
      throw new Error(
        'FetchproxyServer: this MCP declared multiple domains ["honeybook.com", "hbportal.co"]'
        + " — pass { domain: '<one of them>' } on every per-call request",
      );
    });
    const code = await runSession(
      { kind: 'session', profile: 'hb', storageDomain: undefined, storageSubdomain: undefined },
      { ...emptyProfile(['honeybook.com', 'hbportal.co']), cookies: ['a'] }, io, boot as never);
    expect(code).toBe(EXIT.USAGE);
    expect(io.errs[0]).toContain('--storage-domain');
    expect(io.errs[0]).not.toContain('pass { domain');
    expect(io.errs[0]).toContain('["honeybook.com", "hbportal.co"]');
  });

  it('bridge failure → exit 2', async () => {
    const io = memIo();
    const boot = vi.fn(async () => { throw new Error('extension gone'); });
    const code = await runSession(
      { kind: 'session', profile: 'x', storageDomain: undefined, storageSubdomain: undefined },
      emptyProfile(['x.com']), io, boot as never);
    expect(code).toBe(EXIT.BRIDGE);
  });
});
