import { describe, it, expect, vi } from 'vitest';

import { runCaptureRedirect } from '../src/verbs/capture-redirect.js';
import { runGraphql } from '../src/verbs/graphql.js';
import { emptyProfile } from '../src/profiles.js';
import { serverOptsFor } from '../src/server-opts.js';
import { EXIT, UsageError, type Io } from '../src/output.js';

/**
 * The last two capabilities with no CLI surface (chrischall/fetchproxy#341).
 * Unlike `capture_request_header` and `write_cookies`, these were never
 * declarable either — so nothing over-granted, they were simply unreachable.
 */
function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = []; const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}

function stubServer(over: Record<string, unknown> = {}) {
  const s = {
    listen: vi.fn(async () => {}),
    close: vi.fn(async () => {}),
    captureRedirect: vi.fn(async () => 'https://cdn.example.com/presigned?sig=x'),
    graphqlQuery: vi.fn(async () => ({ data: { ok: true } })),
    ...over,
  };
  return s as never;
}
const listenCalls = (s: unknown) =>
  (s as { listen: { mock: { calls: unknown[] } } }).listen.mock.calls.length;

describe('capability derivation', () => {
  it('adds capture_redirect only when the profile grants it', () => {
    const off = serverOptsFor('p', emptyProfile(['x.com']), '2.10.0');
    expect(off.capabilities).not.toContain('capture_redirect');
    const on = serverOptsFor('p', { ...emptyProfile(['x.com']), captureRedirect: true }, '2.10.0');
    expect(on.capabilities).toContain('capture_redirect');
  });

  // Per-operation, not wholesale: an undeclared name would be an arbitrary
  // query on the user's live session.
  it('adds graphql only when at least one operation is declared', () => {
    const off = serverOptsFor('p', emptyProfile(['x.com']), '2.10.0');
    expect(off.capabilities).not.toContain('graphql');
    const on = serverOptsFor('p', {
      ...emptyProfile(['x.com']),
      graphqlOps: [{ name: 'avail', operationName: 'RestaurantsAvailability' }],
    }, '2.10.0');
    expect(on.capabilities).toContain('graphql');
  });
});

describe('fpx capture-redirect', () => {
  const granted = () => ({ ...emptyProfile(['example.com']), captureRedirect: true });
  const cmd = (over: Record<string, unknown> = {}) =>
    ({ kind: 'capture-redirect', profile: 'p', host: 'api.example.com', ...over }) as never;

  it('refuses before dialling when the profile does not grant it', async () => {
    const server = stubServer();
    await expect(
      runCaptureRedirect(cmd(), emptyProfile(['example.com']), memIo(), () => server),
    ).rejects.toThrow(UsageError);
    expect(listenCalls(server)).toBe(0);
  });

  // Scope is the declared domains — there is no per-entry declaration to
  // narrow against, so this check is the only thing bounding the host.
  it('refuses a host outside the declared domains, before dialling', async () => {
    const server = stubServer();
    await expect(
      runCaptureRedirect(cmd({ host: 'evil.test' }), granted(), memIo(), () => server),
    ).rejects.toThrow(UsageError);
    expect(listenCalls(server)).toBe(0);
  });

  it('accepts a subdomain of a declared domain and reports the target', async () => {
    const server = stubServer();
    const io = memIo();
    const code = await runCaptureRedirect(cmd({ path: '/dl/*' }), granted(), io, () => server);
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs.join('\n'))).toEqual({
      host: 'api.example.com',
      path: '/dl/*',
      redirectUrl: 'https://cdn.example.com/presigned?sig=x',
    });
  });

  it('reports a null path when none was given', async () => {
    const io = memIo();
    await runCaptureRedirect(cmd(), granted(), io, () => stubServer());
    expect(JSON.parse(io.outs.join('\n')).path).toBeNull();
  });
});

describe('fpx graphql', () => {
  const OPS = [{ name: 'avail', operationName: 'RestaurantsAvailability' }];
  const granted = () => ({ ...emptyProfile(['example.com']), graphqlOps: OPS });
  const cmd = (over: Record<string, unknown> = {}) =>
    ({ kind: 'graphql', profile: 'p', name: 'avail', variables: {}, ...over }) as never;

  it('refuses before dialling when no operation is declared', async () => {
    const server = stubServer();
    await expect(
      runGraphql(cmd(), emptyProfile(['example.com']), memIo(), () => server),
    ).rejects.toThrow(UsageError);
    expect(listenCalls(server)).toBe(0);
  });

  it('refuses an undeclared operation name, before dialling', async () => {
    const server = stubServer();
    await expect(
      runGraphql(cmd({ name: 'somethingElse' }), granted(), memIo(), () => server),
    ).rejects.toThrow(UsageError);
    expect(listenCalls(server)).toBe(0);
  });

  // #209's regression class: the server guards --via-tab too, but only after
  // the bridge is up, so a typo becomes exit 2 "bridge error" instead of a
  // usage error — after making the user wait on a connection. Adding a second
  // call site for the flag without the check is how that comes back.
  it('refuses a --via-tab outside the declared domains, before dialling', async () => {
    const server = stubServer();
    await expect(
      runGraphql(cmd({ viaTab: 'https://evil.test/' }), granted(), memIo(), () => server),
    ).rejects.toThrow(UsageError);
    expect(listenCalls(server)).toBe(0);
  });

  it('accepts a --via-tab on a declared domain and passes it as tabUrl', async () => {
    const server = stubServer();
    await runGraphql(
      cmd({ viaTab: 'https://www.example.com/' }), granted(), memIo(), () => server,
    );
    const s = server as unknown as { graphqlQuery: { mock: { calls: unknown[][] } } };
    expect(s.graphqlQuery.mock.calls[0]![0]).toMatchObject({
      tabUrl: 'https://www.example.com/',
    });
  });

  it('passes the handle and variables through and prints the result', async () => {
    const server = stubServer();
    const io = memIo();
    const code = await runGraphql(
      cmd({ variables: { first: 10 } }), granted(), io, () => server,
    );
    expect(code).toBe(EXIT.OK);
    const s = server as unknown as { graphqlQuery: { mock: { calls: unknown[][] } } };
    expect(s.graphqlQuery.mock.calls[0]![0]).toMatchObject({
      name: 'avail', variables: { first: 10 },
    });
    expect(JSON.parse(io.outs.join('\n'))).toEqual({ data: { ok: true } });
  });

  // Absent, not undefined: the server distinguishes them.
  it('omits tabUrl entirely when --via-tab was not given', async () => {
    const server = stubServer();
    await runGraphql(cmd(), granted(), memIo(), () => server);
    const s = server as unknown as { graphqlQuery: { mock: { calls: unknown[][] } } };
    expect(Object.prototype.hasOwnProperty.call(s.graphqlQuery.mock.calls[0]![0], 'tabUrl'))
      .toBe(false);
  });
});

/**
 * chrischall/fetchproxy#342 — `--capture-timeout` above 30s was inert.
 *
 * Two independent halves, and only asserting both makes the flag real: the
 * per-call `timeoutMs` has to REACH the verb, and the transport deadline the
 * server races it against has to be lifted clear of it. `fetchTimeoutMs`
 * defaults to 30_000 and the CLI set it nowhere, so `_withVerbTimeout` fired at
 * 30s and the server's own error said so: "A per-call timeoutMs cannot exceed
 * it; raise fetchTimeoutMs on the transport to wait longer."
 *
 * resy-mcp carries this exact trap in a comment at `src/auth-fetchproxy.ts`,
 * which is where the margin's shape comes from.
 */
describe('capture timeouts reach the bridge', () => {
  const captureCall = (s: unknown) =>
    (s as { captureRedirect: { mock: { calls: Record<string, unknown>[][] } } })
      .captureRedirect.mock.calls[0]![0]!;

  it('forwards capture-redirect’s timeoutMs to the verb', async () => {
    const server = stubServer();
    const opts: Record<string, unknown>[] = [];
    await runCaptureRedirect(
      { kind: 'capture-redirect', profile: 'p', host: 'api.example.com', timeoutMs: 90_000 } as never,
      { ...emptyProfile(['example.com']), captureRedirect: true },
      memIo(),
      (o) => { opts.push(o as unknown as Record<string, unknown>); return server; },
    );
    expect(captureCall(server).timeoutMs).toBe(90_000);
  });

  // The half a forwarding test alone cannot see: the call asked for 90s and
  // the transport would still have cut it off at 30.
  it('lifts the transport deadline clear of the window asked for', async () => {
    const server = stubServer();
    const opts: Record<string, unknown>[] = [];
    await runCaptureRedirect(
      { kind: 'capture-redirect', profile: 'p', host: 'api.example.com', timeoutMs: 90_000 } as never,
      { ...emptyProfile(['example.com']), captureRedirect: true },
      memIo(),
      (o) => { opts.push(o as unknown as Record<string, unknown>); return server; },
    );
    expect(opts[0]!.fetchTimeoutMs as number).toBeGreaterThan(90_000);
  });

  // No `--capture-timeout` must not SHORTEN anything: the floor is the
  // server's own default, so an unflagged run behaves exactly as before.
  it('never drops the deadline below the transport default', async () => {
    const server = stubServer();
    const opts: Record<string, unknown>[] = [];
    await runCaptureRedirect(
      { kind: 'capture-redirect', profile: 'p', host: 'api.example.com' } as never,
      { ...emptyProfile(['example.com']), captureRedirect: true },
      memIo(),
      (o) => { opts.push(o as unknown as Record<string, unknown>); return server; },
    );
    expect(opts[0]!.fetchTimeoutMs).toBe(30_000);
    expect(captureCall(server).timeoutMs).toBeUndefined();
  });
});
