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
