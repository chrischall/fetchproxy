import { describe, it, expect, vi } from 'vitest';

import { runCapture } from '../src/verbs/capture.js';
import { runWriteCookies } from '../src/verbs/write-cookies.js';
import { emptyProfile } from '../src/profiles.js';
import { FetchproxySessionNotReadyError } from '@fetchproxy/server';

import { EXIT, UsageError, type Io } from '../src/output.js';

/**
 * Both verbs close the same defect: the CLI could DECLARE a capability —
 * `--capture-header` deriving `capture_request_header`, `--allow-cookie-write`
 * deriving `write_cookies` — put it in the pair prompt for the user to
 * approve, and then had nothing that could use it. Diagnosing
 * chrischall/fetchproxy#324 needed `fpx capture` and had to be done with a
 * throwaway script, which is how the gap surfaced.
 */
function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = []; const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}

function stubServer(over: Record<string, unknown> = {}) {
  const s = {
    listen: vi.fn(async () => {}),
    close: vi.fn(async () => {}),
    captureRequestHeader: vi.fn(async () => 'VALUE'),
    writeCookies: vi.fn(async () => ['sid']),
    ...over,
  };
  return s as never;
}

const DECLS = [
  { headerName: 'authorization', host: 'api.resy.com', path: '/*' },
  { headerName: 'x-resy-auth-token', host: 'api.resy.com', path: '/*' },
];
const withCaptures = () => ({ ...emptyProfile(['resy.com']), captureHeaders: DECLS });

describe('fpx capture', () => {
  it('refuses before dialling when the profile declares no captures', async () => {
    const server = stubServer();
    await expect(
      runCapture({ kind: 'capture', profile: 'p', names: [] } as never,
        emptyProfile(['resy.com']), memIo(), () => server),
    ).rejects.toThrow(UsageError);
    expect((server as unknown as { listen: { mock: { calls: unknown[] } } }).listen.mock.calls)
      .toHaveLength(0);
  });

  it('captures every declared header when none is named', async () => {
    const server = stubServer();
    const io = memIo();
    const code = await runCapture({ kind: 'capture', profile: 'p', names: [] } as never,
      withCaptures(), io, () => server);
    expect(code).toBe(EXIT.OK);
    const s = server as unknown as { captureRequestHeader: { mock: { calls: unknown[][] } } };
    expect(s.captureRequestHeader.mock.calls).toHaveLength(2);
    expect(JSON.parse(io.outs.join('\n'))).toEqual({
      'authorization@api.resy.com/*': 'VALUE',
      'x-resy-auth-token@api.resy.com/*': 'VALUE',
    });
  });

  // The window is shared: a capture resolves on the NEXT matching request, so
  // sequential asks would need one page request each and time out on all but
  // the first. This is the property, not an optimisation.
  it('issues the captures concurrently, not one after another', async () => {
    let inFlight = 0; let peak = 0;
    const server = stubServer({
      captureRequestHeader: vi.fn(async () => {
        inFlight += 1; peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 5));
        inFlight -= 1;
        return 'VALUE';
      }),
    });
    await runCapture({ kind: 'capture', profile: 'p', names: [] } as never,
      withCaptures(), memIo(), () => server);
    expect(peak, 'captures must overlap').toBe(2);
  });

  it('narrows to a named header, by bare name or header@host', async () => {
    for (const name of ['authorization', 'authorization@api.resy.com']) {
      const server = stubServer();
      await runCapture({ kind: 'capture', profile: 'p', names: [name] } as never,
        withCaptures(), memIo(), () => server);
      const s = server as unknown as { captureRequestHeader: { mock: { calls: unknown[][] } } };
      expect(s.captureRequestHeader.mock.calls, name).toHaveLength(1);
    }
  });

  it('refuses an undeclared name before dialling', async () => {
    const server = stubServer();
    await expect(
      runCapture({ kind: 'capture', profile: 'p', names: ['x-nope'] } as never,
        withCaptures(), memIo(), () => server),
    ).rejects.toThrow(UsageError);
  });

  // A partial answer is the useful one: knowing WHICH headers the page sends
  // is the reason to ask for several.
  it('reports a missing header as null and still exits OK', async () => {
    let n = 0;
    const server = stubServer({
      captureRequestHeader: vi.fn(async () => {
        n += 1;
        if (n === 1) throw new Error('capture timed out');
        return 'VALUE';
      }),
    });
    const io = memIo();
    const code = await runCapture({ kind: 'capture', profile: 'p', names: [] } as never,
      withCaptures(), io, () => server);
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs.join('\n'))['authorization@api.resy.com/*']).toBeNull();
  });

  /**
   * A bridge failure must not be printed as `null`.
   *
   * `listen()` does no I/O — identity and mcpId only — and the connect is lazy
   * inside `captureRequestHeader`, so an unpaired extension, a bridge that is
   * not running and a scope the profile does not cover ALL arrive as rejected
   * elements of the `allSettled`, never as a throw. Swallowing them made every
   * one of those look like an idle tab, which is the only one that means
   * "wait and retry".
   */
  it('reports a bridge failure on stderr instead of printing nulls', async () => {
    const server = stubServer({
      captureRequestHeader: vi.fn(async () => {
        throw new FetchproxySessionNotReadyError({
          mcpId: 'fpx-x:1.0.0:aaaaaaaaaaaaaaaa',
          pairCode: '123-456',
        });
      }),
    });
    const io = memIo();
    const code = await runCapture({ kind: 'capture', profile: 'p', names: [] } as never,
      withCaptures(), io, () => server);
    expect(code).toBe(EXIT.BRIDGE);
    expect(io.errs.join('\n')).toMatch(/pair code 123-456/);
    expect(io.outs.join('\n'), 'must not print a wall of nulls instead').toBe('');
  });

  // A partial answer is still the useful one, so a rejection alongside a hit
  // must NOT hijack the output.
  it('still prints partial results when something was captured', async () => {
    let n = 0;
    const server = stubServer({
      captureRequestHeader: vi.fn(async () => {
        n += 1;
        if (n === 1) throw new FetchproxySessionNotReadyError({ mcpId: 'x:1:a', pairCode: '9' });
        return 'VALUE';
      }),
    });
    const io = memIo();
    const code = await runCapture({ kind: 'capture', profile: 'p', names: [] } as never,
      withCaptures(), io, () => server);
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs.join('\n'))['x-resy-auth-token@api.resy.com/*']).toBe('VALUE');
  });

  // The idle-tab case. A script must be able to tell "nothing arrived" from a hit.
  it('exits non-zero when nothing was captured at all', async () => {
    const server = stubServer({
      captureRequestHeader: vi.fn(async () => { throw new Error('capture timed out'); }),
    });
    const code = await runCapture({ kind: 'capture', profile: 'p', names: [] } as never,
      withCaptures(), memIo(), () => server);
    expect(code).toBe(EXIT.BRIDGE);
  });
});

describe('fpx write-cookies', () => {
  const writable = () => ({
    ...emptyProfile(['resy.com']), cookies: ['sid'], cookieWrite: true,
  });
  const cmd = (cookies: Record<string, string>) =>
    ({ kind: 'write-cookies', profile: 'p', cookies }) as never;

  it('refuses when the profile has not been granted cookie writes', async () => {
    const server = stubServer();
    await expect(
      runWriteCookies(cmd({ sid: 'x' }),
        { ...emptyProfile(['resy.com']), cookies: ['sid'] }, memIo(), () => server),
    ).rejects.toThrow(UsageError);
    expect((server as unknown as { listen: { mock: { calls: unknown[] } } }).listen.mock.calls)
      .toHaveLength(0);
  });

  it('refuses a cookie the profile does not declare', async () => {
    await expect(
      runWriteCookies(cmd({ other: 'x' }), writable(), memIo(), () => stubServer()),
    ).rejects.toThrow(UsageError);
  });

  it('refuses an empty write', async () => {
    await expect(
      runWriteCookies(cmd({}), writable(), memIo(), () => stubServer()),
    ).rejects.toThrow(UsageError);
  });

  // Echo what the BROWSER says it set — a cookie the page refused is the thing
  // worth seeing, and it is not necessarily what we asked for.
  it('reports what the browser wrote, not what was requested', async () => {
    const server = stubServer({ writeCookies: vi.fn(async () => ['sid']) });
    const io = memIo();
    const code = await runWriteCookies(cmd({ sid: 'a' }), writable(), io, () => server);
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(io.outs.join('\n'))).toEqual({ written: ['sid'] });
  });
});

/**
 * Two declarations differing only by PATH are legitimate — `--capture-header`
 * takes a path — and keying output on `header@host` collapsed them, so the
 * second overwrote the first and one capture vanished with nothing to say it
 * had.
 */
describe('fpx capture with paths', () => {
  const BY_PATH = [
    { headerName: 'authorization', host: 'api.resy.com', path: '/3/*' },
    { headerName: 'authorization', host: 'api.resy.com', path: '/4/*' },
  ];
  const profileByPath = () => ({ ...emptyProfile(['resy.com']), captureHeaders: BY_PATH });

  it('keeps both results rather than collapsing them', async () => {
    let n = 0;
    const server = stubServer({
      captureRequestHeader: vi.fn(async () => `VALUE${(n += 1)}`),
    });
    const io = memIo();
    await runCapture({ kind: 'capture', profile: 'p', names: [] } as never,
      profileByPath(), io, () => server);
    const out = JSON.parse(io.outs.join('\n'));
    expect(Object.keys(out)).toEqual([
      'authorization@api.resy.com/3/*',
      'authorization@api.resy.com/4/*',
    ]);
    expect(new Set(Object.values(out)).size, 'both values must survive').toBe(2);
  });

  it('a bare header name selects every declaration that shares it', async () => {
    const server = stubServer();
    await runCapture({ kind: 'capture', profile: 'p', names: ['authorization'] } as never,
      profileByPath(), memIo(), () => server);
    const s = server as unknown as { captureRequestHeader: { mock: { calls: unknown[][] } } };
    expect(s.captureRequestHeader.mock.calls).toHaveLength(2);
  });

  it('the full key narrows to exactly one', async () => {
    const server = stubServer();
    await runCapture(
      { kind: 'capture', profile: 'p', names: ['authorization@api.resy.com/4/*'] } as never,
      profileByPath(), memIo(), () => server,
    );
    const s = server as unknown as { captureRequestHeader: { mock: { calls: unknown[][] } } };
    expect(s.captureRequestHeader.mock.calls).toHaveLength(1);
    expect(s.captureRequestHeader.mock.calls[0]![0]).toMatchObject({ path: '/4/*' });
  });
});
