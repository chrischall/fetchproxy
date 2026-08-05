import { describe, it, expect } from 'vitest';
import { sealInnerFrame, openEncryptedFrame } from '../src/seal.js';
import { validateInnerFrame } from '../src/validate.js';
import type { InnerFrame } from '../src/frames.js';

/**
 * Round-trips `write_cookies` through the real seal → open → validate path.
 *
 * This exists because the verb shipped once without it. The handler, the
 * server method, the gates and their unit tests were all correct, and the verb
 * still could not execute: `validate.ts` had no branch for it, so every
 * request was dropped at the extension's frame-decode boundary and
 * `writeCookies()` simply hung to its timeout. The success response was worse
 * — an unknown success-response op throws on the MCP side, and the
 * concentrator host answers that by closing the EXTENSION socket, taking down
 * every other MCP on the bridge.
 *
 * Neither gap was reachable from the existing tests, and not for want of
 * coverage: the server tests stub `sendInnerFrame` and the extension tests call
 * the pure resolvers directly, so nothing crossed the wire. Any new verb needs
 * a test at this layer, not just at both ends of it.
 */
describe('write_cookies — over the wire', () => {
  const key = new Uint8Array(32).fill(7);
  const mcpId = 'creditkarma-mcp:2.4.0:a3f7c91d2e8b4f56';

  const request = (init: Record<string, unknown>): InnerFrame =>
    ({ type: 'request', id: 1, op: 'write_cookies', init }) as unknown as InnerFrame;

  it('round-trips a request', async () => {
    const inner = request({
      origin: 'https://www.creditkarma.com',
      cookies: [{ name: 'CKAT', value: 'rotated' }],
    });

    const opened = await openEncryptedFrame(key, await sealInnerFrame(key, mcpId, 1, inner));

    expect(opened).toEqual(inner);
  });

  it('round-trips a request carrying a cookie path', async () => {
    const inner = request({
      origin: 'https://www.example.com',
      path: '/campus',
      cookies: [{ name: 'JSESSIONID', value: 'v' }],
    });

    expect(await openEncryptedFrame(key, await sealInnerFrame(key, mcpId, 2, inner))).toEqual(inner);
  });

  it('round-trips a success response', async () => {
    // The one that would have closed the extension socket for every MCP on
    // the concentrator, not just the one that made the call.
    const inner: InnerFrame = {
      type: 'response',
      id: 1,
      ok: true,
      op: 'write_cookies',
      written: ['CKAT'],
    } as unknown as InnerFrame;

    expect(await openEncryptedFrame(key, await sealInnerFrame(key, mcpId, 3, inner))).toEqual(inner);
  });

  it('round-trips a gate rejection', async () => {
    const inner: InnerFrame = {
      type: 'response',
      id: 1,
      ok: false,
      op: 'write_cookies',
      error: 'cookie keys not in declared set: ADMIN',
    } as unknown as InnerFrame;

    expect(await openEncryptedFrame(key, await sealInnerFrame(key, mcpId, 4, inner))).toEqual(inner);
  });
});

describe('write_cookies — what the validator refuses', () => {
  const bad = (init: Record<string, unknown>) => () =>
    validateInnerFrame({ type: 'request', id: 1, op: 'write_cookies', init });

  it('refuses an empty cookie list', () => {
    // Otherwise the extension answers `ok: true, written: []` — a success
    // that wrote nothing, which is the exact shape of a silent failure.
    expect(bad({ origin: 'https://www.example.com', cookies: [] })).toThrow(/non-empty/);
  });

  it('refuses a missing cookie list', () => {
    expect(bad({ origin: 'https://www.example.com' })).toThrow(/cookies/);
  });

  it('refuses an origin carrying a path', () => {
    // The domain gate is decided on the bare origin; a path folded into it
    // would be a way past that gate.
    expect(bad({ origin: 'https://www.example.com/admin', cookies: [{ name: 'A', value: 'v' }] }))
      .toThrow(/bare origin/);
  });

  it('refuses a non-https origin', () => {
    expect(bad({ origin: 'http://www.example.com', cookies: [{ name: 'A', value: 'v' }] }))
      .toThrow(/https/);
  });

  it('refuses a glob in a cookie name', () => {
    // Declared keys may be globs; a write names one exact cookie. A pattern
    // here would reach cookies the pair popup never displayed.
    expect(bad({ origin: 'https://www.example.com', cookies: [{ name: 'CK*', value: 'v' }] }))
      .toThrow(/invalid key/);
  });

  it('refuses a non-string value', () => {
    expect(bad({ origin: 'https://www.example.com', cookies: [{ name: 'A', value: 42 }] }))
      .toThrow(/value/);
  });

  it('refuses extra fields on a cookie entry', () => {
    // No smuggling attributes: this verb overwrites a value in place and does
    // not let the caller choose scope or lifetime.
    expect(
      bad({
        origin: 'https://www.example.com',
        cookies: [{ name: 'A', value: 'v', domain: '.evil.test' }],
      }),
    ).toThrow(/unexpected field/);
  });

  it('refuses extra fields on the init', () => {
    expect(
      bad({ origin: 'https://www.example.com', cookies: [{ name: 'A', value: 'v' }], expiry: 1 }),
    ).toThrow(/unexpected field/);
  });

  it('refuses a success response with no written list', () => {
    expect(() =>
      validateInnerFrame({ type: 'response', id: 1, ok: true, op: 'write_cookies' }),
    ).toThrow(/written/);
  });

  it('refuses a written list that is not strings', () => {
    expect(() =>
      validateInnerFrame({ type: 'response', id: 1, ok: true, op: 'write_cookies', written: [1] }),
    ).toThrow(/written/);
  });
});
