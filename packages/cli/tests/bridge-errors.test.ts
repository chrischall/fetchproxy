import { describe, it, expect } from 'vitest';
import { FetchproxyProtocolError } from '@fetchproxy/server';
import { mapBridgeError } from '../src/bridge-errors.js';
import { EXIT, type Io } from '../src/output.js';

function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = [];
  const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}

describe('mapBridgeError — scope-diff errors are not version mismatches', () => {
  // A widened declared scope (e.g. an MCP adding a cookie key) is rejected by
  // the extension's gate #2 until the user re-approves. That surfaces as a
  // `protocol` error, which used to inherit the blanket
  // "extension/server version mismatch — update both." hint — sending users
  // to chase a version problem that does not exist. The remedy is a re-pair.
  it('tells the user to re-approve, not to update, on an undeclared-key error', () => {
    const io = memIo();
    const code = mapBridgeError(
      new FetchproxyProtocolError('cookie keys not in declared set: refreshToken'),
      io,
    );
    expect(code).toBe(EXIT.BRIDGE);
    const out = io.errs.join('\n');
    expect(out).toMatch(/cookie keys not in declared set: refreshToken/);
    expect(out).toMatch(/re-approve|revoke/i);
    expect(out).not.toMatch(/version mismatch/i);
  });

  it('names the profile flag so the user knows what to revoke', () => {
    const io = memIo();
    mapBridgeError(new FetchproxyProtocolError('cookie keys not in declared set: a, b'), io);
    expect(io.errs.join('\n')).toMatch(/Transporter/);
  });

  // Gate #2 rejects a widened scope in EIGHT different wordings, one per
  // declarable bucket. The first cut of this fix only matched the cookie and
  // {local,session}Storage forms, so IndexedDB / DOM / captureHeaders /
  // graphqlOps / storage-pointer rejections still inherited the misleading
  // version-mismatch hint despite being the same re-pair situation.
  it.each([
    'cookie keys not in declared set: refreshToken',
    'localStorage keys not in declared set: token',
    'sessionStorage keys not in declared set: sid',
    'IndexedDB keys not in declared set: order-42',
    'read_dom names not in declared set: priceLabel',
    'localStorage pointer (auth, /token) not in declared set [outputKey=jwt]',
    '(host, path, headerName) not in declared captureHeaders',
    '(origin, database, store) not in declared indexedDbScopes',
    'graphql_query name not in declared graphqlOps: Autocomplete',
  ])('treats %j as a re-pair, not a version mismatch', (msg) => {
    const io = memIo();
    mapBridgeError(new FetchproxyProtocolError(msg), io);
    const out = io.errs.join('\n');
    expect(out).not.toMatch(/version mismatch/i);
    expect(out).toMatch(/re-approve|revoke/i);
    expect(out).toMatch(/Transporter/);
  });

  it('still reports a genuine protocol error as a version mismatch', () => {
    const io = memIo();
    mapBridgeError(new FetchproxyProtocolError('unknown frame type "wat"'), io);
    expect(io.errs.join('\n')).toMatch(/version mismatch/i);
  });
});
