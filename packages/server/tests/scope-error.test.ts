import { describe, it, expect } from 'vitest';
import {
  FetchproxyScopeError,
  FetchproxyProtocolError,
  protocolErrorFrom,
  classifyBridgeError,
} from '../src/index.js';

/**
 * Gate #2 rejects a widened declared scope until the user re-approves it.
 * The CLI learned to say so (#187), but that guidance lived in the CLI — MCPs
 * consume the bridge through @fetchproxy/bootstrap, catch failures, and
 * re-wrap them in their own copy, so the remediation never survived. Users saw
 * a bare "cookie keys not in declared set: refreshToken" attached to an
 * unrelated auth-config message, with no mention of the one action that fixes
 * it. (#195)
 *
 * Carrying the guidance on a typed error puts it where every consumer can
 * surface it, the same way FetchproxyBridgeDownError.hint already is.
 */
describe('protocolErrorFrom — gate-#2 scope rejections', () => {
  const SCOPE_REJECTIONS = [
    'cookie keys not in declared set: refreshToken',
    'localStorage keys not in declared set: token',
    'sessionStorage keys not in declared set: sid',
    'IndexedDB keys not in declared set: order-42',
    'read_dom names not in declared set: priceLabel',
    'localStorage pointer (auth, /token) not in declared set [outputKey=jwt]',
    '(host, path, headerName) not in declared captureHeaders',
    '(origin, database, store) not in declared indexedDbScopes',
    'graphql_query name not in declared graphqlOps: Autocomplete',
  ];

  it.each(SCOPE_REJECTIONS)('types %j as a scope error', (msg) => {
    const err = protocolErrorFrom(msg);
    expect(err).toBeInstanceOf(FetchproxyScopeError);
    expect(err.message).toContain(msg);
  });

  it('carries actionable re-pair guidance on .hint', () => {
    const err = protocolErrorFrom('cookie keys not in declared set: refreshToken') as FetchproxyScopeError;
    expect(err.hint).toMatch(/revoke/i);
    expect(err.hint).toMatch(/Transporter/);
    // The thing that made this worth typing: it must NOT read as a version
    // problem, which is where the old CLI copy sent people.
    expect(err.hint).not.toMatch(/version mismatch/i);
  });

  it('preserves the raw extension error for callers that want it', () => {
    const err = protocolErrorFrom('cookie keys not in declared set: a, b') as FetchproxyScopeError;
    expect(err.originalError).toBe('cookie keys not in declared set: a, b');
  });

  it('is a FetchproxyProtocolError, so existing catch sites still match', () => {
    const err = protocolErrorFrom('cookie keys not in declared set: x');
    expect(err).toBeInstanceOf(FetchproxyProtocolError);
    expect(classifyBridgeError(err)).toBe('protocol');
  });

  it('leaves unrelated protocol errors alone', () => {
    for (const msg of ['unknown frame type "wat"', 'no tab matching https://x.com/']) {
      const err = protocolErrorFrom(msg);
      expect(err).toBeInstanceOf(FetchproxyProtocolError);
      expect(err).not.toBeInstanceOf(FetchproxyScopeError);
    }
  });
});
