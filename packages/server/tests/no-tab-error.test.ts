import { describe, it, expect } from 'vitest';
import {
  FetchproxyNoTabError,
  FetchproxyScopeError,
  FetchproxyHintedError,
  FetchproxyProtocolError,
  protocolErrorFrom,
  classifyBridgeError,
} from '../src/index.js';

/**
 * "no tab matching <url>" means exactly what it says: nothing is open on that
 * host. But `classifyBridgeError` is type-based, so the error arrived as a
 * plain `FetchproxyProtocolError` and the CLI's hint table gave every
 * `protocol` error the blanket "extension/server version mismatch — update
 * both." Real report (#204):
 *
 *   bridge error (protocol): no tab matching https://api.creditkarma.com/
 *     — extension/server version mismatch — update both.
 *
 * Both were current. There was no mismatch. This is the same misdirection
 * FetchproxyScopeError was introduced to stop, so it gets the same treatment:
 * the guidance rides on the error, where every consumer can reach it.
 */
describe('protocolErrorFrom — no-tab rejections', () => {
  it('types a bare no-tab rejection as a no-tab error', () => {
    const err = protocolErrorFrom('no tab matching https://api.creditkarma.com/');
    expect(err).toBeInstanceOf(FetchproxyNoTabError);
  });

  it('names the remedy — open a tab — and not a version bump', () => {
    const err = protocolErrorFrom('no tab matching https://x.com/') as FetchproxyNoTabError;
    expect(err.hint).toMatch(/open a tab/i);
    // The whole point: it must not read as a version problem, which is where
    // the blanket `protocol` hint sent people.
    expect(err.hint).not.toMatch(/version mismatch/i);
    expect(err.hint).not.toMatch(/update both/i);
  });

  it('preserves the raw extension error for callers that want it', () => {
    const err = protocolErrorFrom('no tab matching https://x.com/') as FetchproxyNoTabError;
    expect(err.originalError).toBe('no tab matching https://x.com/');
  });

  it('is a FetchproxyProtocolError, so existing catch sites still match', () => {
    const err = protocolErrorFrom('no tab matching https://x.com/');
    expect(err).toBeInstanceOf(FetchproxyProtocolError);
    expect(classifyBridgeError(err)).toBe('protocol');
  });

  it('leaves the content-script variant alone — it has a different remedy', () => {
    // "matched but unreachable" is fixed by refreshing the page, not by
    // opening one, and the extension's own wording already says so. Retyping
    // it here would bolt on contradictory advice.
    const msg =
      'no tab matching https://x.com/ has the fetchproxy content script loaded ' +
      '(1 URL match, none responded). Refresh the page in your browser to inject ' +
      'the content script, then retry.';
    const err = protocolErrorFrom(msg);
    expect(err).not.toBeInstanceOf(FetchproxyNoTabError);
    expect(err).toBeInstanceOf(FetchproxyProtocolError);
  });

  it('leaves unrelated protocol errors alone', () => {
    const err = protocolErrorFrom('unknown frame type "wat"');
    expect(err).not.toBeInstanceOf(FetchproxyNoTabError);
    expect(err).toBeInstanceOf(FetchproxyProtocolError);
  });

  it('does not collide with scope rejections', () => {
    const scope = protocolErrorFrom('cookie keys not in declared set: a');
    expect(scope).toBeInstanceOf(FetchproxyScopeError);
    expect(scope).not.toBeInstanceOf(FetchproxyNoTabError);
  });
});

/**
 * Both hinted errors carry the same shape. Consumers — the CLI included —
 * should be able to render "raw error — remedy" without knowing which
 * subclass they caught, so the next hinted error added doesn't need a new
 * branch at every call site to avoid inheriting the wrong blanket advice.
 */
describe('FetchproxyHintedError — the shared contract', () => {
  it.each([
    ['scope', 'cookie keys not in declared set: a'],
    ['no-tab', 'no tab matching https://x.com/'],
  ])('%s rejections are hinted errors', (_label, msg) => {
    const err = protocolErrorFrom(msg);
    expect(err).toBeInstanceOf(FetchproxyHintedError);
    const hinted = err as FetchproxyHintedError;
    expect(hinted.originalError).toBe(msg);
    expect(hinted.hint.length).toBeGreaterThan(0);
    expect(hinted.message).toContain(msg);
  });

  it('does not tag ordinary protocol errors as hinted', () => {
    expect(protocolErrorFrom('unknown frame type "wat"')).not.toBeInstanceOf(FetchproxyHintedError);
  });
});
