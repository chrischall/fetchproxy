import { describe, it, expect } from 'vitest';
import {
  FetchproxyTabOpeningError,
  FetchproxyNoTabError,
  FetchproxyHintedError,
  FetchproxyProtocolError,
  protocolErrorFrom,
  classifyBridgeError,
} from '../src/index.js';
import { classifyFetchError } from '../src/index.js';

/**
 * The cold-open race (#291): the extension opens a relay tab per declared
 * domain at server-hello without awaiting the page load, so an MCP's first
 * request can arrive before that tab exists. Answered with the ordinary no-tab
 * remedy, the person is told to open a tab on a host the extension is at that
 * moment opening — and a caller who simply retried would have succeeded.
 *
 * The extension now waits on its own open and, when the wait runs out, says
 * so. This is that wording's contract on the server side.
 */
const STILL_OPENING =
  'no tab matching https://www.zillow.com/ answered yet — one is still opening. ' +
  'The extension opened it moments ago and it has not finished loading; ' +
  'retry in a few seconds rather than opening one yourself.';

describe('protocolErrorFrom — a tab that is still opening', () => {
  it('types it as its own error, not as the ordinary no-tab one', () => {
    const err = protocolErrorFrom(STILL_OPENING);
    expect(err).toBeInstanceOf(FetchproxyTabOpeningError);
    // Load-bearing: both wordings start `no tab matching `, so a classifier
    // that matched the prefix alone would staple "open a tab on that host"
    // onto a tab the extension is already opening.
    expect(err).not.toBeInstanceOf(FetchproxyNoTabError);
  });

  it('names retrying as the remedy, and not opening a tab or updating', () => {
    const err = protocolErrorFrom(STILL_OPENING) as FetchproxyTabOpeningError;
    expect(err.hint).toMatch(/retry/i);
    expect(err.hint).not.toMatch(/open a tab on that host/i);
    expect(err.hint).not.toMatch(/version mismatch|update both/i);
  });

  it('stays a protocol error and a hinted one, so existing catch sites match', () => {
    const err = protocolErrorFrom(STILL_OPENING);
    expect(err).toBeInstanceOf(FetchproxyProtocolError);
    expect(err).toBeInstanceOf(FetchproxyHintedError);
    expect(classifyBridgeError(err)).toBe('protocol');
    expect((err as FetchproxyHintedError).originalError).toBe(STILL_OPENING);
  });

  it('is still a no_tab kind — the condition is a missing tab, transiently', () => {
    // `classifyFetchError`'s union is consumed by cohort MCPs; this
    // wording is a no-tab state that will clear on its own, not a new kind.
    expect(classifyFetchError(STILL_OPENING)).toBe('no_tab');
  });

  it('leaves the two pre-existing no-tab wordings where they were', () => {
    expect(protocolErrorFrom('no tab matching https://x.com/')).toBeInstanceOf(
      FetchproxyNoTabError,
    );
    const unreachable =
      'no tab matching https://x.com/ has the fetchproxy content script loaded ' +
      '(1 URL match, none responded).';
    const err = protocolErrorFrom(unreachable);
    expect(err).not.toBeInstanceOf(FetchproxyNoTabError);
    expect(err).not.toBeInstanceOf(FetchproxyTabOpeningError);
  });
});
