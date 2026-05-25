// Tests for the public error-kind classifier. The kind field is what
// lets downstream MCPs surface specific user-facing hints ("reload the
// extension", "open a tab", etc.) without grep'ing strings — and the
// classifier is the single source of truth for the string → kind map.
//
// The classifier sees the raw `error` string the extension put on the
// wire. Every kind in this file corresponds to a literal error template
// emitted somewhere in `extension-core/src/background.ts` or
// `extension-core/src/content.ts`. New kinds get added as new failure
// modes are surfaced; the catch-all `'other'` makes the field forward-
// compatible without breaking downstream code that switch()es on it.
import { describe, it, expect } from 'vitest';
import { classifyFetchError, type FetchErrorKind } from '../src/index.js';

describe('classifyFetchError', () => {
  // Helper to keep cases compact and the test name self-explanatory.
  const cases: Array<[label: string, input: string, expected: FetchErrorKind]> = [
    // The motivating case: extension's background.ts wraps the Chrome
    // sendMessage failure as `tab fetch failed: <Error>`. The inner
    // Chrome string is one of two phrasings, both indicating a dead /
    // missing content-script listener in the matched tab.
    [
      'Chrome "Could not establish connection" wrapped as tab-fetch-failed',
      'tab fetch failed: Error: Could not establish connection. Receiving end does not exist.',
      'content_script_unreachable',
    ],
    [
      'Chrome "Receiving end does not exist" phrasing alone',
      'Receiving end does not exist.',
      'content_script_unreachable',
    ],
    [
      'Chrome connection-establishment phrasing alone',
      'Could not establish connection.',
      'content_script_unreachable',
    ],
    // A genuine in-page fetch failure (CORS, DNS, network drop) goes
    // through the same `tab fetch failed:` wrapper but the inner
    // message is the underlying Error. Stays distinct from the
    // unreachable case so callers can hint correctly.
    [
      'tab present but in-page fetch threw',
      'tab fetch failed: TypeError: NetworkError when attempting to fetch resource.',
      'tab_fetch_failed',
    ],
    // The content-script-side window.fetch wrapper uses a different
    // prefix; surface as the same kind since the upstream cause is
    // the same shape (network/DNS/CORS).
    [
      'content-script window.fetch threw',
      'fetch threw: TypeError: Failed to fetch',
      'tab_fetch_failed',
    ],
    [
      'no compass.com tab open',
      'no tab matching https://www.compass.com/',
      'no_tab',
    ],
    [
      'declared-domain check rejected the URL',
      'url https://evil.example.com/x not in domains [compass.com]',
      'domain_denied',
    ],
    [
      'capability not granted',
      'capability "read_cookies" not granted (declared: [fetch])',
      'capability_denied',
    ],
    [
      'request body too large',
      'request body too large: 10485761 bytes',
      'body_too_large',
    ],
    [
      'response body too large',
      'response body too large: 20000000 bytes',
      'body_too_large',
    ],
    // Future-proofing: anything we haven't seen before should fall
    // through to `'other'` rather than throwing — the kind field is
    // additive guidance, not a contract that every string is known.
    [
      'unknown failure stays \'other\'',
      'something entirely new that we have not yet categorised',
      'other',
    ],
    [
      'empty string is \'other\'',
      '',
      'other',
    ],
  ];

  for (const [label, input, expected] of cases) {
    it(label, () => {
      expect(classifyFetchError(input)).toBe(expected);
    });
  }
});
