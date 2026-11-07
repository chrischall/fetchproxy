import { describe, it, expect } from 'vitest';
import {
  validateFrame,
  validateInnerFrame,
  encodeInnerFrame,
  sealedFrameWireBytes,
  toB64,
  extensionFeaturesHelloField,
  isBase64Body,
  parseResponseTooLarge,
  responseTooLargeMessage,
  EXTENSION_FEATURE_FETCH_BASE64,
  HOSTED_RELAY_MESSAGE_BYTES,
  KNOWN_EXTENSION_FEATURES,
  MAX_BINARY_RESPONSE_BYTES,
  MAX_EXTENSION_FEATURES,
  MAX_FRAME_BYTES,
  MAX_EXTENSION_FEATURE_LENGTH,
  RELAYED_RESPONSE_HEADERS,
  RESPONSE_TOO_LARGE_CODE,
  type HelloFrameFromExtension,
  type InnerResponseFetchOk,
} from '../src/index.js';

/**
 * #460: an opt-in binary mode for `fetch`. The request asks with
 * `init.responseType: 'base64'`; the answer carries the bytes base64-encoded
 * in the same `body` field, marked `bodyEncoding: 'base64'`, plus a small
 * relayed header subset. Additive inside protocol 4: text-mode frames are
 * byte-for-byte what they were, and the extension advertises support in an
 * unsigned, advisory `features` list on its hello.
 */

const fetchReq = {
  type: 'request',
  id: 1,
  op: 'fetch',
  init: { url: 'https://files.example.com/a.pdf', method: 'GET', tabUrl: 'https://example.com/' },
};

describe('FetchInit.responseType — request validator', () => {
  it('accepts a request without it (every sender before #460)', () => {
    expect(() => validateInnerFrame(fetchReq)).not.toThrow();
  });

  it("accepts 'base64' and passes it through", () => {
    const f = validateInnerFrame({ ...fetchReq, init: { ...fetchReq.init, responseType: 'base64' } });
    expect((f as { init: { responseType?: string } }).init.responseType).toBe('base64');
  });

  it.each(['text', 'arraybuffer', '', 1, true, null])('refuses responseType %j', (v) => {
    expect(() =>
      validateInnerFrame({ ...fetchReq, init: { ...fetchReq.init, responseType: v } }),
    ).toThrow(/inner\.init\.responseType/);
  });
});

const okText = { type: 'response', id: 1, ok: true, op: 'fetch', status: 200, url: 'https://example.com/', body: 'hi' };

describe('fetch response — bodyEncoding and headers', () => {
  it('a text response is unchanged: no bodyEncoding, no headers', () => {
    const f = validateInnerFrame(okText) as InnerResponseFetchOk;
    expect(f).toEqual(okText);
    // Byte-for-byte: the encoder emits exactly the keys it was given.
    expect(new TextDecoder().decode(encodeInnerFrame(okText as InnerResponseFetchOk))).toBe(
      JSON.stringify(okText),
    );
  });

  it('accepts a base64 body with the relayed headers', () => {
    const bytes = new Uint8Array(256).map((_, i) => i);
    const frame = {
      ...okText,
      body: toB64(bytes),
      bodyEncoding: 'base64',
      headers: {
        'content-type': 'application/pdf',
        'content-length': '256',
        'content-disposition': 'attachment; filename="a.pdf"',
      },
    };
    expect(validateInnerFrame(frame)).toEqual(frame);
  });

  it('accepts an empty base64 body (a zero-byte file)', () => {
    expect(() => validateInnerFrame({ ...okText, body: '', bodyEncoding: 'base64', headers: {} })).not.toThrow();
  });

  it.each(['utf8', 'hex', '', 7])('refuses bodyEncoding %j', (v) => {
    expect(() => validateInnerFrame({ ...okText, bodyEncoding: v })).toThrow(/inner\.bodyEncoding/);
  });

  it.each(['not base64!', 'abc', 'ab=c', 'YQ===', 'YWJj\n'])(
    'refuses a base64-marked body that is not standard padded base64: %j',
    (body) => {
      expect(() => validateInnerFrame({ ...okText, body, bodyEncoding: 'base64' })).toThrow(
        /inner\.body/,
      );
    },
  );

  it('refuses non-string header values', () => {
    expect(() =>
      validateInnerFrame({ ...okText, body: '', bodyEncoding: 'base64', headers: { 'content-length': 3 } }),
    ).toThrow(/inner\.headers/);
  });

  it('refuses a non-object headers map', () => {
    expect(() =>
      validateInnerFrame({ ...okText, body: '', bodyEncoding: 'base64', headers: ['content-type'] }),
    ).toThrow(/inner\.headers/);
  });
});

describe('isBase64Body', () => {
  it('accepts every padding length and the full alphabet', () => {
    for (const n of [0, 1, 2, 3, 4, 5, 255, 256]) {
      expect(isBase64Body(toB64(new Uint8Array(n).map((_, i) => i)))).toBe(true);
    }
    expect(isBase64Body('+/+/')).toBe(true);
  });

  it('refuses URL-safe base64, whitespace and bad lengths', () => {
    expect(isBase64Body('-_-_')).toBe(false);
    expect(isBase64Body('YW Jj')).toBe(false);
    expect(isBase64Body('YWJ')).toBe(false);
  });
});

const extHello = {
  type: 'hello',
  protocolVersion: 4,
  role: 'extension',
  platform: 'chrome',
  extensionId: 'contextmint-bridge',
  version: '1.8.0',
  identityX25519Pub: 'AAAA',
  identityEd25519Pub: 'AAAA',
  sessionNonce: 'AAAA',
};

describe('HelloFrameFromExtension.features — validator', () => {
  it('accepts a hello without it (every extension before #460)', () => {
    expect(() => validateFrame(extHello)).not.toThrow();
  });

  it('accepts the list and passes it through', () => {
    const f = validateFrame({ ...extHello, features: ['fetch_base64'] });
    expect((f as HelloFrameFromExtension).features).toEqual(['fetch_base64']);
  });

  it('admits feature names this build does not know — a newer extension must not get its hello refused', () => {
    expect(() => validateFrame({ ...extHello, features: ['fetch_base64', 'teleport'] })).not.toThrow();
  });

  it('refuses a non-array, a non-string entry, an empty or overlong entry, and too many entries', () => {
    expect(() => validateFrame({ ...extHello, features: 'fetch_base64' })).toThrow(/hello\.features/);
    expect(() => validateFrame({ ...extHello, features: [1] })).toThrow(/hello\.features/);
    expect(() => validateFrame({ ...extHello, features: [''] })).toThrow(/hello\.features/);
    expect(() =>
      validateFrame({ ...extHello, features: ['x'.repeat(MAX_EXTENSION_FEATURE_LENGTH + 1)] }),
    ).toThrow(/hello\.features/);
    expect(() =>
      validateFrame({
        ...extHello,
        features: Array.from({ length: MAX_EXTENSION_FEATURES + 1 }, (_, i) => `f${i}`),
      }),
    ).toThrow(/hello\.features/);
  });
});

describe('extensionFeaturesHelloField', () => {
  it('is {} for nothing, so a hello with no features keeps its old bytes', () => {
    expect(extensionFeaturesHelloField([])).toEqual({});
  });

  it('sorts and de-duplicates', () => {
    expect(extensionFeaturesHelloField(['fetch_base64', 'fetch_base64'])).toEqual({
      features: ['fetch_base64'],
    });
  });

  it('knows fetch_base64', () => {
    expect(EXTENSION_FEATURE_FETCH_BASE64).toBe('fetch_base64');
    expect(KNOWN_EXTENSION_FEATURES.has('fetch_base64')).toBe(true);
  });
});

describe('response_too_large', () => {
  it('starts with the wording every published server already classifies as body_too_large', () => {
    expect(responseTooLargeMessage({ limitBytes: 100, declaredBytes: 200 })).toMatch(
      /^response body too large:/,
    );
    expect(responseTooLargeMessage({ limitBytes: 100 })).toMatch(/^response body too large:/);
    expect(RESPONSE_TOO_LARGE_CODE).toBe('response_too_large');
  });

  it('round-trips the cap and the declared length', () => {
    expect(parseResponseTooLarge(responseTooLargeMessage({ limitBytes: 100, declaredBytes: 200 }))).toEqual({
      limitBytes: 100,
      declaredBytes: 200,
    });
    expect(parseResponseTooLarge(responseTooLargeMessage({ limitBytes: 100 }))).toEqual({
      limitBytes: 100,
      declaredBytes: null,
    });
  });

  it('is null for anything else, including the text-mode wording', () => {
    expect(parseResponseTooLarge('response body too large: 6000000 bytes')).toBeNull();
    expect(parseResponseTooLarge('nope')).toBeNull();
  });
});

describe('the binary cap fits the transports it crosses', () => {
  // The largest binary answer a conforming extension can send: the cap's worth
  // of bytes, a long URL, and every relayed header at a generous length.
  const worstCase = (): InnerResponseFetchOk => ({
    type: 'response',
    id: Number.MAX_SAFE_INTEGER,
    ok: true,
    op: 'fetch',
    status: 200,
    url: `https://files.example.com/${'a'.repeat(8 * 1024)}`,
    body: 'A'.repeat(Math.ceil(MAX_BINARY_RESPONSE_BYTES / 3) * 4),
    bodyEncoding: 'base64',
    headers: Object.fromEntries(RELAYED_RESPONSE_HEADERS.map((h) => [h, 'x'.repeat(1024)])),
  });
  const mcpId = `${'m'.repeat(64)}:1.0.0:${'r'.repeat(16)}`;

  it('is larger than the 5 MiB text cap', () => {
    expect(MAX_BINARY_RESPONSE_BYTES).toBeGreaterThan(5 * 1024 * 1024);
  });

  it('seals under MAX_FRAME_BYTES, the cap every receiver enforces', () => {
    const wire = sealedFrameWireBytes(mcpId, Number.MAX_SAFE_INTEGER, encodeInnerFrame(worstCase()));
    expect(wire).toBeLessThan(MAX_FRAME_BYTES);
  });

  it('seals under the hosted relay’s per-message limit, so a hosted download never closes the link', () => {
    const wire = sealedFrameWireBytes(mcpId, Number.MAX_SAFE_INTEGER, encodeInnerFrame(worstCase()));
    expect(wire).toBeLessThan(HOSTED_RELAY_MESSAGE_BYTES);
  });

  it('relays exactly the three headers a server needs before trusting a body', () => {
    expect([...RELAYED_RESPONSE_HEADERS]).toEqual(['content-type', 'content-length', 'content-disposition']);
  });
});
