import { describe, it, expect } from 'vitest';
import {
  MAX_FRAME_BYTES,
  AES_GCM_TAG_BYTES,
  base64Length,
  sealedFrameWireBytes,
  sealInnerFrame,
  toB64,
  type InnerFrame,
} from '../src/index.js';

/**
 * `sealedFrameWireBytes` is the size a frame WILL be, answered before it is
 * sealed. Both the extension's producing-end cap and the host's `maxPayload`
 * are stated in the same units, so the number has to be exact rather than an
 * estimate: an under-count lets an oversize frame out, and an over-count
 * refuses one that would have fitted.
 */

const key = new Uint8Array(32).fill(3);
const utf8 = (s: string) => new TextEncoder().encode(s).length;

const cases: { label: string; inner: InnerFrame }[] = [
  { label: 'ping', inner: { type: 'ping' } },
  {
    label: 'an ASCII fetch response',
    inner: {
      type: 'response',
      id: 4,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://alltrails.com/api/trails',
      body: 'x'.repeat(5000),
    },
  },
  {
    label: 'a response whose body is all non-ASCII',
    inner: {
      type: 'response',
      id: 5,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://alltrails.com/api/trails',
      // Three UTF-8 bytes per UTF-16 code unit, and a lone control
      // character that JSON escaping expands to six.
      body: '日'.repeat(2000) + '\u0001'.repeat(2000) + '😀'.repeat(500),
    },
  },
  {
    label: 'a storage read',
    inner: {
      type: 'response',
      id: 6,
      ok: true,
      op: 'read_local_storage',
      values: { 'auth."token"': 'a\\b\nc'.repeat(300) },
    },
  },
];

describe('sealedFrameWireBytes', () => {
  it.each(cases)('matches the sealed frame exactly: $label', async ({ inner }) => {
    const mcpId = 'alltrails-mcp:2.11.3:0123456789abcdef';
    const seq = 7;
    const sealed = await sealInnerFrame(key, mcpId, seq, inner);
    expect(sealedFrameWireBytes(mcpId, seq, inner)).toBe(utf8(JSON.stringify(sealed)));
  });

  it('is measured against the widest seq, so it never under-counts', () => {
    const mcpId = 'a:1:0123456789abcdef';
    const inner: InnerFrame = { type: 'ping' };
    // The caller cannot know the seq before it spends one, so the estimate is
    // taken at the widest a session could reach. It must therefore be at or
    // above what any real seq produces, never below.
    const widest = sealedFrameWireBytes(mcpId, Number.MAX_SAFE_INTEGER, inner);
    for (const seq of [1, 9, 10, 1000, 987_654_321]) {
      expect(sealedFrameWireBytes(mcpId, seq, inner)).toBeLessThanOrEqual(widest);
    }
  });
});

describe('base64Length', () => {
  it('matches toB64 for every remainder class', () => {
    for (const n of [0, 1, 2, 3, 4, 5, 16, 17, 18, 4096]) {
      expect(base64Length(n)).toBe(toB64(new Uint8Array(n)).length);
    }
  });
});

describe('MAX_FRAME_BYTES', () => {
  it('is above the AES-GCM tag and the envelope it has to carry', () => {
    expect(MAX_FRAME_BYTES).toBeGreaterThan(AES_GCM_TAG_BYTES);
    expect(sealedFrameWireBytes('a:1:0123456789abcdef', 1, { type: 'ping' })).toBeLessThan(
      MAX_FRAME_BYTES,
    );
  });
});
