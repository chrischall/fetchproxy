import { describe, it, expect } from 'vitest';
import {
  sealInnerFrame,
  openEncryptedFrame,
  openEncryptedFrameDetailed,
  sealedFrameWireBytes,
} from '../src/seal.js';
import { frameAad } from '../src/frames.js';
import type { InnerFrame, EncryptedFrame, Direction } from '../src/frames.js';

describe('seal/open', () => {
  const key = new Uint8Array(32).fill(7);
  const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';

  it('round-trips a ping frame', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner, 's2e');
    expect(sealed.type).toBe('frame');
    expect(sealed.mcpId).toBe(mcpId);
    expect(sealed.seq).toBe(1);
    const opened = await openEncryptedFrame(key, sealed, 's2e');
    expect(opened).toEqual(inner);
  });

  it('round-trips a request frame', async () => {
    const inner: InnerFrame = {
      type: 'request',
      id: 42,
      op: 'fetch',
      init: { url: 'https://x.com/y', method: 'GET', tabUrl: 'https://x.com/' },
    };
    const sealed = await sealInnerFrame(key, mcpId, 5, inner, 's2e');
    const opened = await openEncryptedFrame(key, sealed, 's2e');
    expect(opened).toEqual(inner);
  });

  it('round-trips a response (ok=true) frame', async () => {
    const inner: InnerFrame = {
      type: 'response',
      id: 99,
      ok: true,
      status: 200,
      url: 'https://x.com/y',
      body: '{"data":1}',
    };
    const sealed = await sealInnerFrame(key, mcpId, 3, inner, 's2e');
    const opened = await openEncryptedFrame(key, sealed, 's2e');
    expect(opened).toEqual(inner);
  });

  it('rejects ciphertext encrypted under a different key', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner, 's2e');
    const wrongKey = new Uint8Array(32).fill(8);
    await expect(openEncryptedFrame(wrongKey, sealed, 's2e')).rejects.toThrow();
  });

  it('rejects tampered ciphertext', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner, 's2e');
    const bytes = Buffer.from(sealed.ciphertext, 'base64');
    bytes[0] = (bytes[0] ?? 0) ^ 1;
    const bad: EncryptedFrame = { ...sealed, ciphertext: bytes.toString('base64') };
    await expect(openEncryptedFrame(key, bad, 's2e')).rejects.toThrow();
  });

  it('uses random iv each call', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const a = await sealInnerFrame(key, mcpId, 1, inner, 's2e');
    const b = await sealInnerFrame(key, mcpId, 1, inner, 's2e');
    expect(a.iv).not.toBe(b.iv);
  });

  it('iv is 12 bytes (16 base64 chars + padding) — standard AES-GCM nonce', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner, 's2e');
    const ivBytes = Buffer.from(sealed.iv, 'base64');
    expect(ivBytes.length).toBe(12);
  });
});

describe('openEncryptedFrameDetailed', () => {
  const key = new Uint8Array(32).fill(7);
  const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';

  // Encrypts an ARBITRARY plaintext value (bypassing sealInnerFrame's
  // InnerFrame typing) so tests can produce ciphertext that decrypts fine
  // but whose plaintext is malformed JSON or fails schema validation —
  // exactly the "decrypted OK, but the payload is bad" case this function
  // exists to distinguish from a genuine decrypt failure.
  async function sealArbitrary(plaintext: string): Promise<EncryptedFrame> {
    const { aesGcmSeal } = await import('../src/crypto.js');
    const enc = new TextEncoder();
    const iv = new Uint8Array(12).fill(3);
    const ct = await aesGcmSeal(key, iv, enc.encode(plaintext), frameAad(mcpId, 1, 's2e'));
    const { toB64 } = await import('../src/encoding.js');
    return { type: 'frame', mcpId, seq: 1, iv: toB64(iv), ciphertext: toB64(ct) };
  }

  it('returns stage "ok" for a valid frame', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner, 's2e');
    const result = await openEncryptedFrameDetailed(key, sealed, 's2e');
    expect(result).toEqual({ stage: 'ok', inner });
  });

  it('returns stage "decrypt-failed" for the wrong session key — no recoveredId possible', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner, 's2e');
    const wrongKey = new Uint8Array(32).fill(8);
    const result = await openEncryptedFrameDetailed(wrongKey, sealed, 's2e');
    expect(result.stage).toBe('decrypt-failed');
  });

  it('returns stage "decrypt-failed" (not an uncaught throw) for an iv that is structurally-valid-but-undecodable base64', async () => {
    // Regression: BASE64_RE (the structural frame validator) doesn't
    // enforce a length multiple of 4, so a value like "A" passes
    // validateFrame but atob() still throws on it. Before this fix, the
    // two fromB64 calls sat OUTSIDE every try in
    // openEncryptedFrameDetailed, so this threw out of a function
    // documented as "never throws" — with no stage assigned at all.
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner, 's2e');
    const bad: EncryptedFrame = { ...sealed, iv: 'A' };
    const result = await openEncryptedFrameDetailed(key, bad, 's2e');
    expect(result.stage).toBe('decrypt-failed');
  });

  it('returns stage "decrypt-failed" for tampered ciphertext', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner, 's2e');
    const bytes = Buffer.from(sealed.ciphertext, 'base64');
    bytes[0] = (bytes[0] ?? 0) ^ 1;
    const bad: EncryptedFrame = { ...sealed, ciphertext: bytes.toString('base64') };
    const result = await openEncryptedFrameDetailed(key, bad, 's2e');
    expect(result.stage).toBe('decrypt-failed');
  });

  it('returns stage "validation-failed" with a recovered id for a schema violation (e.g. download bytes:-1)', async () => {
    // Decrypts fine (real key, untampered) — this is the "current, live
    // peer sent something that fails validation" case, distinct from a
    // stale-key symptom. The response's `id` must still be recoverable so
    // the caller can fail just that one pending call.
    const malformed = JSON.stringify({
      type: 'response',
      id: 42,
      ok: true,
      op: 'download',
      value: { path: '/tmp/streamed.bin', bytes: -1 },
    });
    const sealed = await sealArbitrary(malformed);
    const result = await openEncryptedFrameDetailed(key, sealed, 's2e');
    expect(result.stage).toBe('validation-failed');
    expect((result as { recoveredId?: number }).recoveredId).toBe(42);
  });

  it('returns stage "validation-failed" with recoveredId undefined when the JSON has no numeric id', async () => {
    const sealed = await sealArbitrary(JSON.stringify({ type: 'response', ok: true }));
    const result = await openEncryptedFrameDetailed(key, sealed, 's2e');
    expect(result.stage).toBe('validation-failed');
    expect((result as { recoveredId?: number }).recoveredId).toBeUndefined();
  });

  it('returns stage "validation-failed" with recoveredId undefined when the plaintext is not even valid JSON', async () => {
    const sealed = await sealArbitrary('not json at all {{{');
    const result = await openEncryptedFrameDetailed(key, sealed, 's2e');
    expect(result.stage).toBe('validation-failed');
    expect((result as { recoveredId?: number }).recoveredId).toBeUndefined();
  });

  it('returns stage "validation-failed" with recoveredId undefined when the JSON top level is an array', async () => {
    const sealed = await sealArbitrary(JSON.stringify([{ id: 1 }]));
    const result = await openEncryptedFrameDetailed(key, sealed, 's2e');
    expect(result.stage).toBe('validation-failed');
    expect((result as { recoveredId?: number }).recoveredId).toBeUndefined();
  });
});

/**
 * v4's AAD. `mcpId` and `seq` ride on the ENVELOPE, outside the ciphertext,
 * so under v3 a party in the path could replay a recorded frame under a
 * bumped counter, re-file one under another MCP's id, or reflect one back
 * down the other direction, and the tag still verified. Binding the triple
 * as additional data makes each of those a tag failure instead.
 */
describe('frameAad', () => {
  const decode = (a: Uint8Array) => new TextDecoder().decode(a);

  it('is the exact NUL-separated encoding', () => {
    expect(decode(frameAad('opentable-mcp:0.9.1:a3f7c91d2e8b4f56', 7, 's2e'))).toBe(
      'fetchproxy/4/frame\u0000opentable-mcp:0.9.1:a3f7c91d2e8b4f56\u00007\u0000s2e',
    );
  });

  it('changes with each of its three inputs', () => {
    const base = decode(frameAad('a-mcp:1.0.0:0123456789abcdef', 7, 's2e'));
    expect(decode(frameAad('b-mcp:1.0.0:0123456789abcdef', 7, 's2e'))).not.toBe(base);
    expect(decode(frameAad('a-mcp:1.0.0:0123456789abcdef', 8, 's2e'))).not.toBe(base);
    expect(decode(frameAad('a-mcp:1.0.0:0123456789abcdef', 7, 'e2s'))).not.toBe(base);
  });

  it('is unambiguous: two different triples cannot concatenate to one string', () => {
    // Plain concatenation would make (seq 23, 's2e') and (seq 2, '3s2e') the
    // SAME authenticated bytes, which is how an AAD quietly stops binding
    // what it claims to. `ID_RE` excludes NUL and `seq` is rendered decimal,
    // so no value of one field can spell the boundary of another.
    expect(decode(frameAad('a:1:0123456789abcdef', 23, 's2e'))).not.toBe(
      decode(frameAad('a:1:0123456789abcdef', 2, '3s2e' as Direction)),
    );
  });
});

describe('the AAD binds a frame to its session, its ordinal and its direction', () => {
  const key = new Uint8Array(32).fill(7);
  const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';
  const inner: InnerFrame = { type: 'ping' };

  it('opens under the same (mcpId, seq, direction) triple', async () => {
    const sealed = await sealInnerFrame(key, mcpId, 9, inner, 's2e');
    expect(await openEncryptedFrame(key, sealed, 's2e')).toEqual(inner);
  });

  // Each of the three below must fail at `decrypt-failed`, never at
  // `validation-failed`: the later stage would mean the GCM tag PASSED and
  // only the plaintext was rejected, i.e. the AAD was not actually binding.
  it('fails to open under a bumped seq — the replay the counter alone could not stop', async () => {
    const sealed = await sealInnerFrame(key, mcpId, 9, inner, 's2e');
    const replayed: EncryptedFrame = { ...sealed, seq: sealed.seq + 1 };
    const result = await openEncryptedFrameDetailed(key, replayed, 's2e');
    expect(result.stage).toBe('decrypt-failed');
  });

  it('fails to open under another mcpId', async () => {
    const sealed = await sealInnerFrame(key, mcpId, 9, inner, 's2e');
    const refiled: EncryptedFrame = { ...sealed, mcpId: 'other-mcp:0.9.1:a3f7c91d2e8b4f56' };
    const result = await openEncryptedFrameDetailed(key, refiled, 's2e');
    expect(result.stage).toBe('decrypt-failed');
  });

  it('fails to open under the other direction — a reflected frame', async () => {
    const sealed = await sealInnerFrame(key, mcpId, 9, inner, 's2e');
    const result = await openEncryptedFrameDetailed(key, sealed, 'e2s');
    expect(result.stage).toBe('decrypt-failed');
  });

  it('throws rather than returning junk when openEncryptedFrame is given the wrong direction', async () => {
    const sealed = await sealInnerFrame(key, mcpId, 9, inner, 'e2s');
    await expect(openEncryptedFrame(key, sealed, 's2e')).rejects.toThrow();
  });
});

describe('sealedFrameWireBytes is untouched by the AAD', () => {
  const key = new Uint8Array(32).fill(7);
  const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';
  const utf8 = (s: string) => new TextEncoder().encode(s).length;

  // GCM's additional data is AUTHENTICATED, not transmitted, so v4 does not
  // move the wire size by a byte. These are the numbers this function
  // returned for these two frames BEFORE the AAD landed, frozen here so
  // nobody "fixes" the measurement — or `MAX_FRAME_BYTES`, which is derived
  // from it — on the belief that the AAD has to be paid for.
  const response: InnerFrame = {
    type: 'response',
    id: 4,
    ok: true,
    op: 'fetch',
    status: 200,
    url: 'https://alltrails.com/api/trails',
    body: 'x'.repeat(5000),
  };

  it('returns the same number it returned before the AAD', () => {
    expect(sealedFrameWireBytes(mcpId, 1, { type: 'ping' })).toBe(155);
    expect(sealedFrameWireBytes(mcpId, 7, response)).toBe(6951);
  });

  it("still equals a sealed frame's JSON.stringify length, in both directions", async () => {
    for (const direction of ['s2e', 'e2s'] as Direction[]) {
      const ping = await sealInnerFrame(key, mcpId, 1, { type: 'ping' }, direction);
      expect(sealedFrameWireBytes(mcpId, 1, { type: 'ping' })).toBe(utf8(JSON.stringify(ping)));
      const sealed = await sealInnerFrame(key, mcpId, 7, response, direction);
      expect(sealedFrameWireBytes(mcpId, 7, response)).toBe(utf8(JSON.stringify(sealed)));
    }
  });
});
