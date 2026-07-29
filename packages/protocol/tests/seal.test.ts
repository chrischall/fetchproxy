import { describe, it, expect } from 'vitest';
import { sealInnerFrame, openEncryptedFrame, openEncryptedFrameDetailed } from '../src/seal.js';
import type { InnerFrame, EncryptedFrame } from '../src/frames.js';

describe('seal/open', () => {
  const key = new Uint8Array(32).fill(7);
  const mcpId = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';

  it('round-trips a ping frame', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner);
    expect(sealed.type).toBe('frame');
    expect(sealed.mcpId).toBe(mcpId);
    expect(sealed.seq).toBe(1);
    const opened = await openEncryptedFrame(key, sealed);
    expect(opened).toEqual(inner);
  });

  it('round-trips a request frame', async () => {
    const inner: InnerFrame = {
      type: 'request',
      id: 42,
      op: 'fetch',
      init: { url: 'https://x.com/y', method: 'GET', tabUrl: 'https://x.com/' },
    };
    const sealed = await sealInnerFrame(key, mcpId, 5, inner);
    const opened = await openEncryptedFrame(key, sealed);
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
    const sealed = await sealInnerFrame(key, mcpId, 3, inner);
    const opened = await openEncryptedFrame(key, sealed);
    expect(opened).toEqual(inner);
  });

  it('rejects ciphertext encrypted under a different key', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner);
    const wrongKey = new Uint8Array(32).fill(8);
    await expect(openEncryptedFrame(wrongKey, sealed)).rejects.toThrow();
  });

  it('rejects tampered ciphertext', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner);
    const bytes = Buffer.from(sealed.ciphertext, 'base64');
    bytes[0] = (bytes[0] ?? 0) ^ 1;
    const bad: EncryptedFrame = { ...sealed, ciphertext: bytes.toString('base64') };
    await expect(openEncryptedFrame(key, bad)).rejects.toThrow();
  });

  it('uses random iv each call', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const a = await sealInnerFrame(key, mcpId, 1, inner);
    const b = await sealInnerFrame(key, mcpId, 1, inner);
    expect(a.iv).not.toBe(b.iv);
  });

  it('iv is 12 bytes (16 base64 chars + padding) — standard AES-GCM nonce', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner);
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
    const ct = await aesGcmSeal(key, iv, enc.encode(plaintext));
    const { toB64 } = await import('../src/encoding.js');
    return { type: 'frame', mcpId, seq: 1, iv: toB64(iv), ciphertext: toB64(ct) };
  }

  it('returns stage "ok" for a valid frame', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner);
    const result = await openEncryptedFrameDetailed(key, sealed);
    expect(result).toEqual({ stage: 'ok', inner });
  });

  it('returns stage "decrypt-failed" for the wrong session key — no recoveredId possible', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner);
    const wrongKey = new Uint8Array(32).fill(8);
    const result = await openEncryptedFrameDetailed(wrongKey, sealed);
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
    const sealed = await sealInnerFrame(key, mcpId, 1, inner);
    const bad: EncryptedFrame = { ...sealed, iv: 'A' };
    const result = await openEncryptedFrameDetailed(key, bad);
    expect(result.stage).toBe('decrypt-failed');
  });

  it('returns stage "decrypt-failed" for tampered ciphertext', async () => {
    const inner: InnerFrame = { type: 'ping' };
    const sealed = await sealInnerFrame(key, mcpId, 1, inner);
    const bytes = Buffer.from(sealed.ciphertext, 'base64');
    bytes[0] = (bytes[0] ?? 0) ^ 1;
    const bad: EncryptedFrame = { ...sealed, ciphertext: bytes.toString('base64') };
    const result = await openEncryptedFrameDetailed(key, bad);
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
    const result = await openEncryptedFrameDetailed(key, sealed);
    expect(result.stage).toBe('validation-failed');
    expect((result as { recoveredId?: number }).recoveredId).toBe(42);
  });

  it('returns stage "validation-failed" with recoveredId undefined when the JSON has no numeric id', async () => {
    const sealed = await sealArbitrary(JSON.stringify({ type: 'response', ok: true }));
    const result = await openEncryptedFrameDetailed(key, sealed);
    expect(result.stage).toBe('validation-failed');
    expect((result as { recoveredId?: number }).recoveredId).toBeUndefined();
  });

  it('returns stage "validation-failed" with recoveredId undefined when the plaintext is not even valid JSON', async () => {
    const sealed = await sealArbitrary('not json at all {{{');
    const result = await openEncryptedFrameDetailed(key, sealed);
    expect(result.stage).toBe('validation-failed');
    expect((result as { recoveredId?: number }).recoveredId).toBeUndefined();
  });

  it('returns stage "validation-failed" with recoveredId undefined when the JSON top level is an array', async () => {
    const sealed = await sealArbitrary(JSON.stringify([{ id: 1 }]));
    const result = await openEncryptedFrameDetailed(key, sealed);
    expect(result.stage).toBe('validation-failed');
    expect((result as { recoveredId?: number }).recoveredId).toBeUndefined();
  });
});
