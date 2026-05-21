import { describe, it, expect } from 'vitest';
import { sealInnerFrame, openEncryptedFrame } from '../src/seal.js';
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
