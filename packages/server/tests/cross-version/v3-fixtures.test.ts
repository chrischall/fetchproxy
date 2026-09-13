import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  PROTOCOL_VERSION,
  aesGcmOpen,
  fromB64,
  openEncryptedFrameDetailed,
  peekHelloVersion,
  sealInnerFrame,
  sealedFrameWireBytes,
  validateFrame,
  validateInnerFrame,
  type EncryptedFrame,
  type InnerFrame,
} from '@fetchproxy/protocol';
import {
  V3_CAPTURE,
  V3_FRAME_INNER_JSON,
  V3_HKDF_SESSION_INFO,
  V3_PAIR_CODE,
  V3_PROTOCOL_VERSION,
  V3_SESSION_KEY_B64,
  v3ExtensionHello,
  v3Frame,
  v3Ready,
  v3ServerHello,
} from './v3-fixtures.js';

/**
 * The freeze itself, under test.
 *
 * `v3-fixtures.ts` is the one file in this repository whose value is that it
 * does NOT track the source beside it, so "frozen" has to be a property this
 * suite can fail on rather than a sentence in a header comment. Every
 * assertion here is about the corpus, not about the code that consumes it —
 * the refusals themselves are `refusal.test.ts`'s subject.
 *
 * The load-bearing one is the last: the fixture module's SOURCE contains no
 * import. An import of `@fetchproxy/protocol` is precisely how today's
 * `PROTOCOL_VERSION`, today's signature payload or today's `sealInnerFrame`
 * would get into a "v3" fixture and quietly turn this whole directory into a
 * test of v4 against itself.
 */
describe('the frozen v3 corpus', () => {
  it('says 3 where this source says 4', () => {
    expect(PROTOCOL_VERSION).toBe(4);
    expect(V3_PROTOCOL_VERSION).toBe(3);
    expect(V3_PROTOCOL_VERSION).not.toBe(PROTOCOL_VERSION);
    for (const hello of [v3ServerHello, v3ExtensionHello]) {
      expect(hello.protocolVersion).toBe(V3_PROTOCOL_VERSION);
    }
  });

  it('carries none of the four fields v4 added', () => {
    // The MCP ephemeral and the extension nonce it answers — the whole of the
    // forward-secrecy half of v4 — plus the ready's echo of that ephemeral.
    expect(v3ServerHello).not.toHaveProperty('sessionPub');
    expect(v3ServerHello).not.toHaveProperty('answersExtNonce');
    expect(v3Ready).not.toHaveProperty('mcpSessionPub');
    // And the frame's envelope is unchanged, which is the point of the fourth:
    // the AAD moved without moving a byte on the wire.
    expect(Object.keys(v3Frame).sort()).toEqual(
      ['ciphertext', 'iv', 'mcpId', 'seq', 'type'].sort(),
    );
  });

  it("today's validator refuses every frame in it", () => {
    for (const frame of [v3ServerHello, v3ExtensionHello, v3Ready]) {
      expect(() => validateFrame(frame)).toThrow();
    }
    // The pair code is refused on its SHAPE — six digits where v4 mints eight.
    expect(() =>
      validateFrame({ type: 'pair-pending', mcpId: v3ServerHello.mcpId, pairCode: V3_PAIR_CODE }),
    ).toThrow();
    // The encrypted frame is the exception, and deliberately so: its envelope
    // is valid v4, so what rejects it is the AEAD tag below and not the schema.
    expect(() => validateFrame(v3Frame)).not.toThrow();
  });

  it('is still answerable: a refused hello yields its version and id', () => {
    const server = peekHelloVersion(v3ServerHello);
    expect(server).toEqual({
      protocolVersion: 3,
      mcpId: 'frozen-v3:2.11.3:a1b2c3d4e5f60718',
      accepts: ['extension-disconnected', 'hello-rejected'],
    });
    expect(peekHelloVersion(v3ExtensionHello)).toEqual({
      protocolVersion: 3,
      mcpId: null,
      accepts: [],
    });
  });

  it('holds a genuine v3 ciphertext: it opens under the recorded key with no AAD', async () => {
    const pt = await aesGcmOpen(
      fromB64(V3_SESSION_KEY_B64),
      fromB64(v3Frame.iv),
      fromB64(v3Frame.ciphertext),
      // v3's `sealInnerFrame` passed no additional data at all, and GCM treats
      // absent and empty alike. Opening under this and nothing else is what
      // makes the ciphertext evidence rather than 44 characters of base64.
      new Uint8Array(0),
    );
    expect(new TextDecoder().decode(pt)).toBe(V3_FRAME_INNER_JSON);
    // The control for the next assertion: the plaintext is a valid v4 inner
    // frame, so a v4 receiver's rejection cannot be blamed on the payload.
    expect(() => validateInnerFrame(JSON.parse(V3_FRAME_INNER_JSON))).not.toThrow();
  });

  it('is rejected by a v4 receiver at the tag, not at the schema', async () => {
    const result = await openEncryptedFrameDetailed(
      fromB64(V3_SESSION_KEY_B64),
      v3Frame as EncryptedFrame,
      'e2s',
    );
    expect(result.stage).toBe('decrypt-failed');
  });

  it('is the same size on the wire as v4: the AAD is authenticated, never sent', async () => {
    // The header of `packages/protocol/src/frames.ts` states this as part of
    // the v4 break — the additional data moved without moving a byte, so
    // `MAX_FRAME_BYTES` is not the AAD's to move. Stated in a comment it is
    // an assertion about GCM; measured against a frame sealed by 2.11.3, with
    // the same plaintext, mcpId and seq, it is evidence. A future refactor
    // that put the direction (or the AAD itself) on the envelope to "make it
    // checkable" would add bytes to every frame and shift the derived cap
    // under it; this is the test that fails when it does.
    const inner = JSON.parse(V3_FRAME_INNER_JSON) as InnerFrame;
    const v4Frame = await sealInnerFrame(
      fromB64(V3_SESSION_KEY_B64),
      v3Frame.mcpId,
      v3Frame.seq,
      inner,
      // The fixture is extension → MCP, and under v4 the direction is an AAD
      // input rather than a field, which is the whole point being measured.
      'e2s',
    );
    const wire = (frame: unknown) => new TextEncoder().encode(JSON.stringify(frame)).length;
    expect(wire(v4Frame)).toBe(wire(v3Frame));
    // And the estimate the producing-end caps are stated in agrees with both,
    // so the number `MAX_FRAME_BYTES` is compared against did not move either.
    expect(sealedFrameWireBytes(v3Frame.mcpId, v3Frame.seq, inner)).toBe(wire(v3Frame));
  });

  it('records where it came from, and it is not this repository', () => {
    expect(V3_CAPTURE.packages).toEqual([
      '@fetchproxy/protocol@2.11.3',
      '@fetchproxy/server@2.11.3',
    ]);
    expect(V3_CAPTURE.installedFrom).toBe('npm');
    expect(V3_HKDF_SESSION_INFO).toBe('fetchproxy/1.0.0/session');
  });

  it('imports nothing — which is what keeps it from being regenerated', () => {
    const source = readFileSync(new URL('./v3-fixtures.ts', import.meta.url), 'utf8');
    // Not a lint preference. Any import here is a path by which the current
    // PROTOCOL_VERSION, signature payload or sealer reaches a file whose only
    // value is that it predates them.
    expect(source).not.toMatch(/^\s*import\s/m);
    expect(source).not.toMatch(/\brequire\s*\(/);
    expect(source).toMatch(/Never regenerate these from the current source/);
  });
});
