import { describe, it, expect } from 'vitest';
import {
  PROTOCOL_VERSION,
  HKDF_SESSION_INFO,
  helloSignaturePayload,
  readySignaturePayload,
  transcriptHash,
  ANSWERS_NO_EXT_SESSION,
  answersNoExtSession,
} from '../src/frames.js';
import { sha256 } from '../src/crypto.js';
import { toHex, toB64, fromB64 } from '../src/encoding.js';

const enc = new TextEncoder();

/** `n` bytes of `fill`, so two inputs of the same shape are distinguishable. */
function bytes(fill: number, n: number): Uint8Array {
  return new Uint8Array(n).fill(fill);
}

function cat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

const MCP_ID = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';

describe('protocol version constants (v4)', () => {
  it('is protocol 4', () => {
    expect(PROTOCOL_VERSION).toBe(4);
  });

  it('derives session keys under a v4 info label', () => {
    // Moves with the version so a hypothetical key confusion across versions
    // yields different bytes rather than the same key under two rule sets.
    expect(HKDF_SESSION_INFO).toBe('fetchproxy/4.0.0/session');
  });
});

describe('helloSignaturePayload', () => {
  const nonce = bytes(0x11, 16);
  const sessionPub = bytes(0x22, 32);
  const answersExtNonce = bytes(0x33, 32);

  it('takes four arguments and is exactly utf8(mcpId) || sessionNonce || sessionPub || answersExtNonce', () => {
    expect(helloSignaturePayload.length).toBe(4);
    expect(helloSignaturePayload(MCP_ID, nonce, sessionPub, answersExtNonce)).toEqual(
      cat(enc.encode(MCP_ID), nonce, sessionPub, answersExtNonce),
    );
  });

  it('changes with the mcpId', () => {
    const a = toHex(helloSignaturePayload(MCP_ID, nonce, sessionPub, answersExtNonce));
    const b = toHex(
      helloSignaturePayload('resy-mcp:0.9.1:a3f7c91d2e8b4f56', nonce, sessionPub, answersExtNonce),
    );
    expect(a).not.toBe(b);
  });

  it('changes with the session nonce', () => {
    const a = toHex(helloSignaturePayload(MCP_ID, nonce, sessionPub, answersExtNonce));
    const b = toHex(helloSignaturePayload(MCP_ID, bytes(0x12, 16), sessionPub, answersExtNonce));
    expect(a).not.toBe(b);
  });

  it('changes with the session pub — the whole reason v4 widened it', () => {
    // Without this field a relay substitutes a `sessionPub` it holds the
    // private half of, the extension derives against the relay's key, and
    // forward secrecy is fiction.
    const a = toHex(helloSignaturePayload(MCP_ID, nonce, sessionPub, answersExtNonce));
    const b = toHex(helloSignaturePayload(MCP_ID, nonce, bytes(0x23, 32), answersExtNonce));
    expect(a).not.toBe(b);
  });

  it('changes with the extension nonce the hello answers', () => {
    // The echo the host's forwarding gate reads (§1a Rule B). Unsigned, it is
    // a field a relay re-points at whichever extension session it wants the
    // hello delivered to.
    const a = toHex(helloSignaturePayload(MCP_ID, nonce, sessionPub, answersExtNonce));
    const b = toHex(helloSignaturePayload(MCP_ID, nonce, sessionPub, bytes(0x34, 32)));
    expect(a).not.toBe(b);
  });

  it('distinguishes "answers nothing" from answering a real session', () => {
    // 32 zero bytes is a VALUE in the signed payload, not an absence of
    // bytes: `mcpId` is variable-length and first, so an omitted trailing
    // field would let two different (mcpId, answers) pairs concatenate to
    // the same signed message.
    const zeroes = bytes(0x00, 32);
    const a = toHex(helloSignaturePayload(MCP_ID, nonce, sessionPub, zeroes));
    const b = toHex(helloSignaturePayload(MCP_ID, nonce, sessionPub, answersExtNonce));
    expect(a).not.toBe(b);
    expect(helloSignaturePayload(MCP_ID, nonce, sessionPub, zeroes).length).toBe(
      enc.encode(MCP_ID).length + nonce.length + sessionPub.length + 32,
    );
  });

  it('does not confuse the session pub with the answered nonce — order is load-bearing', () => {
    // Both fields are 32 bytes and adjacent: the producer and the four
    // verifiers agree on which is which only because one function writes
    // both. Swapping them would still verify against itself.
    const a = toHex(helloSignaturePayload(MCP_ID, nonce, sessionPub, answersExtNonce));
    const b = toHex(helloSignaturePayload(MCP_ID, nonce, answersExtNonce, sessionPub));
    expect(a).not.toBe(b);
  });
});

describe('readySignaturePayload', () => {
  const mcpNonce = bytes(0x31, 16);
  const extNonce = bytes(0x41, 16);
  const extSessionPub = bytes(0x51, 32);
  const mcpSessionPub = bytes(0x61, 32);

  it('takes four arguments and is exactly their concatenation', () => {
    expect(readySignaturePayload.length).toBe(4);
    expect(readySignaturePayload(mcpNonce, extNonce, extSessionPub, mcpSessionPub)).toEqual(
      cat(mcpNonce, extNonce, extSessionPub, mcpSessionPub),
    );
  });

  it('changes with each of its four inputs', () => {
    const base = toHex(readySignaturePayload(mcpNonce, extNonce, extSessionPub, mcpSessionPub));
    expect(
      toHex(readySignaturePayload(bytes(0x32, 16), extNonce, extSessionPub, mcpSessionPub)),
    ).not.toBe(base);
    expect(
      toHex(readySignaturePayload(mcpNonce, bytes(0x42, 16), extSessionPub, mcpSessionPub)),
    ).not.toBe(base);
    expect(
      toHex(readySignaturePayload(mcpNonce, extNonce, bytes(0x52, 32), mcpSessionPub)),
    ).not.toBe(base);
    // The v4 addition: the MCP's ephemeral, so the transcript is bound
    // symmetrically and neither contribution can be substituted.
    expect(
      toHex(readySignaturePayload(mcpNonce, extNonce, extSessionPub, bytes(0x62, 32))),
    ).not.toBe(base);
  });
});

describe('transcriptHash', () => {
  const mcpNonce = bytes(0x71, 16);
  const extNonce = bytes(0x81, 16);
  const mcpSessionPub = bytes(0x91, 32);
  const extSessionPub = bytes(0xa1, 32);

  it('is SHA-256 over mcpNonce || extNonce || mcpSessionPub || extSessionPub', async () => {
    const got = await transcriptHash(mcpNonce, extNonce, mcpSessionPub, extSessionPub);
    const want = await sha256(cat(mcpNonce, extNonce, mcpSessionPub, extSessionPub));
    expect(toHex(got)).toBe(toHex(want));
    expect(got.length).toBe(32);
  });

  it('changes with each of its four inputs', async () => {
    const base = toHex(await transcriptHash(mcpNonce, extNonce, mcpSessionPub, extSessionPub));
    expect(
      toHex(await transcriptHash(bytes(0x72, 16), extNonce, mcpSessionPub, extSessionPub)),
    ).not.toBe(base);
    expect(
      toHex(await transcriptHash(mcpNonce, bytes(0x82, 16), mcpSessionPub, extSessionPub)),
    ).not.toBe(base);
    expect(
      toHex(await transcriptHash(mcpNonce, extNonce, bytes(0x92, 32), extSessionPub)),
    ).not.toBe(base);
    expect(
      toHex(await transcriptHash(mcpNonce, extNonce, mcpSessionPub, bytes(0xa2, 32))),
    ).not.toBe(base);
  });

  it('does not confuse the two ephemerals — order is load-bearing', async () => {
    // Both sides derive the same salt only if both concatenate in the same
    // order. Swapping them is a silent key divergence, so the ordering is
    // asserted rather than assumed.
    const a = toHex(await transcriptHash(mcpNonce, extNonce, mcpSessionPub, extSessionPub));
    const b = toHex(await transcriptHash(mcpNonce, extNonce, extSessionPub, mcpSessionPub));
    expect(a).not.toBe(b);
  });
});

describe('answers-no-extension-session ("answers nothing")', () => {
  it('is 32 zero bytes', () => {
    // Fixed-shape rather than absent, so that "this hello answers no
    // extension session" is a VALUE inside the signed payload. §1a.
    expect(ANSWERS_NO_EXT_SESSION.length).toBe(32);
    expect([...ANSWERS_NO_EXT_SESSION].every((b) => b === 0)).toBe(true);
  });

  it('recognises exactly that value', () => {
    expect(answersNoExtSession(toB64(ANSWERS_NO_EXT_SESSION))).toBe(true);
  });

  it('is false of a hundred CSPRNG nonces', () => {
    // The predicate's whole job is telling a registration hello apart from
    // one answering a live session, and a live session's nonce comes from a
    // CSPRNG. A hundred of them is a cheap proof that it never confuses the
    // two — which is what `host.ts`'s mirror gate depends on.
    for (let i = 0; i < 100; i++) {
      const nonce = new Uint8Array(32);
      (globalThis.crypto as Crypto).getRandomValues(nonce);
      expect(answersNoExtSession(toB64(nonce))).toBe(false);
    }
  });

  it('is false of a right-length value with one bit set, and of a wrong length', () => {
    const almost = new Uint8Array(32);
    almost[31] = 1;
    expect(answersNoExtSession(toB64(almost))).toBe(false);
    expect(answersNoExtSession(toB64(new Uint8Array(31)))).toBe(false);
    expect(answersNoExtSession(toB64(new Uint8Array(33)))).toBe(false);
  });

  it('answers false rather than throwing on a value it cannot decode', () => {
    // It is read off a frame, so a caller must never have to guard it: a
    // gate that throws here is a gate that takes the socket down instead of
    // withholding one frame. Fail CLOSED — "not a registration hello".
    expect(answersNoExtSession('not base64 at all!!')).toBe(false);
    expect(answersNoExtSession('')).toBe(false);
  });

  it('judges the BYTES, not the spelling', () => {
    // base64 of 32 bytes leaves two slack bits in the final character, so
    // more than one string decodes to 32 zeroes. The predicate decodes
    // rather than comparing strings, so a non-canonical spelling of the zero
    // value is still read as "answers nothing" rather than silently becoming
    // a hello the mirror gate withholds.
    const canonical = toB64(ANSWERS_NO_EXT_SESSION);
    const alternate = `${canonical.slice(0, 42)}B=`;
    expect(alternate).not.toBe(canonical);
    expect([...fromB64(alternate)].every((b) => b === 0)).toBe(true);
    expect(answersNoExtSession(alternate)).toBe(true);
  });
});
