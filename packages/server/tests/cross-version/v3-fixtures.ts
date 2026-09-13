/**
 * FROZEN protocol-v3 wire frames.
 * **Never regenerate these from the current source.**
 *
 * They were captured ONCE, on 2026-09-12, from the PUBLISHED
 * `@fetchproxy/protocol@2.11.3` and `@fetchproxy/server@2.11.3` installed from
 * npm into a throwaway directory — `buildServerHello` built the server hello,
 * `readySignaturePayload` + `ed25519Sign` produced the ready signature, and
 * v3's own `sealInnerFrame` (the one whose `aesGcmSeal` call passes no
 * additional data at all) produced the encrypted frame. Nothing below was
 * produced by anything in this repository.
 *
 * That is the whole point of the file, and it is not a stylistic preference.
 * A "v3 fixture" hand-built from today's `PROTOCOL_VERSION`, today's
 * `helloSignaturePayload` or today's `sealInnerFrame` is not a v3 fixture: it
 * is a tautology that keeps passing however far v4 drifts, because it drifts
 * with it. #222's own report records the shape of that failure from the other
 * side — 128 tests failed on the 2→3 break precisely BECAUSE the suite's
 * fixtures hand-built the old version, and each had to be moved onto the
 * shared payload function. This file is the deliberate opposite: one corpus
 * that is allowed to keep saying 3 forever, so a v4 end can be held to a real
 * v3 peer rather than to this repo's memory of one.
 *
 * `v3-fixtures.test.ts` beside this file pins the freeze itself: it asserts
 * these frames say 3 where this source says 4, that today's validator refuses
 * every one of them, that the ciphertext really does open with no AAD under
 * the recorded key, and — the check that makes "never regenerated" a property
 * rather than a comment — that this module's SOURCE contains no import at all.
 * An import is how the current `PROTOCOL_VERSION` would get in here.
 *
 * Adding to the corpus later: capture from a published tarball of the version
 * you are freezing, the same way, and paste the result. Do not touch what is
 * already here — a frozen byte that moves has stopped being evidence.
 *
 * The interfaces below are local and deliberately NOT the ones in
 * `@fetchproxy/protocol`: those describe v4, so typing a v3 frame with them
 * would either fail to compile or drag the fixture toward the current shape
 * on the next field the protocol gains.
 */

/** The protocol version every frame in this file carries. Not a re-export. */
export const V3_PROTOCOL_VERSION = 3;

/** v3's HKDF info label, recorded so a reader can check the derivation below. */
export const V3_HKDF_SESSION_INFO = 'fetchproxy/1.0.0/session';

/** Where these bytes came from, so the claim above is checkable. */
export const V3_CAPTURE = frozen({
  capturedOn: '2026-09-12',
  packages: ['@fetchproxy/protocol@2.11.3', '@fetchproxy/server@2.11.3'],
  installedFrom: 'npm',
  /** How the session key was derived — v3's derivation, stated in full. */
  keyDerivation:
    'HKDF-SHA256(ikm = X25519(mcpIdentityX25519Priv, extensionEphemeralPub), ' +
    'salt = serverHello.sessionNonce, info = "fetchproxy/1.0.0/session", 32 bytes)',
});

/**
 * v3's server hello. No `sessionPub` and no `answersExtNonce`: the MCP
 * contributed no ephemeral at all, which is the hole v4 exists to close, and
 * `sessionSig` therefore signs only `mcpId || sessionNonce`.
 */
export interface FrozenV3ServerHello {
  readonly type: 'hello';
  readonly protocolVersion: 3;
  readonly role: 'server';
  readonly mcpId: string;
  readonly serverName: string;
  readonly version: string;
  readonly domains: readonly string[];
  readonly capabilities: readonly string[];
  readonly identityX25519Pub: string;
  readonly identityEd25519Pub: string;
  readonly sessionNonce: string;
  readonly sessionSig: string;
  readonly accepts: readonly string[];
}

export const v3ServerHello: FrozenV3ServerHello = frozen({
  type: 'hello',
  protocolVersion: 3,
  role: 'server',
  mcpId: 'frozen-v3:2.11.3:a1b2c3d4e5f60718',
  serverName: 'frozen-v3',
  version: '2.11.3',
  domains: ['example.com'],
  capabilities: ['fetch'],
  identityX25519Pub: 'tE933jtOmlKWXFGBDRcyza6+5nlX9XhIOVYt7pZLRWk=',
  identityEd25519Pub: 'NGNhXinnmb9Vroogy1jk4S56R3t/2JBpmw/tJ0+/9PQ=',
  sessionNonce: 'gyoGvTXnFKQry6Vkun+bsPDeJDKj9Hn3gZgh3Sq28fU=',
  sessionSig:
    'hUYEcOcdkEU6suOF3hfF40wb9XkSdG/jKkUCcW7Vi3vOHixED6nhtbZgMM7WVE9J5XUc8txRg9RYB8Axq4phBA==',
  // 2.5.0's advertisement, kept because it is what makes this hello answerable:
  // a v4 extension refusing it consults `accepts` before sending
  // `hello-rejected`, so a fixture without it would prove the refusal is
  // silent rather than that it is delivered.
  accepts: ['extension-disconnected', 'hello-rejected'],
} as const);

/** v3's extension hello. Identical in shape to v4's but for the version. */
export interface FrozenV3ExtensionHello {
  readonly type: 'hello';
  readonly protocolVersion: 3;
  readonly role: 'extension';
  readonly platform: 'chrome';
  readonly extensionId: string;
  readonly version: string;
  readonly identityX25519Pub: string;
  readonly identityEd25519Pub: string;
  readonly sessionNonce: string;
}

export const v3ExtensionHello: FrozenV3ExtensionHello = frozen({
  type: 'hello',
  protocolVersion: 3,
  role: 'extension',
  platform: 'chrome',
  extensionId: 'frozenv3extensionidaaaaaaaaaaaaaa',
  version: '2.11.3',
  identityX25519Pub: 'Sh8gNiTRPMMJT94NcB+x1ku7ApmLXziLIwShPyLX4Hw=',
  identityEd25519Pub: 'WigFptqdOOBpNrPwzGXKD3QWR4P6ZPAlddg833rHxmw=',
  sessionNonce: 'Izxk+bTKe1RP1uBzwyTeBFr8duS24SdQPEjePwasXdA=',
} as const);

/**
 * v3's ready, answering {@link v3ServerHello} for {@link v3ExtensionHello}.
 *
 * No `mcpSessionPub`: under v3 there was no MCP ephemeral to name, so a server
 * could not tell a STALE ready from a forged one and answered both by closing.
 * `sessionSig` covers `mcpHelloNonce || extHelloNonce || extensionSessionPub`
 * — 2.0.0's payload, three fields where v4 signs four.
 */
export interface FrozenV3Ready {
  readonly type: 'ready';
  readonly mcpId: string;
  readonly extensionSessionPub: string;
  readonly sessionSig: string;
}

export const v3Ready: FrozenV3Ready = frozen({
  type: 'ready',
  mcpId: 'frozen-v3:2.11.3:a1b2c3d4e5f60718',
  extensionSessionPub: 'bn5f17FWQ2nANimJySPFaendWRvracKbRwsAA0+Yejk=',
  sessionSig:
    'JvM7gHkTM/RvOoeQMpHL4mjeQF3joCmJDNdiIJov02tOYM7XM+l438bzpZlIj6+oRfKsSaaXFwk80rvAdSAhAA==',
} as const);

/**
 * One encrypted frame, extension → MCP, sealed by v3's `sealInnerFrame` under
 * {@link V3_SESSION_KEY_B64}.
 *
 * The envelope is byte-identical in shape to v4's — same five fields, same
 * base64 — which is exactly why this fixture is worth having. What differs is
 * invisible: v3 sealed with NO additional data, so nothing binds this
 * ciphertext to the `mcpId`, the `seq` or the direction printed beside it. A
 * v4 receiver rejects it at the AEAD tag rather than at the schema, and
 * {@link V3_FRAME_INNER_JSON} is the control for that claim — its plaintext is
 * a perfectly valid v4 inner frame, so a rejection cannot be blamed on the
 * payload.
 */
export interface FrozenV3EncryptedFrame {
  readonly type: 'frame';
  readonly mcpId: string;
  readonly seq: number;
  readonly iv: string;
  readonly ciphertext: string;
}

export const v3Frame: FrozenV3EncryptedFrame = frozen({
  type: 'frame',
  mcpId: 'frozen-v3:2.11.3:a1b2c3d4e5f60718',
  seq: 1,
  iv: '8V6gNpS+mZlEkhBi',
  ciphertext: 'Rpr1wI9Z40KK4jlneg4u0bPIvUuyCSLiXbGJJA1EHg==',
} as const);

/**
 * The AES-256-GCM session key {@link v3Frame} was sealed under — the output of
 * v3's derivation, recorded in {@link V3_CAPTURE}.
 *
 * Frozen for the same reason the ciphertext is: without it the frame is an
 * opaque blob that no test can prove is genuine v3 output rather than 44
 * characters of base64. It is a throwaway key for a session that never existed
 * outside the capture, and it opens nothing else.
 */
export const V3_SESSION_KEY_B64 = 'bby10fAEXuEUOQwC7i7tWDcrYUx7g/OBgfYenzhsUYo=';

/** The exact plaintext {@link v3Frame} carries. */
export const V3_FRAME_INNER_JSON = '{"type":"pong"}';

/**
 * The pair code v3 derived for this pairing — the first four bytes of
 * `SHA256(mcpIdentityX25519Pub || extIdentityX25519Pub)` read as a big-endian
 * uint32, `mod 1_000_000`, formatted `XXX-XXX`.
 *
 * Six digits over two LONG-TERM public keys, which is L5 in one value: both
 * inputs are public and neither changes, so one offline grind produces a code
 * that stays usable against that MCP identity forever. v4's is eight digits
 * over a transcript, so today's validator refuses this one on its shape alone.
 */
export const V3_PAIR_CODE = '279-929';

/**
 * Deep-freeze, so one test cannot hand the next a mutated corpus. Local and
 * tiny for the reason at the top of the file: this module imports nothing.
 */
function frozen<T>(value: T): T {
  if (value !== null && typeof value === 'object') {
    for (const v of Object.values(value as Record<string, unknown>)) frozen(v);
    Object.freeze(value);
  }
  return value;
}
