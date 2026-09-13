import {
  ANSWERS_NO_EXT_SESSION,
  generateX25519,
  fromB64,
  type HelloFrameFromServer,
} from '@fetchproxy/protocol';
import { buildServerHello, type BuildServerHelloOpts } from '../../src/build-server-hello.js';

/**
 * Synthesise a peer's hello for a test that stands in for a peer process.
 *
 * Exists because v4 made `sessionPub` and `answersExtNonce` required, and a
 * test that spells its own keypair at each call site is a test that will spell
 * the wrong `answersExtNonce` somewhere. Two shapes, and which one a test
 * wants is the whole of §1a's gate:
 *
 *  - a REGISTRATION hello (the default) echoes 32 zero bytes: at dial the peer
 *    has been told of no extension session, and the host must NOT forward such
 *    a hello to the extension but MUST hand the peer the cached extension
 *    hello in answer to it;
 *  - a hello that ANSWERS an extension session (`answersExtNonce` given) is
 *    the re-hello the host forwards and answers with nothing.
 *
 * The private half is discarded: no test holds it, because in production only
 * the peer process does. The public half rides on the returned frame.
 */
export async function buildTestPeerHello(
  opts: Omit<BuildServerHelloOpts, 'sessionPub' | 'answersExtNonce'> & {
    /** Raw 32 bytes, or the base64 off an extension hello. */
    answersExtNonce?: Uint8Array | string;
  },
): Promise<HelloFrameFromServer> {
  const { answersExtNonce, ...rest } = opts;
  const kp = await generateX25519();
  const echo =
    answersExtNonce === undefined
      ? ANSWERS_NO_EXT_SESSION
      : typeof answersExtNonce === 'string'
        ? fromB64(answersExtNonce)
        : answersExtNonce;
  return buildServerHello({
    ...rest,
    sessionPub: kp.publicKey,
    answersExtNonce: echo,
  });
}
