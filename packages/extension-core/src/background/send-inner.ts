/**
 * `sendInner` — seal one inner frame for an established MCP session and
 * write it to the host socket. Moved verbatim out of `background.ts`.
 *
 * This lives in its own module, depending on nothing but `state.ts`, so the
 * transport (`socket.ts`) and the request handlers can both reach it without
 * the handlers importing the socket: handlers → send-inner is a downward
 * edge, where handlers → socket would have closed a cycle back through the
 * frame dispatch.
 *
 * Crypto-critical: `entry.nextOutboundSeq()` advances the per-session AEAD
 * counter, and that counter is authenticated input to `sealInnerFrame`. The
 * number of invocations and the single-instance-ness of `SessionKeys` are
 * both load-bearing, so this must stay the one and only sender.
 *
 * Being the one and only sender is also why the wire-size cap lives here: it
 * is the single point every verb's answer passes through, so one check binds
 * `fetch` — whose body cap counts UTF-16 code units rather than bytes, and so
 * bounds nothing on the wire — and equally `read_indexed_db`,
 * `read_local_storage`, `read_session_storage` and `read_dom`, none of which
 * has a size cap of its own at all.
 *
 * The socket is now looked up rather than global: a sealed frame goes out on
 * the link this `mcpId`'s hello arrived on, and on no other. An id bound to no
 * link is not sendable — that is a session whose link dropped between the
 * request arriving and the answer being ready, and writing it to whichever
 * socket happened to be open would hand another bridge a response it never
 * asked for.
 */

import {
  MAX_FRAME_BYTES,
  sealInnerFrame,
  sealedFrameWireBytes,
  type InnerFrame,
} from '@fetchproxy/protocol';

import { state } from './state.js';
import { linkForMcp, sendOnLink } from './links.js';

/**
 * What to send in place of a frame that will not fit.
 *
 * `ws` answers a payload over its `maxPayload` by CLOSING the connection with
 * 1009, and on the concentrator the extension holds ONE connection for every
 * MCP on the host — so letting an oversize frame go would take every sibling
 * MCP's bridge down in order to report that one request's answer was too big.
 * The refusal therefore happens here, while the frame still has a request id
 * to attach it to: that one call fails with a reason it can act on, the
 * socket is untouched, and no other MCP on it notices.
 *
 * Only a `response` can realistically be oversize (a `ping`/`pong` is a few
 * bytes), and only a response carries an id to answer. Anything else returns
 * null and is dropped with the log line — the same outcome an unsendable
 * frame already had.
 */
function refusalFor(inner: InnerFrame, wireBytes: number): InnerFrame | null {
  if (inner.type !== 'response') return null;
  const error =
    `response too large for one bridge frame: ${wireBytes} bytes on the wire, ` +
    `cap ${MAX_FRAME_BYTES}`;
  // The op echo survives whichever kind of response was refused: an `ok: true`
  // one always carries an op, an `ok: false` one carries it when the failure
  // was op-specific. Dropping it on the second would tell the peer less than
  // the frame this stands in for did.
  const op = inner.op;
  return op === undefined
    ? { type: 'response', id: inner.id, ok: false, error }
    : { type: 'response', id: inner.id, ok: false, op, error };
}

export async function sendInner(mcpId: string, inner: InnerFrame): Promise<void> {
  if (!state.sessions) return;
  const entry = state.sessions.get(mcpId);
  const link = linkForMcp(mcpId);
  if (!entry || !link) return;
  // Measured BEFORE sealing, so an oversize frame is never encrypted and
  // never spends a seq: the refusal that replaces it takes the seq the
  // original would have had, leaving no gap for the other end to read as a
  // dropped frame. `Number.MAX_SAFE_INTEGER` stands in for the seq not yet
  // claimed — it is the widest this session could ever reach, so the
  // measurement is at or above the frame that actually goes out, never below.
  const wireBytes = sealedFrameWireBytes(mcpId, Number.MAX_SAFE_INTEGER, inner);
  let toSend = inner;
  if (wireBytes > MAX_FRAME_BYTES) {
    console.error(
      `[fetchproxy] refusing to send a ${wireBytes}-byte frame for ${mcpId} ` +
        `(cap ${MAX_FRAME_BYTES}); the request is failed, the bridge is not`,
    );
    const refusal = refusalFor(inner, wireBytes);
    if (!refusal) return;
    toSend = refusal;
  }
  const sealed = await sealInnerFrame(entry.sessionKey, mcpId, entry.nextOutboundSeq(), toSend);
  sendOnLink(link, JSON.stringify(sealed));
}
