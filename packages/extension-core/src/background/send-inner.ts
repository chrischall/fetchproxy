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
 * The socket is now looked up rather than global: a sealed frame goes out on
 * the link this `mcpId`'s hello arrived on, and on no other. An id bound to no
 * link is not sendable — that is a session whose link dropped between the
 * request arriving and the answer being ready, and writing it to whichever
 * socket happened to be open would hand another bridge a response it never
 * asked for.
 */

import { sealInnerFrame, type InnerFrame } from '@fetchproxy/protocol';

import { state } from './state.js';
import { linkForMcp, sendOnLink } from './links.js';

export async function sendInner(mcpId: string, inner: InnerFrame): Promise<void> {
  if (!state.sessions) return;
  const entry = state.sessions.get(mcpId);
  const link = linkForMcp(mcpId);
  if (!entry || !link) return;
  const sealed = await sealInnerFrame(entry.sessionKey, mcpId, entry.nextOutboundSeq(), inner);
  sendOnLink(link, JSON.stringify(sealed));
}
