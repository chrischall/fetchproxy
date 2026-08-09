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
 */

import { sealInnerFrame, type InnerFrame } from '@fetchproxy/protocol';

import { state } from './state.js';

export async function sendInner(mcpId: string, inner: InnerFrame): Promise<void> {
  if (!state.sessions) return;
  const entry = state.sessions.get(mcpId);
  if (!entry || !state.ws || state.ws.readyState !== WebSocket.OPEN) return;
  const sealed = await sealInnerFrame(entry.sessionKey, mcpId, entry.nextOutboundSeq(), inner);
  state.ws.send(JSON.stringify(sealed));
}
