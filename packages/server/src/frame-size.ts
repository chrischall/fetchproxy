/**
 * The MCP side's producer-side frame-size gate — the mirror of the
 * extension's in `background/send-inner.ts`, and here for the same reason.
 *
 * `ws` answers a payload over its `maxPayload` by CLOSING the socket with
 * 1009. On the concentrator that socket is shared: the host's is the ONE
 * connection every peer's traffic crosses, and a peer's is its only link to
 * the host. So an oversize frame leaving this end would report "that request
 * was too big" by taking the bridge down for every MCP on it — the exact
 * failure `MAX_FRAME_BYTES` exists to make impossible, left open on the
 * outbound direction because only the extension measured.
 *
 * It is a per-request refusal instead: the caller's own `await` throws with
 * the size and the cap, the socket is untouched, and no sibling MCP notices.
 * The measurement happens before a seq is claimed, so a refused frame spends
 * nothing and leaves no gap in the sequence for the far end to read as a
 * dropped frame.
 *
 * Returns the plaintext so the caller can hand it straight to
 * `sealInnerFrame` — the bytes measured ARE the bytes encrypted, and the
 * serialisation is paid for once.
 */

import {
  MAX_FRAME_BYTES,
  encodeInnerFrame,
  sealedFrameWireBytes,
  type InnerFrame,
} from '@fetchproxy/protocol';

export function encodeOutboundInnerFrame(mcpId: string, inner: InnerFrame): Uint8Array {
  const plaintext = encodeInnerFrame(inner);
  // `Number.MAX_SAFE_INTEGER` stands in for the seq not yet claimed: it is the
  // widest decimal this session could ever reach, so the measurement is at or
  // above the frame that actually goes out and never below it.
  const wireBytes = sealedFrameWireBytes(mcpId, Number.MAX_SAFE_INTEGER, plaintext);
  if (wireBytes > MAX_FRAME_BYTES) {
    throw new Error(
      `fetchproxy: this request is too large for one bridge frame: ${wireBytes} bytes ` +
        `on the wire, cap ${MAX_FRAME_BYTES}. The request is refused; the bridge is not ` +
        `closed, so other calls and other MCPs on it are unaffected.`,
    );
  }
  return plaintext;
}
