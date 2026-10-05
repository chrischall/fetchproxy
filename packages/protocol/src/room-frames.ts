import { ROOM_FRAME_ACCEPTS, type RoomFrame, type RoomFrameType } from './frames.js';
import { ProtocolError, validateFrame } from './validate.js';

/**
 * Whether a room frame of `type` may cross a remote link whose EXTENSION hello
 * listed `accepts` (`HelloVersionPeek.accepts`, or a validated hello's
 * `accepts ?? []`). Exact string match against {@link ROOM_FRAME_ACCEPTS}; an
 * unknown type is never admitted.
 *
 * Both directions use it: a relay before sending `bridge-role` / `room-pong`
 * and before honouring `bridge-serve` / `room-ping`; an extension before
 * sending `bridge-serve` / `room-ping` on a link it did not advertise them on.
 */
export function roomFrameAccepted(accepts: readonly string[], type: RoomFrameType): boolean {
  if (!Object.prototype.hasOwnProperty.call(ROOM_FRAME_ACCEPTS, type)) return false;
  return accepts.includes(ROOM_FRAME_ACCEPTS[type]);
}

/**
 * The exact text to put on the wire for a room frame, or a `ProtocolError`
 * when the extension's hello did not list the frame's gating entry in
 * `accepts` — an older extension refuses the unknown type and closes the link
 * `1002`, so sending one ungated breaks the link rather than informing it.
 *
 * The frame is run through {@link validateFrame} first and the REBUILT copy is
 * serialised, so a caller cannot send what the receiver would refuse (an
 * over-long or control-character label, an extra member such as a token id)
 * and the heartbeat pair comes out as exactly `ROOM_PING_TEXT` /
 * `ROOM_PONG_TEXT`.
 */
export function roomFrameText(accepts: readonly string[], frame: RoomFrame): string {
  const type =
    typeof frame === 'object' && frame !== null ? (frame as { type?: unknown }).type : undefined;
  if (typeof type !== 'string' || !Object.prototype.hasOwnProperty.call(ROOM_FRAME_ACCEPTS, type)) {
    throw new ProtocolError(`room frame: unknown type ${JSON.stringify(type)}`);
  }
  const t = type as RoomFrameType;
  if (!roomFrameAccepted(accepts, t)) {
    throw new ProtocolError(
      `${t}: the extension's hello did not list ${JSON.stringify(ROOM_FRAME_ACCEPTS[t])} in accepts`,
    );
  }
  return JSON.stringify(validateFrame(frame));
}
