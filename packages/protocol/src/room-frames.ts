import { ROOM_FRAME_ACCEPTS, type Frame, type RoomFrame, type RoomFrameType } from './frames.js';
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
 * The deepest a room frame nests (`bridge-role` → `serving` → `label` is 2).
 * A snapshot deeper than this is refused rather than followed, so a cyclic
 * object cannot overflow the stack.
 */
const ROOM_FRAME_SNAPSHOT_DEPTH = 4;

/**
 * A plain-data copy of `value`: every own enumerable member is read exactly
 * once (`Object.keys`, then one `[[Get]]` each), and the copy has no
 * accessors, no prototype tricks and no `toJSON`. Everything after this works
 * on the copy only, so a getter or a Proxy in the caller's code has no
 * second read to answer differently.
 */
function snapshot(value: unknown, depth: number): unknown {
  if (value === null || typeof value !== 'object') return value;
  if (depth > ROOM_FRAME_SNAPSHOT_DEPTH) {
    throw new ProtocolError('room frame: nested too deeply');
  }
  if (Array.isArray(value)) {
    const len = value.length;
    const out: unknown[] = [];
    for (let i = 0; i < len; i++) out.push(snapshot(value[i], depth + 1));
    return out;
  }
  const src = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const k of Object.keys(src)) {
    // defineProperty, not assignment: an own `__proto__` key stays a plain
    // member (and is then refused as an unexpected field).
    Object.defineProperty(out, k, {
      value: snapshot(src[k], depth + 1),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

/**
 * The exact text to put on the wire for a room frame, or a `ProtocolError`
 * when the extension's hello did not list the frame's gating entry in
 * `accepts` — an older extension refuses the unknown type and closes the link
 * `1002`, so sending one ungated breaks the link rather than informing it.
 *
 * The caller's object is read exactly once, into a plain-data snapshot (each
 * own enumerable member read once; no accessors survive). Only that snapshot
 * is validated, gated and serialised. Validating alone is not enough: some
 * validators (the encrypted `frame`, `ready`, parts of `hello`) return their
 * input rather than a rebuilt copy, so without the snapshot a getter could
 * validate as `frame`, pass the gate as `room-ping` and serialise as a third
 * type. With it, an accessor or a Proxy cannot pass the check as one value
 * and go out as another, and a caller cannot send what the receiver would
 * refuse (an over-long or control-character label, an extra member such as a
 * token id). The heartbeat pair comes out as exactly `ROOM_PING_TEXT` /
 * `ROOM_PONG_TEXT`.
 */
export function roomFrameText(accepts: readonly string[], frame: RoomFrame): string {
  const checked: Frame = validateFrame(snapshot(frame, 0));
  const type: string = checked.type;
  if (!Object.prototype.hasOwnProperty.call(ROOM_FRAME_ACCEPTS, type)) {
    throw new ProtocolError(`room frame: unknown type ${JSON.stringify(type)}`);
  }
  const t = type as RoomFrameType;
  if (!roomFrameAccepted(accepts, t)) {
    throw new ProtocolError(
      `${t}: the extension's hello did not list ${JSON.stringify(ROOM_FRAME_ACCEPTS[t])} in accepts`,
    );
  }
  return JSON.stringify(checked);
}
