import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  BRIDGE_ROLE_FRAME,
  BRIDGE_ROLE_LABEL_MAX,
  BRIDGE_SERVE_FRAME,
  ROOM_FRAME_ACCEPTS,
  ROOM_PING_FRAME,
  ROOM_PING_TEXT,
  ROOM_PONG_FRAME,
  ROOM_PONG_TEXT,
  ProtocolError,
  roomFrameAccepted,
  roomFrameText,
  validateFrame,
  validateRoomHeartbeatText,
  type BridgeRoleFrame,
  type RoomFrame,
  type RoomFrameType,
} from '../src/index.js';

// The vector file is written from the spec (mcp-host 2026-10-05 multi-browser
// spec §5.8), not from this implementation, and mcp-host's room transcribes
// against it — the account-attest.json precedent.
const vectorPath = fileURLToPath(new URL('./vectors/bridge-role.json', import.meta.url));
interface Vectors {
  accepts: Record<string, string>;
  literals: Record<string, string>;
  labelMaxLength: number;
  valid: { name: string; frame: Record<string, unknown> }[];
  invalid: { name: string; frame: Record<string, unknown> }[];
  invalidTexts: { name: string; text: string }[];
}
// Re-read the raw text per use so a prototype-pollution key in a fixture is an
// own property of a fresh object, exactly as it arrives off the wire.
const rawVectors = readFileSync(vectorPath, 'utf8');
const V = JSON.parse(rawVectors) as Vectors;
const freshInvalid = (i: number): unknown => (JSON.parse(rawVectors) as Vectors).invalid[i]!.frame;

const ALL_TYPES: RoomFrameType[] = ['bridge-role', 'bridge-serve', 'room-ping', 'room-pong'];

const STANDBY: BridgeRoleFrame = {
  type: 'bridge-role',
  role: 'standby',
  canServe: true,
  serving: { label: 'Chrome on MacBook', since: 1791196800000 },
};
const SERVING: BridgeRoleFrame = { type: 'bridge-role', role: 'serving', canServe: true };

const FRAMES: Record<RoomFrameType, RoomFrame> = {
  'bridge-role': STANDBY,
  'bridge-serve': { type: 'bridge-serve' },
  'room-ping': { type: 'room-ping' },
  'room-pong': { type: 'room-pong' },
};

describe('frame-type constants', () => {
  it('names the four room frames and the two literal heartbeat texts', () => {
    expect(BRIDGE_ROLE_FRAME).toBe('bridge-role');
    expect(BRIDGE_SERVE_FRAME).toBe('bridge-serve');
    expect(ROOM_PING_FRAME).toBe('room-ping');
    expect(ROOM_PONG_FRAME).toBe('room-pong');
    expect(ROOM_PING_TEXT).toBe(V.literals['room-ping']);
    expect(ROOM_PONG_TEXT).toBe(V.literals['room-pong']);
    expect(BRIDGE_ROLE_LABEL_MAX).toBe(V.labelMaxLength);
  });

  it('gates each frame on the accepts entry the vector file names', () => {
    expect({ ...ROOM_FRAME_ACCEPTS }).toEqual(V.accepts);
  });

  it('freezes the accepts map, so a consumer cannot widen a gate at runtime', () => {
    expect(Object.isFrozen(ROOM_FRAME_ACCEPTS)).toBe(true);
  });
});

describe('vector file: valid frames', () => {
  for (const v of V.valid) {
    it(`accepts ${v.name} and returns an equal copy`, () => {
      const input = structuredClone(v.frame);
      const got = validateFrame(input);
      expect(got).toEqual(v.frame);
      expect(got).not.toBe(input);
    });
  }
});

describe('vector file: invalid frames', () => {
  V.invalid.forEach((v, i) => {
    it(`refuses ${v.name}`, () => {
      // Refused by the frame's own validator, not as an unknown type.
      let err: unknown;
      try {
        validateFrame(freshInvalid(i));
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(ProtocolError);
      expect((err as Error).message).not.toMatch(/unknown frame type/);
    });
  });
});

describe('bridge-role validator', () => {
  it('rebuilds the frame and its serving member, sharing nothing with the input', () => {
    const input = structuredClone(STANDBY) as BridgeRoleFrame & { role: 'standby' };
    const got = validateFrame(input) as BridgeRoleFrame & { role: 'standby' };
    expect(got).toEqual(STANDBY);
    expect(got.serving).not.toBe(input.serving);
  });

  it('returns no serving member for a serving browser', () => {
    const got = validateFrame(structuredClone(SERVING));
    expect(got).toEqual(SERVING);
    expect(Object.keys(got)).toEqual(['type', 'role', 'canServe']);
  });

  it('refuses a missing or unknown role', () => {
    expect(() => validateFrame({ type: 'bridge-role', canServe: true })).toThrow(
      /bridge-role\.role/,
    );
    expect(() => validateFrame({ ...SERVING, role: 'primary' })).toThrow(/bridge-role\.role/);
  });

  it('refuses a canServe that is not a boolean', () => {
    expect(() => validateFrame({ ...SERVING, canServe: 'true' })).toThrow(/bridge-role\.canServe/);
    expect(() => validateFrame({ type: 'bridge-role', role: 'serving' })).toThrow(
      /bridge-role\.canServe/,
    );
  });

  it('requires serving on a standby and refuses it on a serving browser', () => {
    expect(() => validateFrame({ ...STANDBY, serving: undefined })).toThrow(/bridge-role\.serving/);
    const { serving } = STANDBY as BridgeRoleFrame & { role: 'standby' };
    expect(() => validateFrame({ ...SERVING, serving })).toThrow(/bridge-role\.serving/);
  });

  it('refuses a serving that is not a plain object', () => {
    for (const bad of [null, 'Chrome', [], 7]) {
      expect(() => validateFrame({ ...STANDBY, serving: bad })).toThrow(/bridge-role\.serving/);
    }
    class S {
      label = 'Chrome';
      since = 1;
    }
    expect(() => validateFrame({ ...STANDBY, serving: new S() })).toThrow(/non-plain/);
  });

  it(`accepts a label of exactly ${BRIDGE_ROLE_LABEL_MAX} characters and refuses one longer`, () => {
    const at = (label: string): unknown => ({ ...STANDBY, serving: { label, since: 1 } });
    expect(() => validateFrame(at('L'.repeat(BRIDGE_ROLE_LABEL_MAX)))).not.toThrow();
    expect(() => validateFrame(at('L'.repeat(BRIDGE_ROLE_LABEL_MAX + 1)))).toThrow(
      /bridge-role\.serving\.label/,
    );
    expect(() => validateFrame(at(''))).toThrow(/bridge-role\.serving\.label/);
  });

  it('refuses a label with a control or bidi-override character', () => {
    for (const label of ['a\u0000b', 'a\tb', 'a\nb', 'a\u007fb', 'a\u0085b', '‮emorhC', 'a⁦b']) {
      expect(() => validateFrame({ ...STANDBY, serving: { label, since: 1 } })).toThrow(
        /control or bidi-override/,
      );
    }
  });

  it('refuses a since that is not a non-negative safe integer', () => {
    for (const since of [-1, 1.5, '1', Number.MAX_SAFE_INTEGER + 2, Number.NaN, null]) {
      expect(() => validateFrame({ ...STANDBY, serving: { label: 'Chrome', since } })).toThrow(
        /bridge-role\.serving\.since/,
      );
    }
  });

  it('refuses an extra member on the frame or on serving', () => {
    expect(() => validateFrame({ ...SERVING, tokenId: 'brt_x' })).toThrow(/unexpected field/);
    expect(() =>
      validateFrame({ ...STANDBY, serving: { label: 'Chrome', since: 1, accountId: 'acc_x' } }),
    ).toThrow(/unexpected field/);
  });

  it('refuses a prototype-pollution key on the frame and on serving', () => {
    const top = JSON.parse(
      `{"__proto__":{"polluted":1},${JSON.stringify(SERVING).slice(1)}`,
    ) as unknown;
    expect(() => validateFrame(top)).toThrow(/forbidden key/);
    const nested = JSON.parse(
      '{"type":"bridge-role","role":"standby","canServe":true,"serving":{"__proto__":{"polluted":1},"label":"Chrome","since":1}}',
    ) as unknown;
    expect(() => validateFrame(nested)).toThrow(/forbidden key/);
    expect(() => validateFrame({ ...SERVING, constructor: 1 })).toThrow(/forbidden key/);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });
});

describe('bridge-serve, room-ping and room-pong validators', () => {
  for (const type of ['bridge-serve', 'room-ping', 'room-pong'] as const) {
    it(`accepts a bare ${type} and returns a fresh copy`, () => {
      const input = { type };
      const got = validateFrame(input);
      expect(got).toEqual({ type });
      expect(got).not.toBe(input);
    });

    it(`refuses a ${type} with any other member`, () => {
      expect(() => validateFrame({ type, at: 1 })).toThrow(new RegExp(`${type}: unexpected field`));
      expect(() => validateFrame({ type, mcpId: 'x' })).toThrow(/unexpected field/);
    });

    it(`refuses a ${type} with a prototype-pollution key`, () => {
      const raw = JSON.parse(`{"__proto__":{"polluted":1},"type":"${type}"}`) as unknown;
      expect(() => validateFrame(raw)).toThrow(/forbidden key/);
    });
  }
});

describe('room heartbeat literal texts', () => {
  it('accepts exactly the two literal texts', () => {
    expect(validateRoomHeartbeatText(ROOM_PING_TEXT)).toEqual({ type: 'room-ping' });
    expect(validateRoomHeartbeatText(ROOM_PONG_TEXT)).toEqual({ type: 'room-pong' });
  });

  for (const v of V.invalidTexts) {
    it(`refuses ${v.name}`, () => {
      expect(() => validateRoomHeartbeatText(v.text)).toThrow(ProtocolError);
    });
  }

  it('refuses a non-string', () => {
    expect(() => validateRoomHeartbeatText({ type: 'room-ping' } as unknown as string)).toThrow(
      ProtocolError,
    );
  });

  // The literal is what lets a relay answer with a fixed auto-response pair
  // (Cloudflare's WebSocketRequestResponsePair matches the text byte for
  // byte), so the parsed-object validator must not be looser than the text:
  // a ping with extra members is a different serialisation, refused both ways.
  it('refuses a heartbeat with extra members as text and as a parsed frame', () => {
    const text = '{"type":"room-ping","at":1}';
    expect(() => validateRoomHeartbeatText(text)).toThrow(ProtocolError);
    expect(() => validateFrame(JSON.parse(text))).toThrow(ProtocolError);
    const pong = '{"type":"room-pong","at":1}';
    expect(() => validateRoomHeartbeatText(pong)).toThrow(ProtocolError);
    expect(() => validateFrame(JSON.parse(pong))).toThrow(ProtocolError);
  });

  it('serialises the literal texts from the frame objects', () => {
    expect(JSON.stringify(validateFrame(JSON.parse(ROOM_PING_TEXT)))).toBe(ROOM_PING_TEXT);
    expect(JSON.stringify(validateFrame(JSON.parse(ROOM_PONG_TEXT)))).toBe(ROOM_PONG_TEXT);
  });
});

describe('accepts gate', () => {
  for (const type of ALL_TYPES) {
    const entry = V.accepts[type]!;

    it(`admits ${type} only when accepts lists ${JSON.stringify(entry)}`, () => {
      expect(roomFrameAccepted([entry], type)).toBe(true);
      expect(roomFrameAccepted([], type)).toBe(false);
      expect(roomFrameAccepted(['peer-gone', 'account-key', 'account-attest'], type)).toBe(false);
      const others = ALL_TYPES.map((t) => V.accepts[t]!).filter((e) => e !== entry);
      expect(roomFrameAccepted(others, type)).toBe(false);
    });

    it(`refuses to serialise ${type} unless accepts lists ${JSON.stringify(entry)}`, () => {
      expect(() => roomFrameText([], FRAMES[type])).toThrow(/accepts/);
      expect(() => roomFrameText(['peer-gone'], FRAMES[type])).toThrow(ProtocolError);
      expect(typeof roomFrameText([entry], FRAMES[type])).toBe('string');
    });
  }

  it('matches an accepts entry exactly, not by prefix or case', () => {
    expect(roomFrameAccepted(['bridge-role-v2'], 'bridge-role')).toBe(false);
    expect(roomFrameAccepted(['BRIDGE-ROLE'], 'bridge-role')).toBe(false);
    expect(roomFrameAccepted(['room-pong'], 'room-pong')).toBe(false);
  });

  it('refuses an unknown frame type', () => {
    expect(roomFrameAccepted(['account-key'], 'account-key' as RoomFrameType)).toBe(false);
    expect(() =>
      roomFrameText(['account-key'], { type: 'account-key' } as unknown as RoomFrame),
    ).toThrow(ProtocolError);
  });
});

describe('roomFrameText', () => {
  const all = ['bridge-role', 'bridge-serve', 'room-ping'];

  it('sends exactly the literal texts for the heartbeat pair', () => {
    expect(roomFrameText(all, { type: 'room-ping' })).toBe(ROOM_PING_TEXT);
    expect(roomFrameText(all, { type: 'room-pong' })).toBe(ROOM_PONG_TEXT);
    expect(roomFrameText(all, { type: 'bridge-serve' })).toBe('{"type":"bridge-serve"}');
  });

  it('round-trips a bridge-role through the validator', () => {
    const text = roomFrameText(all, STANDBY);
    expect(validateFrame(JSON.parse(text))).toEqual(STANDBY);
    expect(validateFrame(JSON.parse(roomFrameText(all, SERVING)))).toEqual(SERVING);
  });

  it('refuses anything a caller adds to the frame, such as a token id', () => {
    const padded = { ...SERVING, tokenId: 'brt_0123456789abcdef01234567' } as BridgeRoleFrame;
    expect(() => roomFrameText(all, padded)).toThrow(/unexpected field/);
  });

  it('refuses to send a bridge-role the extension would refuse', () => {
    const long = {
      ...STANDBY,
      serving: { label: 'L'.repeat(BRIDGE_ROLE_LABEL_MAX + 1), since: 1 },
    };
    expect(() => roomFrameText(all, long as BridgeRoleFrame)).toThrow(/label/);
    const ctl = { ...STANDBY, serving: { label: 'a\u0007', since: 1 } };
    expect(() => roomFrameText(all, ctl as BridgeRoleFrame)).toThrow(/control/);
  });

  // A caller's object is read ONCE: what is checked is what is sent. An
  // accessor or a Proxy that answers differently on a second read must not
  // get past the gate or the label check (JSON.parse input has no accessors,
  // so this guards the SENDING side's own code, not the wire).
  it('checks and sends the same label even when the getter changes its answer', () => {
    let n = 0;
    const flip = {
      type: 'bridge-role',
      role: 'standby',
      canServe: true,
      serving: {
        since: 1,
        get label() {
          return n++ === 0 ? 'Chrome' : 'tok_SECRET\u202e';
        },
      },
    } as unknown as BridgeRoleFrame;
    const text = roomFrameText(all, flip);
    expect(text).toBe(
      '{"type":"bridge-role","role":"standby","canServe":true,"serving":{"label":"Chrome","since":1}}',
    );
    expect(validateFrame(JSON.parse(text))).toEqual({
      type: 'bridge-role',
      role: 'standby',
      canServe: true,
      serving: { label: 'Chrome', since: 1 },
    });
  });

  it('checks and sends the same canServe even when the getter changes its answer', () => {
    let n = 0;
    const flip = {
      type: 'bridge-role',
      role: 'serving',
      get canServe() {
        return n++ === 0 ? true : 'yes';
      },
    } as unknown as BridgeRoleFrame;
    expect(roomFrameText(all, flip)).toBe(
      '{"type":"bridge-role","role":"serving","canServe":true}',
    );
  });

  it('gates on the type it validated, not on a second read of it', () => {
    let n = 0;
    const toOther = {
      get type() {
        return n++ === 0 ? 'room-ping' : 'extension-disconnected';
      },
    } as unknown as RoomFrame;
    expect(roomFrameText(all, toOther)).toBe(ROOM_PING_TEXT);

    let m = 0;
    const fromOther = {
      get type() {
        return m++ === 0 ? 'extension-disconnected' : 'room-ping';
      },
    } as unknown as RoomFrame;
    expect(() => roomFrameText(all, fromOther)).toThrow(ProtocolError);
  });

  // Some validators (encrypted 'frame', 'ready', parts of 'hello') return
  // their input object rather than a rebuilt copy, so the gate and the
  // serialiser must never see the caller's object at all — only a snapshot
  // taken before validation. This sequence passed validation as an encrypted
  // frame, the gate as room-ping, and went out as extension-disconnected.
  it('refuses a getter that validates as a non-room frame and then answers as a room frame', () => {
    let n = 0;
    const seq = ['frame', 'room-ping', 'extension-disconnected'];
    const f = {
      mcpId: 'srv:1.0:0123456789abcdef',
      seq: 1,
      iv: 'AAAA',
      ciphertext: 'AAAA',
    } as Record<string, unknown>;
    Object.defineProperty(f, 'type', {
      enumerable: true,
      get: () => seq[Math.min(n++, seq.length - 1)],
    });
    expect(() => roomFrameText(all, f as unknown as RoomFrame)).toThrow(ProtocolError);
    expect(n).toBe(1);
  });

  it('reads every member of a plain object exactly once', () => {
    const reads = new Map<string, number>();
    const counted = (o: Record<string, unknown>): Record<string, unknown> => {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(o)) {
        const inner =
          v !== null && typeof v === 'object' ? counted(v as Record<string, unknown>) : v;
        Object.defineProperty(out, k, {
          enumerable: true,
          get: () => {
            reads.set(k, (reads.get(k) ?? 0) + 1);
            return inner;
          },
        });
      }
      return out;
    };
    const frame = counted({ ...STANDBY, serving: { label: 'Firefox', since: 7 } });
    const text = roomFrameText(all, frame as unknown as BridgeRoleFrame);
    expect(JSON.parse(text)).toEqual({ ...STANDBY, serving: { label: 'Firefox', since: 7 } });
    for (const [k, c] of reads) expect([k, c]).toEqual([k, 1]);
    expect([...reads.keys()].sort()).toEqual([
      'canServe',
      'label',
      'role',
      'serving',
      'since',
      'type',
    ]);
  });

  // roomFrameText snapshots first, so these call validateFrame directly: the
  // validator's own read-once rebuild stays pinned as a second layer.
  it('validateFrame rebuilds bridge-role from a single read of each member', () => {
    let l = 0;
    const flipLabel = {
      type: 'bridge-role',
      role: 'standby',
      canServe: true,
      serving: {
        since: 1,
        get label() {
          return l++ === 0 ? 'Chrome' : 'tok_SECRET‮';
        },
      },
    };
    expect(validateFrame(flipLabel)).toEqual({
      type: 'bridge-role',
      role: 'standby',
      canServe: true,
      serving: { label: 'Chrome', since: 1 },
    });

    for (const role of ['standby', 'serving'] as const) {
      let c = 0;
      const flipServe: Record<string, unknown> = {
        type: 'bridge-role',
        role,
        get canServe() {
          return c++ === 0 ? true : 'yes';
        },
      };
      if (role === 'standby') flipServe.serving = { label: 'Chrome', since: 1 };
      expect((validateFrame(flipServe) as BridgeRoleFrame).canServe).toBe(true);
    }
  });

  it('refuses a cyclic object instead of overflowing the stack', () => {
    const a: Record<string, unknown> = { type: 'bridge-serve' };
    a.self = a;
    expect(() => roomFrameText(all, a as unknown as RoomFrame)).toThrow(ProtocolError);
  });

  it('reads a Proxy once per member too', () => {
    const reads = new Map<PropertyKey, number>();
    const target = {
      type: 'bridge-role',
      role: 'standby',
      canServe: false,
      serving: { label: 'Firefox', since: 7 },
    };
    const proxy = new Proxy(target, {
      get(t, k, r) {
        const c = (reads.get(k) ?? 0) + 1;
        reads.set(k, c);
        if (k === 'type' && c > 1) return 'extension-disconnected';
        if (k === 'canServe' && c > 1) return 'nope';
        return Reflect.get(t, k, r);
      },
    }) as unknown as BridgeRoleFrame;
    const text = roomFrameText(all, proxy);
    expect(validateFrame(JSON.parse(text))).toEqual(target);
  });

  it("serialises the validator's rebuilt copy, never the caller's object", () => {
    // A non-enumerable toJSON is invisible to the exact-fields check
    // (Object.keys) but JSON.stringify(callerObject) would call it.
    const sneaky = { type: 'bridge-serve' } as unknown as RoomFrame;
    Object.defineProperty(sneaky, 'toJSON', {
      enumerable: false,
      value: () => ({ type: 'bridge-serve', tokenId: 'brt_0123456789abcdef01234567' }),
    });
    expect(roomFrameText(all, sneaky)).toBe('{"type":"bridge-serve"}');

    const role = { ...STANDBY } as BridgeRoleFrame;
    Object.defineProperty(role, 'toJSON', { enumerable: false, value: () => 'raw' });
    expect(roomFrameText(all, role)).toBe(JSON.stringify(validateFrame({ ...STANDBY })));
  });

  it('refuses a heartbeat object with extra members', () => {
    expect(() => roomFrameText(all, { type: 'room-ping', at: 1 } as unknown as RoomFrame)).toThrow(
      /unexpected field/,
    );
  });
});
