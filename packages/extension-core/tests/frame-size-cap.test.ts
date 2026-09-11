import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  MAX_FRAME_BYTES,
  AES_GCM_TAG_BYTES,
  base64Length,
  openEncryptedFrame,
  sealedFrameWireBytes,
  type EncryptedFrame,
  type InnerFrame,
} from '@fetchproxy/protocol';

import type { Link } from '../src/background/links.js';

/**
 * The extension refuses to put an oversize frame on the wire, and refuses it
 * ONE FRAME AT A TIME.
 *
 * `ws` answers a payload over `maxPayload` by closing the socket with 1009,
 * and the extension's socket is the one socket every MCP on the concentrator
 * shares — so a single large response would have taken every other MCP's
 * bridge down with it. The cap now bites at the producing end, where the
 * request it belongs to can simply be failed.
 */

class FakeSocket {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSING = 2;
  static readonly CLOSED = 3;

  readyState = 1;
  sent: string[] = [];
  closeCalls = 0;

  addEventListener(): void {}
  send(data: string): void {
    this.sent.push(data);
  }
  close(): void {
    this.closeCalls++;
    this.readyState = 3;
  }
}

vi.stubGlobal('WebSocket', FakeSocket);

const { sendInner } = await import('../src/background/send-inner.js');
const { state } = await import('../src/background/state.js');
const { links, unbindAll, bindMcpToLink, localLink } = await import('../src/background/links.js');
const { SessionKeys } = await import('../src/session-keys.js');
const { MAX_RESPONSE_BODY_BYTES } = await import('../src/content-limits.js');

const MCP_ID = 'alltrails-mcp:2.11.3:0123456789abcdef';
const KEY = new Uint8Array(32).fill(11);

let ws: FakeSocket;
let link: Link;

function sentFrames(): EncryptedFrame[] {
  return ws.sent.map((s) => JSON.parse(s) as EncryptedFrame);
}

/** A response frame whose wire form lands `over` bytes past the cap. */
function responseOfWireSize(over: number): InnerFrame {
  const probe: InnerFrame = {
    type: 'response',
    id: 12,
    ok: true,
    op: 'read_local_storage',
    values: { session: '' },
  };
  const overhead = sealedFrameWireBytes(MCP_ID, Number.MAX_SAFE_INTEGER, probe);
  // Every body byte here is ASCII, so one character is one plaintext byte and
  // four base64 characters cover three of them.
  const bodyBytes = Math.ceil(((MAX_FRAME_BYTES + over - overhead) * 3) / 4);
  return {
    type: 'response',
    id: 12,
    ok: true,
    op: 'read_local_storage',
    values: { session: 'x'.repeat(bodyBytes) },
  };
}

/**
 * A case that actually SEALS a frame at the cap moves ~42 MiB through
 * JSON.stringify, AES-GCM and base64. That is 1-2 s of CPU on its own and
 * several times that with the rest of the suite's 129 workers competing for
 * the machine, where vitest's default 5 s budget — sized for a test that is
 * WAITING, not one that is WORKING — turns a correct test into a flake. The
 * two cases below that seal at the cap were measured at 4166 ms and 3656 ms
 * under the full suite, so they carry a budget of their own rather than the
 * whole suite being given one: a 5 s test everywhere else still means
 * something is wrong, and that is worth keeping.
 */
const CAP_SIZED_TIMEOUT_MS = 30_000;

describe('the extension caps the frame it sends', () => {
  beforeEach(() => {
    unbindAll();
    links.clear();
    ws = new FakeSocket();
    link = localLink();
    link.ws = ws as unknown as WebSocket;
    links.set(link.id, link);
    bindMcpToLink(MCP_ID, link);
    state.sessions = new SessionKeys();
    state.sessions.set(MCP_ID, KEY);
  });

  it('refuses an oversize response with an error for that request, not a closed socket', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    const oversize = responseOfWireSize(1024);
    expect(sealedFrameWireBytes(MCP_ID, Number.MAX_SAFE_INTEGER, oversize)).toBeGreaterThan(
      MAX_FRAME_BYTES,
    );

    await sendInner(MCP_ID, oversize);

    // One frame went out, and it is not the oversize one.
    expect(ws.sent).toHaveLength(1);
    const sent = sentFrames()[0]!;
    expect(new TextEncoder().encode(ws.sent[0]!).length).toBeLessThanOrEqual(MAX_FRAME_BYTES);
    const inner = await openEncryptedFrame(KEY, sent);
    expect(inner).toMatchObject({
      type: 'response',
      id: 12,
      ok: false,
      op: 'read_local_storage',
    });
    expect((inner as { error: string }).error).toContain(String(MAX_FRAME_BYTES));

    // The socket every other MCP shares is untouched.
    expect(ws.closeCalls).toBe(0);
    expect(ws.readyState).toBe(FakeSocket.OPEN);
    expect(errors).toHaveBeenCalled();
    errors.mockRestore();
  });

  it(
    'sends a frame that fits, unchanged',
    async () => {
      const fits = responseOfWireSize(-1024);
      await sendInner(MCP_ID, fits);
      expect(ws.sent).toHaveLength(1);
      const inner = await openEncryptedFrame(KEY, sentFrames()[0]!);
      expect(inner).toMatchObject({ type: 'response', id: 12, ok: true });
      expect(ws.closeCalls).toBe(0);
    },
    CAP_SIZED_TIMEOUT_MS,
  );

  it('keeps the op echo when the frame it refuses was already a failure', async () => {
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {});
    // An `ok: false` response carries an optional `op`; when it has one the
    // refusal that replaces it must carry it too, exactly as the `ok: true`
    // branch does. Narrowing it here would tell the peer less than the frame
    // it stands in for did.
    const probe: InnerFrame = { type: 'response', id: 12, ok: false, op: 'read_dom', error: '' };
    const overhead = sealedFrameWireBytes(MCP_ID, Number.MAX_SAFE_INTEGER, probe);
    const oversize: InnerFrame = {
      type: 'response',
      id: 12,
      ok: false,
      op: 'read_dom',
      error: 'x'.repeat(Math.ceil(((MAX_FRAME_BYTES + 1024 - overhead) * 3) / 4)),
    };
    expect(sealedFrameWireBytes(MCP_ID, Number.MAX_SAFE_INTEGER, oversize)).toBeGreaterThan(
      MAX_FRAME_BYTES,
    );

    await sendInner(MCP_ID, oversize);

    expect(ws.sent).toHaveLength(1);
    const inner = await openEncryptedFrame(KEY, sentFrames()[0]!);
    expect(inner).toMatchObject({ type: 'response', id: 12, ok: false, op: 'read_dom' });
    expect((inner as { error: string }).error).toContain(String(MAX_FRAME_BYTES));
    expect(ws.closeCalls).toBe(0);
    errors.mockRestore();
  });

  it(
    'spends exactly one seq either way, so a refusal leaves no gap',
    async () => {
      await sendInner(MCP_ID, responseOfWireSize(-1024));
      await sendInner(MCP_ID, responseOfWireSize(1024));
      await sendInner(MCP_ID, { type: 'pong' });
      expect(sentFrames().map((f) => f.seq)).toEqual([1, 2, 3]);
    },
    CAP_SIZED_TIMEOUT_MS,
  );
});

describe('MAX_FRAME_BYTES is derived from the worst legitimate frame', () => {
  it('six bytes per UTF-16 code unit is the worst JSON escaping can do', () => {
    const enc = new TextEncoder();
    for (const ch of ['\u0000', '\u001f', '\ud800', '"', '\\', '\n', 'a', 'é', '€', '日', '😀']) {
      // Minus the two quotes JSON.stringify wraps the string in.
      const bytes = enc.encode(JSON.stringify(ch)).length - 2;
      expect(bytes / ch.length).toBeLessThanOrEqual(6);
    }
  });

  it('holds a 5 MiB response body of the most expensive characters there are', () => {
    // content.ts caps a relayed body at MAX_RESPONSE_BODY_BYTES UTF-16 code
    // units — `body.length`, not bytes — so the plaintext it can become is
    // six times that (the multiplier the test above pins), plus the rest of
    // the inner frame, plus the tag, then base64 and the envelope.
    const INNER_OVERHEAD_BYTES = 64 * 1024;
    const plaintext = MAX_RESPONSE_BODY_BYTES * 6 + INNER_OVERHEAD_BYTES;
    const wire =
      base64Length(plaintext + AES_GCM_TAG_BYTES) +
      sealedFrameWireBytes('a'.repeat(128) + ':9.9.9:0123456789abcdef', Number.MAX_SAFE_INTEGER, {
        type: 'ping',
      });
    expect(wire).toBeLessThanOrEqual(MAX_FRAME_BYTES);
  });
});
