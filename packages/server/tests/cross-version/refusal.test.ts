import { describe, it, expect, afterEach, vi } from 'vitest';
import { WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  PROTOCOL_VERSION,
  aesGcmSeal,
  openEncryptedFrame,
  openEncryptedFrameDetailed,
  sealInnerFrame,
  toB64,
  type EncryptedFrame,
  type InnerFrame,
} from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../../src/host.js';
import { electRole } from '../../src/election.js';
import { loadOrCreateIdentity } from '../../src/identity.js';
import { SESSION_READY_TIMEOUT_MS } from '../../src/session-ready.js';
import type { ExtensionPin, ExtensionTrustPort } from '../../src/extension-trust.js';
import { connectMockExtension } from '../helpers/mock-extension.js';
import { v3ExtensionHello, v3Frame } from './v3-fixtures.js';

/**
 * A v3 peer meeting a v4 host — held to the FROZEN corpus beside this file.
 *
 * Task 4.2 already pins the host's refusal, and pins it well; what it pins it
 * against is a `v3ExtensionHello()` helper written in `host.test.ts` by this
 * branch, from this branch's understanding of what v3 looked like. That is
 * the right test for the branch and the wrong one for the question Group 5
 * asks, which is whether a v4 end meets a REAL v3 peer cleanly. A fixture the
 * v4 work also authored drifts with it: change the shape of a hello and both
 * the code and its "old version" move together, and the suite stays green
 * over a break it can no longer see. `v3-fixtures.ts` is bytes captured once
 * from the published 2.11.3 packages and never regenerated, so these cases
 * are the ones that keep meaning something after the next wire break.
 *
 * The four cases are the plan's Group 5. Case 2 — a v3 MCP meeting a v4
 * EXTENSION — is in `packages/extension-core/tests/cross-version/refusal.test.ts`
 * against the same frozen corpus: its harness is the extension's service
 * worker with `chrome.*` and a fake `WebSocket`, and the alternative was a
 * server-package test reaching into another workspace's private source to
 * drive it. The corpus stays single-sourced, which is the part that matters —
 * both ends are refusing the same bytes.
 *
 * Every case asserts a CLEAN outcome and none asserts a wall-clock threshold:
 * the whole failure this group exists to bound is a hang, and a test that
 * bounds it with `expect(elapsed).toBeLessThan(n)` measures the machine it
 * ran on. Case 1 uses a fake clock that never advances instead, so the only
 * possible source of the settlement is the refusal itself.
 */

const MCP_ID = 'opentable-mcp:0.9.1:abc1234567890def';

/**
 * The real `setTimeout`, captured at module load — before any test installs a
 * fake clock.
 *
 * Case 1 freezes time on purpose, so a regression there would not fail, it
 * would HANG: the promise never settles and there is no timer left that could
 * make it. This turns that into an assertion failure with a sentence on it.
 * It is a guard rail and never the instrument — no assertion below reads an
 * elapsed time.
 */
const realSetTimeout = globalThis.setTimeout;
const SETTLE_GUARD_MS = 2_000;

function settleOrFail<T>(p: Promise<T>, what: string): Promise<T> {
  return Promise.race([
    p,
    new Promise<never>((_, reject) => {
      const t = realSetTimeout(
        () => reject(new Error(`${what} never settled within ${SETTLE_GUARD_MS}ms`)),
        SETTLE_GUARD_MS,
      );
      t.unref?.();
    }),
  ]);
}

/** #208: `startHost` requires a trust store; these tests want a blank one. */
function blankTrust(): ExtensionTrustPort {
  let pin: ExtensionPin | null = null;
  return {
    allowNew: false,
    read: async () => pin,
    write: async (next) => {
      pin = next;
    },
  };
}

describe('cross-version: a v3 peer meets a v4 host', () => {
  let host: HostHandle | null = null;

  afterEach(async () => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    if (host) await host.close();
    host = null;
  });

  async function startTestHost(): Promise<number> {
    const el = await electRole({ host: '127.0.0.1', port: 0 });
    if (el.role !== 'host') throw new Error('expected host');
    const port = (el.server.address() as AddressInfo).port;
    const idDir = mkdtempSync(join(tmpdir(), 'fp-xver-'));
    host = await startHost({
      httpServer: el.server,
      ownIdentity: await loadOrCreateIdentity('opentable-mcp', idDir),
      ownMcpId: MCP_ID,
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomains: ['opentable.com'],
      extensionTrust: blankTrust(),
    });
    return port;
  }

  async function openSocket(port: number): Promise<{
    ws: WebSocket;
    closed: Promise<{ code: number; reason: string }>;
  }> {
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((resolve, reject) => {
      ws.once('open', () => resolve());
      ws.once('error', reject);
    });
    ws.on('error', () => {
      /* expected: the host closes this socket under us */
    });
    const closed = new Promise<{ code: number; reason: string }>((resolve) => {
      ws.once('close', (code: number, reason: Buffer) =>
        resolve({ code, reason: reason.toString() }),
      );
    });
    return { ws, closed };
  }

  // -------------------------------------------------------------------------
  // Case 1 — a v3 extension's hello, verbatim from 2.11.3, at a v4 host.
  // -------------------------------------------------------------------------

  describe('case 1 — the frozen v3 extension hello', () => {
    it('closes 1002 naming both versions and fails the waiting call on a clock that never moves', async () => {
      const port = await startTestHost();

      // Installed AFTER the host is up, so the bind and the identity read run
      // on real time; only `awaitSessionReady`'s guard lands on the fake
      // clock. `setInterval` is deliberately not faked — nothing here needs
      // it, and leaving it real keeps this from being a test of `ws`.
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
      const frozenAt = Date.now();
      const idleTimers = vi.getTimerCount();

      // The call that used to hang for thirty seconds.
      const waiting = host!.sendOwnInner({ type: 'ping' }).then(
        () => 'sent' as const,
        (e: unknown) => e as Error,
      );
      // The 30 s guard is armed, and it is armed on a clock this test owns —
      // so from here NOTHING can time out unless this test advances it, and
      // nothing below does.
      expect(vi.getTimerCount()).toBe(idleTimers + 1);

      const { ws, closed } = await openSocket(port);
      ws.send(JSON.stringify(v3ExtensionHello));

      const err = await settleOrFail(waiting, 'the pending call');
      // The assertion the whole case is built around: the clock never moved,
      // so this rejection cannot have come from a timeout of any length.
      expect(Date.now()).toBe(frozenAt);
      expect(err).toBeInstanceOf(Error);
      expect((err as Error).name).toBe('FetchproxyProtocolVersionError');
      expect((err as Error).message).toBe(
        'protocol version mismatch: this MCP speaks fetchproxy protocol 4, the attached ' +
          'browser extension speaks 3 — update Transporter (the fetchproxy extension) to ' +
          '3.0.0 or later',
      );

      const { code, reason } = await settleOrFail(closed, 'the socket close');
      // 1002 is RFC 6455's protocol error, which a version mismatch exactly
      // is; 1008 in `host.ts` is spent on identity and authorization refusals.
      expect(code).toBe(1002);
      expect(reason).toMatch(/protocol version mismatch/);
      expect(reason).toContain(String(PROTOCOL_VERSION));
      expect(reason).toContain(String(v3ExtensionHello.protocolVersion));
      // RFC 6455 caps a close reason at 123 bytes and `ws` throws above it.
      expect(Buffer.byteLength(reason, 'utf8')).toBeLessThanOrEqual(123);
      expect(Date.now()).toBe(frozenAt);
    });

    it('and the fake clock is really the instrument — un-refused, the same call waits the timeout out', async () => {
      // The control for the case above, and the reason its frozen clock is an
      // assertion rather than a formality: on this path the ONLY thing that
      // settles the call is `SESSION_READY_TIMEOUT_MS` elapsing, and it does
      // not elapse until this test says so. A case-1 regression therefore
      // cannot settle at all, which is what `settleOrFail` turns into a
      // message.
      await startTestHost();
      vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });

      let settled: unknown = null;
      const waiting = host!.sendOwnInner({ type: 'ping' }).then(
        () => 'sent' as const,
        (e: unknown) => e as Error,
      );
      void waiting.then((v) => {
        settled = v;
      });

      await vi.advanceTimersByTimeAsync(SESSION_READY_TIMEOUT_MS - 1);
      expect(settled).toBeNull();

      await vi.advanceTimersByTimeAsync(1);
      const err = await settleOrFail(waiting, 'the un-refused call');
      expect((err as Error).name).toBe('FetchproxySessionNotReadyError');
    });
  });

  // -------------------------------------------------------------------------
  // Case 3 — the control. Without it, cases 1 and 4 prove only that nothing
  // works.
  // -------------------------------------------------------------------------

  describe('case 3 — the v4 control on the same rig', () => {
    it('completes the handshake, derives matching keys, and round-trips a sealed frame', async () => {
      const port = await startTestHost();
      const ext = await connectMockExtension(port);
      // The key the EXTENSION derived. The host derived its own from its own
      // half, and nothing compares the two directly — the round trip below is
      // what proves they agree, in both directions.
      const key = await ext.completeHandshake(MCP_ID);
      await vi.waitFor(() => expect(host!.sessionLinked()).toBe(true));

      const received: InnerFrame[] = [];
      host!.onOwnInner((inner) => received.push(inner));

      await host!.sendOwnInner({ type: 'ping' });
      await vi.waitFor(() =>
        expect(ext.framesFor(MCP_ID).some((f) => f.type === 'frame')).toBe(true),
      );
      const outbound = ext
        .framesFor(MCP_ID)
        .find((f) => f.type === 'frame') as unknown as EncryptedFrame;
      // 's2e': the extension's side of the direction binding.
      expect(await openEncryptedFrame(key, outbound, 's2e')).toMatchObject({ type: 'ping' });

      ext.ws.send(JSON.stringify(await sealInnerFrame(key, MCP_ID, 1, { type: 'pong' }, 'e2s')));
      await vi.waitFor(() => expect(received).toHaveLength(1));
      expect(received[0]).toMatchObject({ type: 'pong' });

      ext.close();
    });
  });

  // -------------------------------------------------------------------------
  // Case 4 — a v3-shaped frame at a live v4 session, and the M2 regression.
  // -------------------------------------------------------------------------

  describe('case 4 — a v3-shaped frame offered to a v4 session', () => {
    /** A live v4 session, and the key both ends agreed on. */
    async function linked(): Promise<{
      key: Uint8Array;
      ext: Awaited<ReturnType<typeof connectMockExtension>>;
    }> {
      const port = await startTestHost();
      const ext = await connectMockExtension(port);
      const key = await ext.completeHandshake(MCP_ID);
      await vi.waitFor(() => expect(host!.sessionLinked()).toBe(true));
      return { key, ext };
    }

    /**
     * Seal a frame the way v3 sealed one: AES-GCM under the session key with
     * NO additional data at all, and the same five-field envelope.
     *
     * Sealed under the LIVE key rather than replayed from the corpus on
     * purpose. `v3Frame` is sealed under a session that existed for one
     * capture and nothing else, so a v4 end would reject it for the
     * uninteresting reason that the key is wrong — which proves nothing about
     * the AAD. What the corpus contributes here is the SHAPE, asserted below:
     * v3's envelope is byte-for-byte v4's, so the only thing that can reject
     * this frame is the tag.
     */
    async function sealTheV3Way(
      key: Uint8Array,
      mcpId: string,
      seq: number,
      inner: InnerFrame,
    ): Promise<EncryptedFrame> {
      const iv = new Uint8Array(12);
      crypto.getRandomValues(iv);
      const pt = new TextEncoder().encode(JSON.stringify(inner));
      return {
        type: 'frame',
        mcpId,
        seq,
        iv: toB64(iv),
        ciphertext: toB64(await aesGcmSeal(key, iv, pt, new Uint8Array(0))),
      };
    }

    it('fails at the tag, not the schema — and the same plaintext sealed the v4 way opens', async () => {
      const { key, ext } = await linked();

      const v3Shaped = await sealTheV3Way(key, MCP_ID, 1, { type: 'pong' });
      // Grounded in the corpus rather than in this file's memory of v3: the
      // frozen frame's envelope has exactly these fields, which is why the
      // AAD could move without moving a byte on the wire.
      expect(Object.keys(v3Shaped).sort()).toEqual(Object.keys(v3Frame).sort());

      expect((await openEncryptedFrameDetailed(key, v3Shaped, 'e2s')).stage).toBe(
        'decrypt-failed',
      );
      // The control: same key, same id, same seq, same direction, same
      // plaintext — sealed with the AAD. A rejection above cannot be blamed
      // on any of those.
      const v4Sealed = await sealInnerFrame(key, MCP_ID, 1, { type: 'pong' }, 'e2s');
      expect((await openEncryptedFrameDetailed(key, v4Sealed, 'e2s')).stage).toBe('ok');

      ext.close();
    });

    it('is refused on the wire too: never delivered, and dropped loudly without costing the shared link', async () => {
      const warns = vi.spyOn(console, 'warn').mockImplementation(() => {});
      const { key, ext } = await linked();

      const received: InnerFrame[] = [];
      host!.onOwnInner((inner) => received.push(inner));

      ext.ws.send(JSON.stringify(await sealTheV3Way(key, MCP_ID, 1, { type: 'pong' })));
      // B-BUG-4: the host used to tear the EXTENSION socket down over a frame
      // it could not open — the socket every MCP on the concentrator shares.
      // It now drops the frame with a warning, as a peer does, and the seq
      // stays unspent: a genuine v4 frame under the same seq still opens.
      await vi.waitFor(() => expect(warns).toHaveBeenCalled());
      expect(received).toHaveLength(0);
      ext.ws.send(JSON.stringify(await sealInnerFrame(key, MCP_ID, 1, { type: 'pong' }, 'e2s')));
      await vi.waitFor(() => expect(received).toHaveLength(1));
      expect(ext.ws.readyState).toBe(ext.ws.OPEN);

      ext.close();
    });

    it('refuses a genuine v4 frame re-offered under seq + 1 — the M2 regression', async () => {
      const { key, ext } = await linked();

      const sealed = await sealInnerFrame(key, MCP_ID, 7, { type: 'pong' }, 'e2s');
      // `seq` rides on the envelope, outside the ciphertext. Until v4 nothing
      // the tag covered committed to it, so a party in the path could replay a
      // recorded frame under a bumped counter.
      expect((await openEncryptedFrameDetailed(key, { ...sealed, seq: 8 }, 'e2s')).stage).toBe(
        'decrypt-failed',
      );
      // The other two members of the AAD, for the same reason: the shared
      // concentrator socket carries every MCP's frames, and a frame reflected
      // back at its own sender used to open cleanly.
      expect(
        (
          await openEncryptedFrameDetailed(
            key,
            { ...sealed, mcpId: 'tock-mcp:1.0.0:1111111111111111' },
            'e2s',
          )
        ).stage,
      ).toBe('decrypt-failed');
      expect((await openEncryptedFrameDetailed(key, sealed, 's2e')).stage).toBe('decrypt-failed');

      // And the envelope untouched still opens, so what failed above is the
      // binding and not the frame.
      expect((await openEncryptedFrameDetailed(key, sealed, 'e2s')).stage).toBe('ok');

      ext.close();
    });
  });
});
