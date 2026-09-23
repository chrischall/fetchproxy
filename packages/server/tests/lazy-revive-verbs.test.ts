import { describe, it, expect } from 'vitest';
import { FetchproxyServer, FetchproxyBridgeDownError } from '../src/index.js';
import { installFakeHost } from './helpers/fake-host.js';

// B-QUAL-1: capture_redirect and download share the lazy-revive policy with
// capture_request_header (one helper, `withLazyRevive`). These pin it for the
// two verbs that had no revive coverage.

const SW_ERROR =
  'tab fetch failed: Error: Could not establish connection. Receiving end does not exist.';
const URL = 'https://example.com/file.pdf';

const opts = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
  capabilities: ['capture_redirect' as const, 'download' as const],
};

type Verb = 'capture_redirect' | 'download';
const call = (s: FetchproxyServer, verb: Verb): Promise<unknown> =>
  verb === 'download'
    ? s.download({ url: URL })
    : s.captureRedirect({ host: 'example.com', path: '/x*' });
const okValue = (verb: Verb): unknown =>
  verb === 'download'
    ? { path: '/tmp/x.pdf', bytes: 1, mime: 'application/pdf', finalUrl: URL }
    : 'https://cdn.example.com/x';

const tick = () => new Promise((r) => setTimeout(r, 5));

for (const verb of ['capture_redirect', 'download'] as const) {
  describe(`${verb} — lazy-revive`, () => {
    it('retries once on SW-down and returns the retry result', async () => {
      const s = new FetchproxyServer({ ...opts, bridgeReviveDelayMs: 1 });
      const h = installFakeHost(s);
      const p = call(s, verb);
      await tick();
      const first = h.lastInner()!.id;
      h.reply({ type: 'response', id: first, ok: false, op: verb, error: SW_ERROR });
      await tick();
      const second = h.lastInner()!.id;
      expect(second).not.toBe(first);
      h.reply({ type: 'response', id: second, ok: true, op: verb, value: okValue(verb) } as never);
      await expect(p).resolves.toEqual(okValue(verb));
      const health = s.bridgeHealth();
      expect(health.swEviction.lazyReviveAttempts).toBe(1);
      expect(health.swEviction.lazyReviveSuccesses).toBe(1);
      expect(health.consecutiveFailures).toBe(0);
    });

    it('throws FetchproxyBridgeDownError(retryAttempted:true) when the retry is also down', async () => {
      const s = new FetchproxyServer({ ...opts, bridgeReviveDelayMs: 1 });
      const h = installFakeHost(s);
      const p = call(s, verb).catch((e: unknown) => e);
      await tick();
      h.reply({ type: 'response', id: h.lastInner()!.id, ok: false, op: verb, error: SW_ERROR });
      await tick();
      h.reply({ type: 'response', id: h.lastInner()!.id, ok: false, op: verb, error: SW_ERROR });
      const err = await p;
      expect(err).toBeInstanceOf(FetchproxyBridgeDownError);
      expect((err as FetchproxyBridgeDownError).retryAttempted).toBe(true);
      expect((err as FetchproxyBridgeDownError).op).toBe(verb);
      expect(s.bridgeHealth().lastFailureReason).toMatch(new RegExp(`^${verb} bridge-down:`));
    });

    it('does not retry when bridgeReviveDelayMs is 0', async () => {
      const s = new FetchproxyServer({ ...opts, bridgeReviveDelayMs: 0 });
      const h = installFakeHost(s);
      const p = call(s, verb).catch((e: unknown) => e);
      await tick();
      h.reply({ type: 'response', id: h.lastInner()!.id, ok: false, op: verb, error: SW_ERROR });
      const err = await p;
      expect((err as FetchproxyBridgeDownError).retryAttempted).toBe(false);
      expect(s.bridgeHealth().swEviction.lastEvictionDetectedAt).not.toBeNull();
    });

    it('rethrows a non-SW error without retrying', async () => {
      const s = new FetchproxyServer({ ...opts, bridgeReviveDelayMs: 1 });
      const h = installFakeHost(s);
      const p = call(s, verb).catch((e: unknown) => e);
      await tick();
      h.reply({ type: 'response', id: h.lastInner()!.id, ok: false, op: verb, error: 'boom' });
      const err = await p;
      expect(err).not.toBeInstanceOf(FetchproxyBridgeDownError);
      expect(s.bridgeHealth().lastFailureReason).toBe(`${verb}: boom`);
    });
  });
}
