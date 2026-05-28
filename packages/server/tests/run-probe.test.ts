import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  FetchproxyServer,
  FetchproxyBridgeDownError,
  FetchproxyTimeoutError,
  FetchproxyProtocolError,
} from '../src/index.js';
import type { BridgeProbeResult } from '../src/index.js';

/**
 * `runProbe(fetchFn, probePath)` is the transport half of the
 * healthcheck loop zillow/redfin/homes duplicated verbatim in
 * `src/tools/healthcheck.ts`: run a probe fetch, measure elapsed ms,
 * classify any error (via the typed-error hierarchy), and project
 * `bridgeHealth()` into a `bridge` sub-object. The tool registration +
 * the site-specific hint text STAY in the consumer — `runProbe` only
 * does probe execution + classification + the bridge projection.
 */
const baseOpts = {
  serverName: 'test-mcp',
  version: '0.4.2',
  domains: ['example.com'],
};

describe('runProbe()', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('ok path: returns ok=true, the elapsed ms, a bridge projection, and no error', async () => {
    const s = new FetchproxyServer(baseOpts);
    const fetchFn = vi.fn(async (_path: string) => {
      // simulate a 120ms round-trip
      vi.setSystemTime(120);
      return '<robots>';
    });
    const result: BridgeProbeResult = await s.runProbe(fetchFn, '/robots.txt');
    expect(fetchFn).toHaveBeenCalledWith('/robots.txt');
    expect(result.ok).toBe(true);
    expect(result.elapsed_ms).toBe(120);
    expect(result.error).toBeUndefined();
    // Bridge projection mirrors bridgeHealth() — version + port surface.
    expect(result.bridge.server_version).toBe('0.4.2');
    expect(result.bridge.port).toBe(37149);
    // Role is null because we never connected a fake host here.
    expect(result.bridge.role).toBeNull();
  });

  it('projects the live bridgeHealth() freshness counters into bridge', async () => {
    const s = new FetchproxyServer(baseOpts);
    const fetchFn = vi.fn(async () => 'ok');
    const result = await s.runProbe(fetchFn, '/robots.txt');
    const health = s.bridgeHealth();
    expect(result.bridge.role).toBe(health.role);
    expect(result.bridge.port).toBe(health.port);
    expect(result.bridge.server_version).toBe(health.serverVersion);
    expect(result.bridge.fetch_timeout_ms).toBe(health.fetchTimeoutMs);
    expect(result.bridge.last_success_at).toBe(health.lastSuccessAt);
    expect(result.bridge.last_failure_at).toBe(health.lastFailureAt);
    expect(result.bridge.last_failure_reason).toBe(health.lastFailureReason);
    expect(result.bridge.consecutive_failures).toBe(health.consecutiveFailures);
  });

  it('timeout: classifies a FetchproxyTimeoutError as kind="timeout"', async () => {
    const s = new FetchproxyServer(baseOpts);
    const fetchFn = vi.fn(async () => {
      vi.setSystemTime(30_000);
      throw new FetchproxyTimeoutError({
        url: 'https://example.com/robots.txt',
        timeoutMs: 30_000,
        role: 'host',
        port: 37149,
      });
    });
    const result = await s.runProbe(fetchFn, '/robots.txt');
    expect(result.ok).toBe(false);
    expect(result.elapsed_ms).toBe(30_000);
    expect(result.error?.kind).toBe('timeout');
    expect(result.error?.message).toMatch(/did not respond/);
  });

  it('bridge-down: classifies a FetchproxyBridgeDownError as kind="bridge_down"', async () => {
    const s = new FetchproxyServer(baseOpts);
    const fetchFn = vi.fn(async () => {
      throw new FetchproxyBridgeDownError({
        originalError: 'Could not establish connection',
        retryAttempted: true,
        role: 'host',
        port: 37149,
      });
    });
    const result = await s.runProbe(fetchFn, '/robots.txt');
    expect(result.ok).toBe(false);
    expect(result.error?.kind).toBe('bridge_down');
  });

  it('protocol error: classifies a generic FetchproxyProtocolError as kind="protocol"', async () => {
    const s = new FetchproxyServer(baseOpts);
    const fetchFn = vi.fn(async () => {
      throw new FetchproxyProtocolError('no tab matching https://example.com/');
    });
    const result = await s.runProbe(fetchFn, '/robots.txt');
    expect(result.ok).toBe(false);
    expect(result.error?.kind).toBe('protocol');
  });

  it('non-fetchproxy error: classifies as kind="other" and carries the message', async () => {
    const s = new FetchproxyServer(baseOpts);
    const fetchFn = vi.fn(async () => {
      throw new Error('boom');
    });
    const result = await s.runProbe(fetchFn, '/robots.txt');
    expect(result.ok).toBe(false);
    expect(result.error?.kind).toBe('other');
    expect(result.error?.message).toBe('boom');
  });

  it('non-Error throw: still classified other with a stringified message', async () => {
    const s = new FetchproxyServer(baseOpts);
    const fetchFn = vi.fn(async () => {
      throw 'plain string';
    });
    const result = await s.runProbe(fetchFn, '/robots.txt');
    expect(result.ok).toBe(false);
    expect(result.error?.kind).toBe('other');
    expect(result.error?.message).toBe('plain string');
  });
});
