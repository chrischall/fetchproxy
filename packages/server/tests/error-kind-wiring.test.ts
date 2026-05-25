import { describe, it, expect } from 'vitest';
import { FetchproxyServer } from '../src/index.js';
import { installFakeHost } from './helpers/fake-host.js';

const baseOpts = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
};

describe('FetchproxyServer.fetch — ok:false kind wiring', () => {
  it('populates `kind: \'content_script_unreachable\'` for the Chrome SW-eviction error', async () => {
    const s = new FetchproxyServer(baseOpts);
    const harness = installFakeHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    // Give the microtask queue a turn so the inner request is sent.
    await Promise.resolve();
    const inner = harness.lastInner();
    expect(inner).not.toBeNull();
    harness.reply({
      type: 'response',
      id: inner!.id,
      ok: false,
      op: 'fetch',
      error: 'tab fetch failed: Error: Could not establish connection. Receiving end does not exist.',
    });
    const result = await pending;
    expect(result.ok).toBe(false);
    // Backward compat: the existing `error` field is unchanged.
    expect((result as { error: string }).error).toMatch(/Could not establish connection/);
    // New: the `kind` field is populated by the server-side classifier.
    expect((result as { kind?: string }).kind).toBe('content_script_unreachable');
  });

  it('populates `kind: \'no_tab\'` for the no-matching-tab error', async () => {
    const s = new FetchproxyServer(baseOpts);
    const harness = installFakeHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await Promise.resolve();
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: false,
      op: 'fetch',
      error: 'no tab matching https://example.com/',
    });
    const result = await pending;
    expect((result as { kind?: string }).kind).toBe('no_tab');
  });

  it('populates `kind: \'other\'` for an unrecognised extension error', async () => {
    // Forward-compat: if the extension introduces a new error template
    // in a future version, the server keeps surfacing the raw string
    // and falls back to `kind: 'other'` rather than throwing.
    const s = new FetchproxyServer(baseOpts);
    const harness = installFakeHost(s);
    const pending = s.fetch({
      url: 'https://example.com/x',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await Promise.resolve();
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: false,
      op: 'fetch',
      error: 'some entirely new failure mode',
    });
    const result = await pending;
    expect((result as { kind?: string }).kind).toBe('other');
  });
});
