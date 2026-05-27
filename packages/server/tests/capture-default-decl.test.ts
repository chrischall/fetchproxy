import { describe, it, expect } from 'vitest';
import { FetchproxyServer } from '../src/index.js';
import { installFakeHost } from './helpers/fake-host.js';

const oneDecl = {
  serverName: 'test-mcp',
  version: '0.0.1',
  domains: ['example.com'],
  capabilities: ['fetch' as const, 'capture_request_header' as const],
  captureHeaders: [
    { urlPattern: 'https://example.com/x*', headerName: 'Authorization' },
  ],
};

const twoDecls = {
  ...oneDecl,
  captureHeaders: [
    { urlPattern: 'https://example.com/x*', headerName: 'Authorization' },
    { urlPattern: 'https://example.com/y*', headerName: 'X-CSRF' },
  ],
};

describe('captureRequestHeader() — declaration-based defaults', () => {
  it('defaults to the single declared entry when called with no args', async () => {
    const s = new FetchproxyServer(oneDecl);
    const harness = installFakeHost(s);
    const pending = s.captureRequestHeader();
    await Promise.resolve();
    const inner = harness.lastInner();
    expect(inner).not.toBeNull();
    expect(inner!.op).toBe('capture_request_header');
    // The frame the server emitted must carry the resolved pattern/header.
    expect((inner!.init as { urlPattern: string }).urlPattern).toBe(
      'https://example.com/x*',
    );
    expect((inner!.init as { headerName: string }).headerName).toBe(
      'Authorization',
    );
    harness.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'capture_request_header',
      value: 'Bearer eyJ',
    });
    await expect(pending).resolves.toBe('Bearer eyJ');
  });

  it('defaults to the single declared entry when called with only timeoutMs', async () => {
    const s = new FetchproxyServer(oneDecl);
    const harness = installFakeHost(s);
    const pending = s.captureRequestHeader({ timeoutMs: 500 });
    await Promise.resolve();
    const inner = harness.lastInner()!;
    expect((inner.init as { urlPattern: string }).urlPattern).toBe(
      'https://example.com/x*',
    );
    expect((inner.init as { timeoutMs: number }).timeoutMs).toBe(500);
    harness.reply({
      type: 'response',
      id: inner.id,
      ok: true,
      op: 'capture_request_header',
      value: 'X',
    });
    await pending;
  });

  it('throws a clear error when multiple captureHeaders are declared and the caller omits the selector', async () => {
    const s = new FetchproxyServer(twoDecls);
    installFakeHost(s);
    await expect(s.captureRequestHeader()).rejects.toThrow(
      /multiple captureHeaders declared|disambiguate/i,
    );
  });

  it('throws a clear error when no captureHeaders are declared (programmer error)', async () => {
    const s = new FetchproxyServer({
      ...oneDecl,
      captureHeaders: [],
    });
    installFakeHost(s);
    await expect(s.captureRequestHeader()).rejects.toThrow(
      /no captureHeaders declared/i,
    );
  });

  it('still works the old way when both fields are explicitly passed (back-compat)', async () => {
    const s = new FetchproxyServer(twoDecls);
    const harness = installFakeHost(s);
    const pending = s.captureRequestHeader({
      urlPattern: 'https://example.com/y*',
      headerName: 'X-CSRF',
    });
    await Promise.resolve();
    harness.reply({
      type: 'response',
      id: harness.lastInner()!.id,
      ok: true,
      op: 'capture_request_header',
      value: 'csrf-tok',
    });
    await expect(pending).resolves.toBe('csrf-tok');
  });

  it('throws when only one of urlPattern/headerName is specified (force pair or neither)', async () => {
    const s = new FetchproxyServer(twoDecls);
    installFakeHost(s);
    // @ts-expect-error — exercising the runtime guard.
    await expect(s.captureRequestHeader({ urlPattern: 'x' })).rejects.toThrow(
      /pass both .* or neither/i,
    );
  });
});
