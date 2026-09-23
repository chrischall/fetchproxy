import { describe, expect, it, beforeEach, afterEach, vi } from 'vitest';

/**
 * B-BUG-12 — when the download window expires, the Chrome download must be
 * cancelled (and its record erased), not left transferring and writing to
 * disk. Otherwise every retry of a slow download starts another copy.
 */

const sent: { mcpId: string; inner: Record<string, unknown> }[] = [];
vi.mock('../src/background/send-inner.js', () => ({
  sendInner: async (mcpId: string, inner: Record<string, unknown>) => {
    sent.push({ mcpId, inner });
  },
}));

const { handleDownloadRequest } = await import('../src/background/handlers/download.js');
const { bindMcpToLink, localLink, unbindAll } = await import('../src/background/links.js');

const MCP_ID = 'alltrails-mcp:2.1.3:aaaaaaaaaaaaaaaa';

function installDownloads(opts: { resolveDownloadAfterMs?: number } = {}) {
  const cancel = vi.fn(async () => {});
  const erase = vi.fn(async () => []);
  (globalThis as { chrome?: unknown }).chrome = {
    downloads: {
      onChanged: { addListener: () => {}, removeListener: () => {} },
      download: () =>
        new Promise<number>((resolve) => setTimeout(() => resolve(42), opts.resolveDownloadAfterMs ?? 0)),
      search: async () => [{ id: 42, state: 'in_progress' }],
      cancel,
      erase,
    },
  };
  return { cancel, erase };
}

describe('download timeout cancels the browser download (B-BUG-12)', () => {
  beforeEach(() => {
    sent.length = 0;
    unbindAll();
    bindMcpToLink(MCP_ID, localLink());
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('cancels and erases the in-progress download when the window expires', async () => {
    const { cancel, erase } = installDownloads();
    const p = handleDownloadRequest(
      MCP_ID,
      { type: 'request', op: 'download', id: 'r1', init: { url: 'https://alltrails.com/big.gpx', timeoutMs: 1000 } },
      ['alltrails.com'],
    );
    await vi.advanceTimersByTimeAsync(0);
    await p;
    await vi.advanceTimersByTimeAsync(1000);
    expect(sent.at(-1)!.inner).toMatchObject({ ok: false, error: 'timeout' });
    expect(cancel).toHaveBeenCalledWith(42);
    expect(erase).toHaveBeenCalledWith({ id: 42 });
  });

  it('cancels a download whose id only arrives after the timeout fired', async () => {
    const { cancel } = installDownloads({ resolveDownloadAfterMs: 2000 });
    const p = handleDownloadRequest(
      MCP_ID,
      { type: 'request', op: 'download', id: 'r2', init: { url: 'https://alltrails.com/big.gpx', timeoutMs: 1000 } },
      ['alltrails.com'],
    );
    await vi.advanceTimersByTimeAsync(1000);
    expect(sent.at(-1)!.inner).toMatchObject({ ok: false, error: 'timeout' });
    await vi.advanceTimersByTimeAsync(1000);
    await p;
    expect(cancel).toHaveBeenCalledWith(42);
  });
});
