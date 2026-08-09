import { describe, expect, it, beforeEach, vi } from 'vitest';

/**
 * `download` is the one verb that cannot cross a remote bridge.
 *
 * It answers with a filesystem PATH on the machine running the browser, on the
 * assumption that the MCP asking reads the same disk. That holds for every MCP
 * on `127.0.0.1` and for none reached through a relay — and the second thing
 * it would do is worse than the first: a remote MCP writing bytes into the
 * user's Downloads folder is the only verb in this protocol that leaves
 * something behind on the machine.
 */

const sent: { mcpId: string; inner: Record<string, unknown> }[] = [];
vi.mock('../src/background/send-inner.js', () => ({
  sendInner: async (mcpId: string, inner: Record<string, unknown>) => {
    sent.push({ mcpId, inner });
  },
}));

const { handleDownloadRequest, DOWNLOAD_LOCAL_ONLY_ERROR } = await import(
  '../src/background/handlers/download.js'
);
const { bindMcpToLink, localLink, remoteLink, unbindAll } = await import('../src/background/links.js');

const MCP_ID = 'alltrails-mcp:2.1.3:aaaaaaaaaaaaaaaa';
const request = {
  type: 'request' as const,
  op: 'download' as const,
  id: 'req-1',
  init: { url: 'https://alltrails.com/map.gpx' },
};

describe('download over a remote bridge', () => {
  beforeEach(() => {
    sent.length = 0;
    unbindAll();
  });

  it('is refused, with a reason the calling MCP can print', async () => {
    bindMcpToLink(
      MCP_ID,
      remoteLink({ id: 'host1', url: 'wss://mcp.nullnet.app/bridge', token: 'mcpb_x', enabled: true }, []),
    );

    await handleDownloadRequest(MCP_ID, request, ['alltrails.com']);

    expect(sent).toHaveLength(1);
    expect(sent[0]!.inner).toMatchObject({ ok: false, op: 'download', id: 'req-1' });
    expect(sent[0]!.inner.error).toBe(DOWNLOAD_LOCAL_ONLY_ERROR);
    expect(String(sent[0]!.inner.error)).toMatch(/local-only/);
  });

  it('is refused before the URL is even looked at — the link is the reason', async () => {
    bindMcpToLink(
      MCP_ID,
      remoteLink({ id: 'host1', url: 'wss://mcp.nullnet.app/bridge', token: 'mcpb_x', enabled: true }, []),
    );

    await handleDownloadRequest(MCP_ID, { ...request, init: { url: 'https://elsewhere.example/x' } }, [
      'alltrails.com',
    ]);

    // Not "url host not in domains": the answer must not depend on what was
    // asked for, or an MCP could conclude the verb works and its URL was wrong.
    expect(sent[0]!.inner.error).toBe(DOWNLOAD_LOCAL_ONLY_ERROR);
  });

  it('still runs its ordinary gates on the loopback link', async () => {
    bindMcpToLink(MCP_ID, localLink());

    await handleDownloadRequest(MCP_ID, { ...request, init: { url: 'https://elsewhere.example/x' } }, [
      'alltrails.com',
    ]);

    expect(String(sent[0]!.inner.error)).toMatch(/not in domains/);
  });
});
