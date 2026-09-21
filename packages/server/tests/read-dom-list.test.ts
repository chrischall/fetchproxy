import { describe, it, expect, vi } from 'vitest';
import { FetchproxyServer, FetchproxyProtocolError } from '../src/index.js';
import { installFakeHost } from './helpers/fake-host.js';

/**
 * `read_dom_list` is `read_dom`'s answer for a REPEATED structure — a chat's
 * messages, a table's rows — that a single `querySelector` per name cannot
 * express. Added for microsoft-teams-mcp, whose message data lives only in a
 * client-side sync cache with no fetchable REST/GraphQL surface; the
 * currently-rendered DOM is the only thing a bridge can read.
 */
function server(opts: {
  capabilities?: string[];
  domListSelectors?: ConstructorParameters<typeof FetchproxyServer>[0]['domListSelectors'];
} = {}) {
  return new FetchproxyServer({
    serverName: 'test',
    version: '0.0.0',
    domains: ['example.com'],
    capabilities: (opts.capabilities ?? ['fetch', 'read_dom_list']) as never,
    domListSelectors: opts.domListSelectors ?? [
      {
        name: 'chatMessages',
        itemSelector: '[data-tid="message"]',
        fields: [
          { name: 'sender', selector: '.author' },
          { name: 'text', selector: '.body' },
        ],
      },
    ],
  });
}

/** Capture the inner frame instead of talking to a bridge. */
function captureFrame(s: FetchproxyServer) {
  const sent: unknown[] = [];
  vi.spyOn(s as never, 'ensureConnected').mockResolvedValue(undefined as never);
  vi.spyOn(s as never, 'throwIfPendingPair').mockReturnValue(undefined as never);
  vi.spyOn(s as never, 'sendInnerFrame').mockImplementation(async (f: unknown) => {
    sent.push(f);
  });
  return sent;
}

describe('readDomList — gates', () => {
  it('refuses when the capability was not declared', async () => {
    const s = server({ capabilities: ['fetch'] });
    await expect(s.readDomList({ name: 'chatMessages' })).rejects.toThrow(
      /did not declare "read_dom_list"/,
    );
  });

  it('refuses a name outside the declared domListSelectors', async () => {
    const s = server();
    captureFrame(s);
    await expect(s.readDomList({ name: 'nope' })).rejects.toThrow(/not in declared/);
  });

  it('refuses an empty name', async () => {
    const s = server();
    captureFrame(s);
    await expect(s.readDomList({ name: '' })).rejects.toThrow(/non-empty string/);
  });
});

describe('readDomList — the frame it sends', () => {
  it('carries a bare origin and the declared name', async () => {
    const s = server();
    const sent = captureFrame(s);

    void s.readDomList({ name: 'chatMessages' });
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    expect(sent[0]).toMatchObject({
      op: 'read_dom_list',
      init: { origin: 'https://example.com', name: 'chatMessages' },
    });
  });

  it('targets the requested subdomain', async () => {
    const s = server();
    const sent = captureFrame(s);

    void s.readDomList({ name: 'chatMessages', subdomain: 'app' });
    await vi.waitFor(() => expect(sent).toHaveLength(1));

    expect(sent[0]).toMatchObject({ init: { origin: 'https://app.example.com' } });
  });
});

describe('readDomList — response resolution', () => {
  it('resolves the rows array on a matching ok response', async () => {
    const s = server();
    const fake = installFakeHost(s);

    const promise = s.readDomList({ name: 'chatMessages' });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    expect(inner).not.toBeNull();
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'read_dom_list',
      rows: [
        { sender: 'Alice', text: 'hi' },
        { sender: 'Bob', text: 'hello' },
      ],
    });

    await expect(promise).resolves.toEqual([
      { sender: 'Alice', text: 'hi' },
      { sender: 'Bob', text: 'hello' },
    ]);
  });

  it('resolves an empty array when no items matched', async () => {
    const s = server();
    const fake = installFakeHost(s);

    const promise = s.readDomList({ name: 'chatMessages' });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    fake.reply({ type: 'response', id: inner!.id, ok: true, op: 'read_dom_list', rows: [] });

    await expect(promise).resolves.toEqual([]);
  });

  it('rejects with the extension-reported error on an ok:false response', async () => {
    const s = server();
    const fake = installFakeHost(s);

    const promise = s.readDomList({ name: 'chatMessages' });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: false,
      op: 'read_dom_list',
      error: 'origin https://example.com/ not in domains [other.com]',
    });

    await expect(promise).rejects.toThrow(FetchproxyProtocolError);
    await expect(promise).rejects.toThrow(/not in domains/);
  });

  it('a wrong-op response wakes the awaiter with a protocol error, not a hang', async () => {
    const s = server();
    const fake = installFakeHost(s);

    const promise = s.readDomList({ name: 'chatMessages' });
    await new Promise((r) => setTimeout(r, 0));
    const inner = fake.lastInner();
    fake.reply({
      type: 'response',
      id: inner!.id,
      ok: true,
      op: 'read_dom',
      values: { x: 'should never be returned' },
    });

    await expect(promise).rejects.toThrow(/unexpected read_dom response/);
  });
});
