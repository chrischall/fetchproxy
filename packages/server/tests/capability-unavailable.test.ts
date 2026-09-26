import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  capabilityUnavailableMessage,
  openEncryptedFrame,
  sealInnerFrame,
  type EncryptedFrame,
  type InnerRequest,
} from '@fetchproxy/protocol';
import {
  FetchproxyServer,
  FetchproxyCapabilityUnavailableError,
  FetchproxyHelloRejectedError,
  FetchproxyHintedError,
  FetchproxyProtocolError,
  classifyBridgeError,
  classifyFetchError,
  protocolErrorFrom,
} from '../src/index.js';
import { connectMockExtension, type MockExtension } from './helpers/mock-extension.js';
import {
  newFakeExtension,
  startFakeConcentrator,
  type FakeConcentrator,
} from './helpers/concentrator.js';
import { getEphemeralPort } from './helpers/ephemeral-port.js';

/**
 * #418: the extension grants the servable subset and says which capabilities
 * this browser cannot serve. The server keeps that list per session, refuses a
 * verb for one of them locally (no round trip), turns the extension's typed
 * refusal into an error that blames the BROWSER, and reports both through
 * `bridgeHealth()`.
 */

describe('classifyFetchError — capability_unavailable', () => {
  it('classifies the fixed wording', () => {
    expect(classifyFetchError(capabilityUnavailableMessage('download', 'safari'))).toBe(
      'capability_unavailable',
    );
  });

  it('classifies the pre-#418 bridge wording, which named no browser', () => {
    expect(classifyFetchError('capability "download" is not available in this browser')).toBe(
      'capability_unavailable',
    );
  });

  it('classifies by the wire code when the wording is something else', () => {
    expect(classifyFetchError('whatever a later extension says', 'capability_unavailable')).toBe(
      'capability_unavailable',
    );
  });

  it('keeps capability_denied for a grant the MCP never asked for', () => {
    expect(classifyFetchError('capability "download" not granted (declared: [fetch])')).toBe(
      'capability_denied',
    );
  });
});

describe('protocolErrorFrom — capability_unavailable', () => {
  it('types the fixed wording, with the capability and the browser', () => {
    const err = protocolErrorFrom(capabilityUnavailableMessage('download', 'safari'));
    expect(err).toBeInstanceOf(FetchproxyCapabilityUnavailableError);
    const e = err as FetchproxyCapabilityUnavailableError;
    expect(e.capability).toBe('download');
    expect(e.platform).toBe('safari');
    expect(e.originalError).toBe('capability "download" is not available in this browser (safari)');
  });

  it('blames the browser, not the MCP or a version', () => {
    const e = protocolErrorFrom(
      capabilityUnavailableMessage('download', 'safari'),
    ) as FetchproxyCapabilityUnavailableError;
    expect(e.hint).toMatch(/safari/i);
    expect(e.hint).toMatch(/browser/i);
    expect(e.hint).not.toMatch(/version mismatch/i);
    expect(e.hint).not.toMatch(/re-?pair/i);
  });

  it('is a hinted protocol error, so existing catch sites and the CLI branch still match', () => {
    const e = protocolErrorFrom(capabilityUnavailableMessage('graphql', 'safari'));
    expect(e).toBeInstanceOf(FetchproxyHintedError);
    expect(e).toBeInstanceOf(FetchproxyProtocolError);
    expect(classifyBridgeError(e)).toBe('protocol');
  });

  it('types a coded refusal whose wording it cannot parse, taking the capability from the op', () => {
    const e = protocolErrorFrom('nope', undefined, {
      code: 'capability_unavailable',
      op: 'graphql_query',
    });
    expect(e).toBeInstanceOf(FetchproxyCapabilityUnavailableError);
    expect((e as FetchproxyCapabilityUnavailableError).capability).toBe('graphql');
    expect((e as FetchproxyCapabilityUnavailableError).platform).toBeNull();
  });

  it('leaves "not granted" alone', () => {
    const e = protocolErrorFrom('capability "download" not granted (declared: [fetch])');
    expect(e).not.toBeInstanceOf(FetchproxyCapabilityUnavailableError);
  });
});

describe('FetchproxyHelloRejectedError — unsupported-capability', () => {
  it('lists the capabilities and blames the browser', () => {
    const e = new FetchproxyHelloRejectedError({
      mcpId: 'x-mcp:1.0.0:abc',
      reason: 'unsupported-capability: download, graphql (not available in this browser)',
      platform: 'safari',
    });
    expect(e.unavailableCapabilities).toEqual(['download', 'graphql']);
    expect(e.platform).toBe('safari');
    expect(e.hint).toMatch(/safari/);
    expect(e.hint).toMatch(/download, graphql/);
    expect(e.hint).not.toMatch(/version/i);
    expect(classifyBridgeError(e)).toBe('hello_rejected');
  });

  it('carries no list or hint for any other reason', () => {
    const e = new FetchproxyHelloRejectedError({ mcpId: 'x', reason: 'sessionSig invalid' });
    expect(e.unavailableCapabilities).toEqual([]);
    expect(e.hint).toBeNull();
  });
});

// ── Integration: host role ─────────────────────────────────────────────────

let server: FetchproxyServer | null = null;
let ext: MockExtension | null = null;
let rig: FakeConcentrator | null = null;
afterEach(async () => {
  ext?.close();
  ext = null;
  if (server) await server.close();
  server = null;
  if (rig) await rig.close();
  rig = null;
});

async function hostWithExtension(
  helloExtra: Parameters<typeof connectMockExtension>[2],
): Promise<{ server: FetchproxyServer; ext: MockExtension; mcpId: string; key: Uint8Array }> {
  const port = await getEphemeralPort();
  const dir = mkdtempSync(join(tmpdir(), 'fp-unavail-host-'));
  server = new FetchproxyServer({
    port,
    serverName: 'shop-mcp',
    version: '1.0.0',
    domains: ['example.com'],
    capabilities: ['fetch', 'fetch_in_page', 'download'],
    identityDir: dir,
    trustDir: dir,
    allowNewExtensionIdentity: true,
    fetchTimeoutMs: 5_000,
    bridgeReviveDelayMs: 0,
    keepAliveIntervalMs: 0,
  });
  await server.listen();
  await server.connect();
  expect(server.role).toBe('host');
  const mcpId = (server as unknown as { mcpId: string }).mcpId;
  ext = await connectMockExtension(port, undefined, helloExtra);
  const key = await ext.completeHandshake(mcpId);
  await vi.waitFor(() => expect(server!.bridgeHealth().session.state).toBe('linked'));
  return { server, ext, mcpId, key };
}

const sentFrames = (e: MockExtension, mcpId: string): number =>
  e.framesFor(mcpId).filter((f) => f.type === 'frame').length;

describe('host: the unavailable list from the verified extension hello', () => {
  it('reports the known names and the platform, and drops names it does not know', async () => {
    const { server } = await hostWithExtension({
      platform: 'safari',
      unavailableCapabilities: ['download', 'teleport_tab'] as never,
    });
    expect(server.bridgeHealth().session).toMatchObject({
      state: 'linked',
      unavailableCapabilities: ['download'],
      platform: 'safari',
    });
    const probe = await server.runProbe(async () => undefined, '/');
    expect(probe.bridge).toMatchObject({
      unavailable_capabilities: ['download'],
      platform: 'safari',
    });
  });

  it('refuses a verb for an unavailable capability locally, with no round trip', async () => {
    const { server, ext, mcpId } = await hostWithExtension({
      platform: 'safari',
      unavailableCapabilities: ['download'],
    });
    const before = sentFrames(ext, mcpId);
    const err = await server.download({ url: 'https://example.com/f.pdf' }).catch((e) => e);
    expect(err).toBeInstanceOf(FetchproxyCapabilityUnavailableError);
    expect(err.capability).toBe('download');
    expect(err.platform).toBe('safari');
    await new Promise((r) => setTimeout(r, 30));
    expect(sentFrames(ext, mcpId)).toBe(before);
  });

  it('refuses an in-page fetch when fetch_in_page is unavailable — as an envelope from fetch(), a throw from request()', async () => {
    const { server } = await hostWithExtension({
      platform: 'safari',
      unavailableCapabilities: ['fetch_in_page'],
    });
    const env = await server.fetch({
      url: 'https://example.com/a',
      method: 'GET',
      tabUrl: 'https://example.com/',
      inPage: true,
    });
    expect(env.ok).toBe(false);
    if (!env.ok) expect(env.kind).toBe('capability_unavailable');
    const err = await server.request('GET', '/a', { inPage: true }).catch((e) => e);
    expect(err).toBeInstanceOf(FetchproxyCapabilityUnavailableError);
    expect(err.capability).toBe('fetch_in_page');
  });

  it('turns the extension’s typed refusal into a browser-blaming error', async () => {
    // A stripped list (or an old record) sends the request anyway; the
    // extension answers with the authenticated typed error.
    const { server, ext, mcpId, key } = await hostWithExtension({ platform: 'safari' });
    const pending = server.request('GET', '/a').catch((e) => e);
    await vi.waitFor(() => expect(sentFrames(ext, mcpId)).toBe(1));
    const sealed = ext
      .framesFor(mcpId)
      .find((f) => f.type === 'frame') as unknown as EncryptedFrame;
    const req = (await openEncryptedFrame(key, sealed, 's2e')) as InnerRequest;
    ext.ws.send(
      JSON.stringify(
        await sealInnerFrame(
          key,
          mcpId,
          1,
          {
            type: 'response',
            id: req.id,
            ok: false,
            op: 'fetch',
            code: 'capability_unavailable',
            error: capabilityUnavailableMessage('fetch', 'safari'),
          },
          'e2s',
        ),
      ),
    );
    const err = await pending;
    expect(err).toBeInstanceOf(FetchproxyCapabilityUnavailableError);
    expect(err.platform).toBe('safari');
  });

  it('an extension that sends no list: nothing refused locally, platform still reported', async () => {
    const { server, ext, mcpId } = await hostWithExtension({});
    expect(server.bridgeHealth().session).toMatchObject({
      unavailableCapabilities: [],
      platform: 'chrome',
    });
    void server.download({ url: 'https://example.com/f.pdf' }).catch(() => undefined);
    await vi.waitFor(() => expect(sentFrames(ext, mcpId)).toBe(1));
  });

  it('clears the list when the extension disconnects', async () => {
    const { server, ext } = await hostWithExtension({
      platform: 'safari',
      unavailableCapabilities: ['download'],
    });
    ext.close();
    await vi.waitFor(() =>
      expect(server.bridgeHealth().session).toMatchObject({
        unavailableCapabilities: [],
        platform: null,
      }),
    );
  });
});

// ── Integration: peer role ─────────────────────────────────────────────────

describe('peer: the list follows the hello the accepted ready verified', () => {
  it('keeps the linked session’s list until the next ready verifies, then switches; clears on disconnect', async () => {
    rig = await startFakeConcentrator();
    const dir = mkdtempSync(join(tmpdir(), 'fp-unavail-peer-'));
    server = new FetchproxyServer({
      serverName: 'shop-mcp',
      version: '1.0.0',
      domains: ['example.com'],
      capabilities: ['fetch', 'download', 'graphql'],
      graphqlOps: [{ name: 'q', operationName: 'Q' }],
      host: '127.0.0.1',
      port: rig.port,
      identityDir: dir,
      trustDir: dir,
      allowNewExtensionIdentity: true,
      fetchTimeoutMs: 5_000,
      bridgeReviveDelayMs: 0,
      keepAliveIntervalMs: 0,
    });
    await server.listen();
    // A peer dials lazily; a verb call makes it connect.
    void server.fetch({
      url: 'https://example.com/',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await rig.waitForHello();

    const e1 = await newFakeExtension();
    e1.hello = { ...e1.hello, platform: 'safari', unavailableCapabilities: ['download'] };
    await rig.relayExtensionHello(e1);
    await rig.answerReady(e1, await rig.waitForHello(1));
    await vi.waitFor(() => expect(server!.bridgeHealth().session.state).toBe('linked'));
    expect(server.bridgeHealth().session).toMatchObject({
      unavailableCapabilities: ['download'],
      platform: 'safari',
    });

    // A later extension session's hello arrives; its ready has not.
    const e2 = await newFakeExtension(e1);
    e2.hello = { ...e2.hello, unavailableCapabilities: ['graphql'] };
    await rig.relayExtensionHello(e2);
    const h2 = await rig.waitForHello(2);
    expect(server.bridgeHealth().session.unavailableCapabilities).toEqual(['download']);

    await rig.answerReady(e2, h2);
    await vi.waitFor(() =>
      expect(server!.bridgeHealth().session.unavailableCapabilities).toEqual(['graphql']),
    );
    const err = (await server
      .graphqlQuery({ name: 'q', variables: {} })
      .catch((e: unknown) => e)) as FetchproxyCapabilityUnavailableError;
    expect(err).toBeInstanceOf(FetchproxyCapabilityUnavailableError);
    expect(err.capability).toBe('graphql');

    await rig.relayExtensionDisconnected();
    await vi.waitFor(() =>
      expect(server!.bridgeHealth().session).toMatchObject({
        unavailableCapabilities: [],
        platform: null,
      }),
    );
  }, 20_000);
});
