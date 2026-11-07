import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  openEncryptedFrame,
  responseTooLargeMessage,
  sealInnerFrame,
  toB64,
  MAX_BINARY_RESPONSE_BYTES,
  RESPONSE_TOO_LARGE_CODE,
  type EncryptedFrame,
  type InnerFrame,
  type InnerRequestFetch,
} from '@fetchproxy/protocol';
import {
  FetchproxyServer,
  FetchproxyExtensionUpdateRequiredError,
  FetchproxyHintedError,
  FetchproxyHttpError,
  FetchproxyProtocolError,
  FetchproxyResponseTooLargeError,
  classifyBridgeError,
  classifyFetchError,
  protocolErrorFrom,
} from '../src/index.js';
import { sessionInfoFromHello } from '../src/session-info.js';
import { connectMockExtension, type MockExtension } from './helpers/mock-extension.js';
import { getEphemeralPort } from './helpers/ephemeral-port.js';

/**
 * #460: `requestBytes()` / `getBytes()` fetch a response's BYTES through the
 * bridge. The request carries `responseType: 'base64'`; the extension answers
 * with base64 in `body`, `bodyEncoding: 'base64'` and a relayed header subset.
 * The server refuses locally when the extension's hello does not list
 * `fetch_base64`, and refuses any answer that lacks the marker.
 */

let server: FetchproxyServer | null = null;
let ext: MockExtension | null = null;
afterEach(async () => {
  ext?.close();
  ext = null;
  if (server) await server.close();
  server = null;
});

const ALL_BYTES = Uint8Array.from({ length: 256 }, (_, i) => i);

async function linked(
  helloExtra: Parameters<typeof connectMockExtension>[2] = { features: ['fetch_base64'] },
): Promise<{ server: FetchproxyServer; ext: MockExtension; mcpId: string; key: Uint8Array }> {
  const port = await getEphemeralPort();
  const dir = mkdtempSync(join(tmpdir(), 'fp-binary-'));
  server = new FetchproxyServer({
    port,
    serverName: 'files-mcp',
    version: '1.0.0',
    domains: ['example.com'],
    identityDir: dir,
    trustDir: dir,
    allowNewExtensionIdentity: true,
    fetchTimeoutMs: 5_000,
    bridgeReviveDelayMs: 0,
    keepAliveIntervalMs: 0,
  });
  await server.listen();
  await server.connect();
  const mcpId = (server as unknown as { mcpId: string }).mcpId;
  ext = await connectMockExtension(port, undefined, helloExtra);
  const key = await ext.completeHandshake(mcpId);
  await vi.waitFor(() => expect(server!.bridgeHealth().session.state).toBe('linked'));
  return { server, ext, mcpId, key };
}

const sentFrames = (e: MockExtension, mcpId: string): EncryptedFrame[] =>
  e.framesFor(mcpId).filter((f) => f.type === 'frame') as unknown as EncryptedFrame[];

/** Wait for the nth request the server sealed, open it, and return it. */
async function nextRequest(
  e: MockExtension,
  mcpId: string,
  key: Uint8Array,
  nth = 0,
): Promise<InnerRequestFetch> {
  await vi.waitFor(() => expect(sentFrames(e, mcpId).length).toBeGreaterThan(nth));
  return (await openEncryptedFrame(key, sentFrames(e, mcpId)[nth]!, 's2e')) as InnerRequestFetch;
}

let replySeq = 1;
async function reply(e: MockExtension, mcpId: string, key: Uint8Array, inner: InnerFrame): Promise<void> {
  e.ws.send(JSON.stringify(await sealInnerFrame(key, mcpId, replySeq++, inner, 'e2s')));
}

describe('requestBytes — the binary round trip', () => {
  it('returns all 256 byte values exactly, with status, final url and the relayed headers', async () => {
    replySeq = 1;
    const { server, ext, mcpId, key } = await linked();
    const pending = server.getBytes('https://files.example.com/doc/1?sig=abc');
    const req = await nextRequest(ext, mcpId, key);
    expect(req.op).toBe('fetch');
    expect(req.init).toMatchObject({
      url: 'https://files.example.com/doc/1?sig=abc',
      method: 'GET',
      responseType: 'base64',
    });
    const headers = {
      'content-type': 'application/pdf',
      'content-length': '256',
      'content-disposition': 'attachment; filename="report.pdf"',
    };
    await reply(ext, mcpId, key, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://files.example.com/doc/1?sig=abc',
      body: toB64(ALL_BYTES),
      bodyEncoding: 'base64',
      headers,
    });
    const res = await pending;
    expect(res.status).toBe(200);
    expect(res.url).toBe('https://files.example.com/doc/1?sig=abc');
    expect(res.headers).toEqual(headers);
    expect(res.bytes).toBeInstanceOf(Uint8Array);
    expect(res.bytes.length).toBe(256);
    expect(Array.from(res.bytes)).toEqual(Array.from(ALL_BYTES));
  });

  it('reports the final url after a redirect, as the extension observed it', async () => {
    replySeq = 1;
    const { server, ext, mcpId, key } = await linked();
    const pending = server.getBytes('/download/7');
    const req = await nextRequest(ext, mcpId, key);
    expect(req.init.url).toBe('https://example.com/download/7');
    await reply(ext, mcpId, key, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://files.example.com/signed/7?sig=x',
      body: toB64(new Uint8Array([0xff, 0x00, 0xfe])),
      bodyEncoding: 'base64',
      headers: {},
    });
    const res = await pending;
    expect(res.url).toBe('https://files.example.com/signed/7?sig=x');
    expect(Array.from(res.bytes)).toEqual([0xff, 0x00, 0xfe]);
  });

  it('refuses an answer whose final url left the declared domains', async () => {
    replySeq = 1;
    const { server, ext, mcpId, key } = await linked();
    const pending = server.getBytes('/download/7').catch((e) => e);
    const req = await nextRequest(ext, mcpId, key);
    await reply(ext, mcpId, key, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://elsewhere.example.org/x',
      body: '',
      bodyEncoding: 'base64',
      headers: {},
    });
    const err = await pending;
    expect(err).toBeInstanceOf(FetchproxyProtocolError);
    expect(err.message).toMatch(/outside declared domains/);
  });

  it('honours expectStatus with the same FetchproxyHttpError request() throws', async () => {
    replySeq = 1;
    const { server, ext, mcpId, key } = await linked();
    const pending = server.getBytes('/missing', { expectStatus: 200 }).catch((e) => e);
    const req = await nextRequest(ext, mcpId, key);
    await reply(ext, mcpId, key, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'fetch',
      status: 404,
      url: 'https://example.com/missing',
      body: toB64(new TextEncoder().encode('not found')),
      bodyEncoding: 'base64',
      headers: { 'content-type': 'text/plain' },
    });
    const err = await pending;
    expect(err).toBeInstanceOf(FetchproxyHttpError);
    expect(err.response.status).toBe(404);
  });

  it('refuses a url outside the declared domains before anything is sent', async () => {
    const { server, ext, mcpId } = await linked();
    await expect(server.getBytes('https://bank.example.org/statement.pdf')).rejects.toThrow(
      /outside declared domains/,
    );
    expect(sentFrames(ext, mcpId)).toHaveLength(0);
  });
});

describe('text mode is unchanged', () => {
  it('request() puts no responseType on the wire and returns the body as text', async () => {
    replySeq = 1;
    const { server, ext, mcpId, key } = await linked();
    const pending = server.get('/page');
    const req = await nextRequest(ext, mcpId, key);
    expect(req.init).toEqual({
      url: 'https://example.com/page',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    await reply(ext, mcpId, key, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/page',
      body: 'héllo',
    });
    expect(await pending).toEqual({ status: 200, url: 'https://example.com/page', body: 'héllo' });
  });
});

describe('capability negotiation with an older extension', () => {
  it('reports the advertised features in bridgeHealth()', async () => {
    const { server } = await linked({ features: ['fetch_base64', 'teleport'] as never });
    expect(server.bridgeHealth().session.features).toEqual(['fetch_base64']);
  });

  it('refuses locally, with no round trip, when the extension does not list fetch_base64', async () => {
    const { server, ext, mcpId } = await linked({});
    expect(server.bridgeHealth().session.features).toEqual([]);
    const err = await server.getBytes('/f.pdf').catch((e) => e);
    expect(err).toBeInstanceOf(FetchproxyExtensionUpdateRequiredError);
    expect(err).toBeInstanceOf(FetchproxyHintedError);
    expect(err.feature).toBe('fetch_base64');
    expect(err.hint).toMatch(/update/i);
    expect(err.hint).toMatch(/ContextMint Bridge/);
    expect(classifyBridgeError(err)).toBe('protocol');
    await new Promise((r) => setTimeout(r, 30));
    expect(sentFrames(ext, mcpId)).toHaveLength(0);
  });

  it('the raw fetch() envelope names the kind instead of throwing', async () => {
    await linked({});
    const env = await server!.fetch({
      url: 'https://example.com/f.pdf',
      method: 'GET',
      tabUrl: 'https://example.com/',
      responseType: 'base64',
    });
    expect(env.ok).toBe(false);
    if (!env.ok) expect(env.kind).toBe('extension_update_required');
  });

  it('refuses an answer with no bodyEncoding marker — an old extension answering as text', async () => {
    // A relay can ADD `fetch_base64` to the unsigned hello. The older
    // extension behind it ignores `responseType` and answers in text; that
    // text must never be decoded as bytes.
    replySeq = 1;
    const { server, ext, mcpId, key } = await linked();
    const pending = server.getBytes('/f.pdf').catch((e) => e);
    const req = await nextRequest(ext, mcpId, key);
    await reply(ext, mcpId, key, {
      type: 'response',
      id: req.id,
      ok: true,
      op: 'fetch',
      status: 200,
      url: 'https://example.com/f.pdf',
      body: '%PDF-1.7 ��',
    });
    const err = await pending;
    expect(err).toBeInstanceOf(FetchproxyExtensionUpdateRequiredError);
  });

  it('parses only the features it knows from the hello', () => {
    const info = sessionInfoFromHello({
      type: 'hello',
      protocolVersion: 4,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'x',
      version: '1',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AAAA',
      features: ['teleport', 'fetch_base64', 'fetch_base64'],
    });
    expect(info.features).toEqual(['fetch_base64']);
  });
});

describe('the size cap', () => {
  it('maps the early (content-length) refusal to a typed error with both numbers', async () => {
    replySeq = 1;
    const { server, ext, mcpId, key } = await linked();
    const pending = server.getBytes('/huge.zip').catch((e) => e);
    const req = await nextRequest(ext, mcpId, key);
    await reply(ext, mcpId, key, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      code: RESPONSE_TOO_LARGE_CODE,
      error: responseTooLargeMessage({
        limitBytes: MAX_BINARY_RESPONSE_BYTES,
        declaredBytes: 40_000_000,
      }),
    });
    const err = await pending;
    expect(err).toBeInstanceOf(FetchproxyResponseTooLargeError);
    expect(err.limitBytes).toBe(MAX_BINARY_RESPONSE_BYTES);
    expect(err.declaredBytes).toBe(40_000_000);
    expect(err.hint).not.toMatch(/version mismatch|re-?pair/i);
  });

  it('maps the streaming refusal (no or lying content-length) too', async () => {
    replySeq = 1;
    const { server, ext, mcpId, key } = await linked();
    const pending = server.getBytes('/huge.zip').catch((e) => e);
    const req = await nextRequest(ext, mcpId, key);
    await reply(ext, mcpId, key, {
      type: 'response',
      id: req.id,
      ok: false,
      op: 'fetch',
      code: RESPONSE_TOO_LARGE_CODE,
      error: responseTooLargeMessage({ limitBytes: MAX_BINARY_RESPONSE_BYTES }),
    });
    const err = await pending;
    expect(err).toBeInstanceOf(FetchproxyResponseTooLargeError);
    expect(err.declaredBytes).toBeNull();
  });

  it('classifies the wording and the code as body_too_large', () => {
    const msg = responseTooLargeMessage({ limitBytes: 10, declaredBytes: 20 });
    expect(classifyFetchError(msg)).toBe('body_too_large');
    expect(classifyFetchError('reworded', RESPONSE_TOO_LARGE_CODE)).toBe('body_too_large');
  });

  it('protocolErrorFrom types a coded refusal whose wording it cannot parse', () => {
    const e = protocolErrorFrom('reworded', undefined, { code: RESPONSE_TOO_LARGE_CODE });
    expect(e).toBeInstanceOf(FetchproxyResponseTooLargeError);
    expect((e as FetchproxyResponseTooLargeError).limitBytes).toBeNull();
  });
});
