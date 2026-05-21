import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import { FetchproxyServer } from '../src/index.js';

const TEST_PORT = 47149;

describe('FetchproxyServer', () => {
  let server: FetchproxyServer;

  beforeEach(async () => {
    server = new FetchproxyServer({
      port: TEST_PORT,
      server: 'test-mcp',
      version: '0.0.1',
      domain: 'example.com',
    });
    await server.start();
  });

  afterEach(async () => {
    await server.close();
  });

  it('sends a hello frame to the extension when it connects', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${TEST_PORT}`);
    const helloFromServer = await new Promise<unknown>((resolve) => {
      ws.on('message', (data) => resolve(JSON.parse(String(data))));
    });
    expect(helloFromServer).toMatchObject({
      type: 'hello',
      role: 'server',
      server: 'test-mcp',
      version: '0.0.1',
      domain: 'example.com',
    });
    ws.close();
  });

  it('relays a fetch through the extension', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${TEST_PORT}`);
    ws.on('open', () => {
      ws.send(JSON.stringify({
        type: 'hello',
        role: 'extension',
        version: '1.0.0',
        platform: 'chrome',
        extension_id: 'fetchproxy',
      }));
      ws.send(JSON.stringify({ type: 'ready' }));
    });
    // Echo any request back as a successful response.
    ws.on('message', (data) => {
      const frame = JSON.parse(String(data));
      if (frame.type === 'request') {
        ws.send(JSON.stringify({
          type: 'response',
          id: frame.id,
          ok: true,
          status: 200,
          url: frame.init.url,
          body: 'echo',
        }));
      }
    });

    const result = await server.fetch({
      url: 'https://example.com/foo',
      method: 'GET',
      tabUrl: 'https://example.com/',
    });
    expect(result.status).toBe(200);
    expect(result.body).toBe('echo');
    ws.close();
  });

  it('throws "extension offline" if no extension is connected within the timeout', async () => {
    server.setConnectTimeoutMs(100);
    await expect(
      server.fetch({
        url: 'https://example.com/foo',
        method: 'GET',
        tabUrl: 'https://example.com/',
      })
    ).rejects.toThrow(/extension offline/);
  });

  it('rejects a second simultaneous extension connection', async () => {
    const ws1 = new WebSocket(`ws://127.0.0.1:${TEST_PORT}`);
    await new Promise<void>((resolve) => ws1.on('open', resolve));
    const ws2 = new WebSocket(`ws://127.0.0.1:${TEST_PORT}`);
    const closeReason = await new Promise<string>((resolve) => {
      ws2.on('close', (_code, reason) => resolve(reason.toString()));
    });
    expect(closeReason).toMatch(/already connected/i);
    ws1.close();
  });

  it('rejects WS upgrades whose Origin is a public web origin', async () => {
    const ws = new WebSocket(`ws://127.0.0.1:${TEST_PORT}`, {
      headers: { Origin: 'https://evil.example.com' },
    });
    const closed = await new Promise<boolean>((resolve) => {
      ws.on('close', () => resolve(true));
      ws.on('error', () => resolve(true));
    });
    expect(closed).toBe(true);
  });
});
