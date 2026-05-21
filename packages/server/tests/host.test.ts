import { describe, it, expect, afterEach } from 'vitest';
import { WebSocket } from 'ws';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  validateFrame,
  type HelloFrameFromExtension,
} from '@fetchproxy/protocol';
import { startHost, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';

describe('host (concentrator)', () => {
  let host: HostHandle | null = null;

  afterEach(async () => {
    if (host) await host.close();
    host = null;
  });

  it('accepts extension WS and forwards its own hello after extension says hi', async () => {
    const port = 41100;
    const el = await electRole({ host: '127.0.0.1', port });
    expect(el.role).toBe('host');
    if (el.role !== 'host') throw new Error('expected host');
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);

    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomain: 'opentable.com',
    });

    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((resolve, reject) => {
      ws.once('open', () => resolve());
      ws.once('error', reject);
    });

    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: 1,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.1.0',
    };
    ws.send(JSON.stringify(extHello));

    const ownHelloPromise = new Promise<Record<string, unknown>>((resolve) => {
      ws.on('message', (data) => {
        const parsed = JSON.parse(data.toString());
        if (
          parsed.type === 'hello' &&
          parsed.role === 'server' &&
          parsed.mcpId === 'opentable-mcp:0.9.1:abc1234567890def'
        ) {
          resolve(parsed);
        }
      });
    });
    const ownHello = await ownHelloPromise;
    expect(ownHello.serverName).toBe('opentable-mcp');
    expect(ownHello.domain).toBe('opentable.com');
    expect(() => validateFrame(ownHello)).not.toThrow();

    ws.close();
  });

  it('rejects WS upgrades with public Origin header', async () => {
    const port = 41101;
    const el = await electRole({ host: '127.0.0.1', port });
    if (el.role !== 'host') throw new Error('expected host');
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);

    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomain: 'opentable.com',
    });

    // Connect with an Origin header that simulates a public webpage.
    const ws = new WebSocket(`ws://127.0.0.1:${port}`, {
      headers: { Origin: 'https://evil.com' },
    });
    const closedWithError = await new Promise<boolean>((resolve) => {
      ws.once('error', () => resolve(true));
      ws.once('open', () => resolve(false));
    });
    expect(closedWithError).toBe(true);
  });

  it('sendOwnInner rejects if the extension disconnects before sending ready', async () => {
    const port = 41103;
    const el = await electRole({ host: '127.0.0.1', port });
    if (el.role !== 'host') throw new Error('expected host');
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);

    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomain: 'opentable.com',
    });

    // Mock extension: open the WS, send hello, then disconnect without ready.
    const ws = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => ws.once('open', () => r()));
    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: 1,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.1.0',
    };
    ws.send(JSON.stringify(extHello));
    await new Promise((r) => setTimeout(r, 30));  // let host record the connection
    ws.close();

    await expect(host.sendOwnInner({ type: 'ping' })).rejects.toThrow(
      /extension disconnected before ready/,
    );
  });

  it('refuses a second extension connection', async () => {
    const port = 41102;
    const el = await electRole({ host: '127.0.0.1', port });
    if (el.role !== 'host') throw new Error('expected host');
    const idDir = mkdtempSync(join(tmpdir(), 'fp-host-'));
    const id = await loadOrCreateIdentity('opentable-mcp', idDir);

    host = await startHost({
      httpServer: el.server,
      ownIdentity: id,
      ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
      ownServerName: 'opentable-mcp',
      ownVersion: '0.9.1',
      ownDomain: 'opentable.com',
    });

    const extHello: HelloFrameFromExtension = {
      type: 'hello',
      protocolVersion: 1,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.1.0',
    };

    const a = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => a.once('open', () => r()));
    a.send(JSON.stringify(extHello));
    await new Promise((r) => setTimeout(r, 50));  // let host process

    const b = new WebSocket(`ws://127.0.0.1:${port}`);
    await new Promise<void>((r) => b.once('open', () => r()));
    b.send(JSON.stringify(extHello));
    const bClosed = await new Promise<boolean>((resolve) => {
      b.once('close', () => resolve(true));
      setTimeout(() => resolve(false), 500);
    });
    expect(bClosed).toBe(true);

    a.close();
  });
});
