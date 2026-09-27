import { describe, it, expect, afterEach, vi } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FetchproxyServer } from '../src/index.js';
import { EXTENSION_PINS_ENV } from '../src/extension-pins.js';
import type { ExtensionTrustPort } from '../src/extension-trust.js';

/**
 * A3: how `FetchproxyServer` reaches managed mode — the `extensionPins`
 * option, or `FETCHPROXY_EXTENSION_PINS=managed` for a host that sets an
 * environment variable on a child it did not write.
 */

function server(opts: Record<string, unknown> = {}): FetchproxyServer {
  return new FetchproxyServer({
    port: 0,
    serverName: 'opentable-mcp',
    version: '0.9.1',
    domains: ['opentable.com'],
    identityDir: mkdtempSync(join(tmpdir(), 'fp-mpsrv-id-')),
    trustDir: mkdtempSync(join(tmpdir(), 'fp-mpsrv-')),
    ...opts,
  });
}

function portOf(srv: FetchproxyServer): ExtensionTrustPort {
  return (srv as unknown as { extensionTrust(): ExtensionTrustPort }).extensionTrust();
}

describe('FetchproxyServer and managed extension pins', () => {
  afterEach(() => {
    delete process.env[EXTENSION_PINS_ENV];
    delete process.env.FETCHPROXY_TRUST_NEW_EXTENSION;
    vi.restoreAllMocks();
  });

  it('is unmanaged by default — the first-use port, unchanged', async () => {
    const srv = server();
    try {
      const port = portOf(srv);
      expect(port.managed).toBeUndefined();
      expect(port.location).toMatch(/opentable-mcp\.extension-trust\.json$/);
    } finally {
      await srv.close();
    }
  });

  it('is managed by the option', async () => {
    const srv = server({ extensionPins: 'managed' });
    try {
      const port = portOf(srv);
      expect(port.managed?.location).toMatch(/opentable-mcp\.extension-pins\.json$/);
    } finally {
      await srv.close();
    }
  });

  it('is managed by the environment variable', async () => {
    process.env[EXTENSION_PINS_ENV] = 'managed';
    const srv = server();
    try {
      expect(portOf(srv).managed).toBeDefined();
    } finally {
      await srv.close();
    }
  });

  it('ignores FETCHPROXY_TRUST_NEW_EXTENSION in managed mode, and logs that once', async () => {
    process.env[EXTENSION_PINS_ENV] = 'managed';
    process.env.FETCHPROXY_TRUST_NEW_EXTENSION = '1';
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const srv = server();
    try {
      // A re-election builds the port again; the notice is still one line.
      expect(portOf(srv).allowNew).toBe(false);
      expect(portOf(srv).allowNew).toBe(false);
      const notices = warn.mock.calls
        .map((c) => String(c[0]))
        .filter((m) => m.includes('FETCHPROXY_TRUST_NEW_EXTENSION'));
      expect(notices).toHaveLength(1);
      expect(notices[0]).toMatch(/ignor/i);
    } finally {
      await srv.close();
    }
  });

  it('ignores an explicit allowNewExtensionIdentity in managed mode too', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const srv = server({ extensionPins: 'managed', allowNewExtensionIdentity: true });
    try {
      expect(portOf(srv).allowNew).toBe(false);
      expect(warn).toHaveBeenCalled();
    } finally {
      await srv.close();
    }
  });

  it('leaves the environment variable working when unmanaged', async () => {
    process.env.FETCHPROXY_TRUST_NEW_EXTENSION = '1';
    const srv = server();
    try {
      expect(portOf(srv).allowNew).toBe(true);
    } finally {
      await srv.close();
    }
  });
});
