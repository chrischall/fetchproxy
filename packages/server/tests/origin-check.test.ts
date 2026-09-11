import { describe, it, expect, afterEach, beforeEach, vi } from 'vitest';
import { WebSocket } from 'ws';
import type { AddressInfo } from 'node:net';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startHost, originVerdict, ALLOW_LOCAL_ORIGINS_ENV, type HostHandle } from '../src/host.js';
import { electRole } from '../src/election.js';
import { loadOrCreateIdentity } from '../src/identity.js';
import type { ExtensionPin, ExtensionTrustPort } from '../src/extension-trust.js';

function blankTrust(): ExtensionTrustPort {
  let pin: ExtensionPin | null = null;
  return {
    allowNew: false,
    read: async () => pin,
    write: async (next) => {
      pin = next;
    },
  };
}

async function bootHost(): Promise<{ handle: HostHandle; port: number }> {
  const el = await electRole({ host: '127.0.0.1', port: 0 });
  if (el.role !== 'host') throw new Error('expected host');
  const port = (el.server.address() as AddressInfo).port;
  const idDir = mkdtempSync(join(tmpdir(), 'fp-origin-'));
  const id = await loadOrCreateIdentity('opentable-mcp', idDir);
  const handle = await startHost({
    httpServer: el.server,
    ownIdentity: id,
    ownMcpId: 'opentable-mcp:0.9.1:abc1234567890def',
    ownServerName: 'opentable-mcp',
    ownVersion: '0.9.1',
    ownDomains: ['opentable.com'],
    extensionTrust: blankTrust(),
    // Long enough that nothing under test is reaped mid-assertion.
    handshakeTimeoutMs: 60_000,
  });
  return { handle, port };
}

type DialResult = { accepted: true } | { accepted: false; message: string };

/**
 * Dial the concentrator with (or without) an `Origin` header and report which
 * way the upgrade went. A refusal arrives as `ws`'s "Unexpected server
 * response: 403" error, never as an open socket.
 */
function dial(port: number, sockets: WebSocket[], origin?: string): Promise<DialResult> {
  return new Promise((resolve) => {
    const ws = new WebSocket(
      `ws://127.0.0.1:${port}`,
      origin === undefined ? {} : { headers: { Origin: origin } },
    );
    sockets.push(ws);
    ws.once('open', () => resolve({ accepted: true }));
    ws.once('error', (err: Error) => resolve({ accepted: false, message: err.message }));
  });
}

describe('host origin gate (docs/SECURITY.md §T2 defense 2)', () => {
  let host: HostHandle | null = null;
  const sockets: WebSocket[] = [];
  const original = process.env[ALLOW_LOCAL_ORIGINS_ENV];

  beforeEach(() => {
    delete process.env[ALLOW_LOCAL_ORIGINS_ENV];
  });

  afterEach(async () => {
    if (original === undefined) delete process.env[ALLOW_LOCAL_ORIGINS_ENV];
    else process.env[ALLOW_LOCAL_ORIGINS_ENV] = original;
    for (const ws of sockets.splice(0)) {
      try {
        ws.terminate();
      } catch {
        /* already gone */
      }
    }
    if (host) await host.close();
    host = null;
  });

  it('refuses an opaque (null) origin', async () => {
    // A sandboxed iframe, an `srcdoc` document or a `file://` page sends the
    // literal string `null`. None of those is the extension.
    const booted = await bootHost();
    host = booted.handle;
    const res = await dial(booted.port, sockets, 'null');
    expect(res.accepted).toBe(false);
    if (!res.accepted) expect(res.message).toMatch(/403/);
  });

  it('refuses a localhost page origin', async () => {
    // Any dev server, notebook or local app the user happens to have open.
    const booted = await bootHost();
    host = booted.handle;
    const res = await dial(booted.port, sockets, 'http://localhost:3000');
    expect(res.accepted).toBe(false);
    if (!res.accepted) expect(res.message).toMatch(/403/);
  });

  it('refuses a 127.0.0.1 page origin', async () => {
    const booted = await bootHost();
    host = booted.handle;
    const res = await dial(booted.port, sockets, 'http://127.0.0.1:8888');
    expect(res.accepted).toBe(false);
  });

  it('refuses an IPv6 loopback page origin, and offers the escape for it', async () => {
    // A dev server reached over `[::1]` is the same population as one reached
    // over 127.0.0.1: local, plausibly the developer, and owed the remedy.
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const booted = await bootHost();
      host = booted.handle;
      const res = await dial(booted.port, sockets, 'http://[::1]:5173');
      expect(res.accepted).toBe(false);
      const said = warn.mock.calls.map((args) => args.join(' ')).join('\n');
      expect(said).toContain('http://[::1]:5173');
      expect(said).toContain(`${ALLOW_LOCAL_ORIGINS_ENV}=1`);
    } finally {
      warn.mockRestore();
    }
  });

  it("accepts the extension's own origin", async () => {
    const booted = await bootHost();
    host = booted.handle;
    const res = await dial(
      booted.port,
      sockets,
      'chrome-extension://hgmoaheomcbnfnjhcldbeldccmnjlpop',
    );
    expect(res).toEqual({ accepted: true });
  });

  it('refuses a custom-scheme app origin — a Tauri/Capacitor/Electron page is a page', async () => {
    // The gate used to end in a bare `return { allow: true }`, so everything
    // that was not http(s) or `null` was read as "the extension". A packaged
    // desktop or mobile app's page has an origin of its own and is exactly
    // the browsing context this layer refuses.
    const booted = await bootHost();
    host = booted.handle;
    const res = await dial(booted.port, sockets, 'tauri://localhost');
    expect(res.accepted).toBe(false);
    if (!res.accepted) expect(res.message).toMatch(/403/);
  });

  it("accepts the other two browsers' extension schemes", async () => {
    const booted = await bootHost();
    host = booted.handle;
    expect(
      await dial(booted.port, sockets, 'moz-extension://abcdef01-2345-6789-abcd-ef0123456789'),
    ).toEqual({
      accepted: true,
    });
    expect(await dial(booted.port, sockets, 'safari-web-extension://ABCDEF01-2345')).toEqual({
      accepted: true,
    });
  });

  describe('the admitted population is an allowlist, not a fallthrough', () => {
    // Read straight off the exported decision so a scheme nobody thought of
    // is covered by the same assertion as the ones that have been seen.
    const notExtensions = [
      'tauri://localhost',
      'capacitor://localhost',
      'ionic://localhost',
      'app://.',
      'about://x',
      'file://',
      // A present `Origin:` header with no value. Not the same as absent.
      '',
    ];

    for (const origin of notExtensions) {
      it(`refuses ${JSON.stringify(origin)} whether or not the escape is set`, () => {
        expect(originVerdict(origin, false)).toEqual({
          allow: false,
          reason: 'origin not allowed',
          escapable: false,
        });
        // The escape is for null and localhost. It does not widen this.
        expect(originVerdict(origin, true)).toEqual({
          allow: false,
          reason: 'origin not allowed',
          escapable: false,
        });
      });
    }
  });

  it('accepts an upgrade that sends no Origin at all — that is a peer', async () => {
    // A Node `ws` client sends no Origin header; peers dial this port.
    const booted = await bootHost();
    host = booted.handle;
    const res = await dial(booted.port, sockets);
    expect(res).toEqual({ accepted: true });
  });

  it('refuses a public origin', async () => {
    const booted = await bootHost();
    host = booted.handle;
    const res = await dial(booted.port, sockets, 'https://evil.com');
    expect(res.accepted).toBe(false);
  });

  it('tells a developer who trips it what to set', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const booted = await bootHost();
      host = booted.handle;
      await dial(booted.port, sockets, 'http://localhost:3000');
      const said = warn.mock.calls.map((args) => args.join(' ')).join('\n');
      expect(said).toContain('http://localhost:3000');
      expect(said).toContain(`${ALLOW_LOCAL_ORIGINS_ENV}=1`);
    } finally {
      warn.mockRestore();
    }
  });

  it('does not offer the escape for a public origin, which it would not admit', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    try {
      const booted = await bootHost();
      host = booted.handle;
      await dial(booted.port, sockets, 'https://evil.com');
      const said = warn.mock.calls.map((args) => args.join(' ')).join('\n');
      expect(said).not.toContain(ALLOW_LOCAL_ORIGINS_ENV);
    } finally {
      warn.mockRestore();
    }
  });

  describe(`with ${ALLOW_LOCAL_ORIGINS_ENV}=1`, () => {
    it('accepts a null origin', async () => {
      process.env[ALLOW_LOCAL_ORIGINS_ENV] = '1';
      const booted = await bootHost();
      host = booted.handle;
      expect(await dial(booted.port, sockets, 'null')).toEqual({ accepted: true });
    });

    it('accepts a localhost page origin', async () => {
      process.env[ALLOW_LOCAL_ORIGINS_ENV] = '1';
      const booted = await bootHost();
      host = booted.handle;
      expect(await dial(booted.port, sockets, 'http://localhost:3000')).toEqual({
        accepted: true,
      });
    });

    it('accepts an IPv6 loopback page origin', async () => {
      process.env[ALLOW_LOCAL_ORIGINS_ENV] = '1';
      const booted = await bootHost();
      host = booted.handle;
      expect(await dial(booted.port, sockets, 'http://[::1]:5173')).toEqual({ accepted: true });
    });

    it('still refuses a public origin — it is an escape for local ones only', async () => {
      process.env[ALLOW_LOCAL_ORIGINS_ENV] = '1';
      const booted = await bootHost();
      host = booted.handle;
      const res = await dial(booted.port, sockets, 'https://evil.com');
      expect(res.accepted).toBe(false);
    });
  });

  describe('a value that is not exactly 1', () => {
    // A value that half works is how a development escape survives into a
    // deployment, so anything but `1` is a typo and is read as off.
    for (const raw of ['true', 'yes', '0']) {
      it(`${JSON.stringify(raw)} does not turn it on`, async () => {
        vi.spyOn(console, 'warn').mockImplementation(() => {});
        try {
          process.env[ALLOW_LOCAL_ORIGINS_ENV] = raw;
          const booted = await bootHost();
          host = booted.handle;
          const res = await dial(booted.port, sockets, 'http://localhost:3000');
          expect(res.accepted).toBe(false);
        } finally {
          vi.mocked(console.warn).mockRestore();
        }
      });
    }

    it('says the value was ignored and names the one that works', async () => {
      const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
      try {
        process.env[ALLOW_LOCAL_ORIGINS_ENV] = 'true';
        const booted = await bootHost();
        host = booted.handle;
        const said = warn.mock.calls.map((args) => args.join(' ')).join('\n');
        expect(said).toContain(`ignoring ${ALLOW_LOCAL_ORIGINS_ENV}="true"`);
        expect(said).toMatch(/only value that turns it on is 1/);
      } finally {
        warn.mockRestore();
      }
    });
  });
});
