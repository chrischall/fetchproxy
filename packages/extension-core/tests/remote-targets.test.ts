import { describe, it, expect } from 'vitest';
import {
  BRIDGE_SUBPROTOCOL,
  MAX_REMOTE_TARGETS,
  bridgeSubprotocols,
  normaliseRemoteTargets,
  remoteTargetDisplay,
  validateRemoteTargetToken,
  validateRemoteTargetUrl,
} from '../src/remote-targets.js';

describe('validateRemoteTargetUrl', () => {
  it('accepts wss://', () => {
    expect(validateRemoteTargetUrl('wss://mcp.nullnet.app/bridge').ok).toBe(true);
  });

  it('refuses plaintext ws:// to a non-loopback host', () => {
    const v = validateRemoteTargetUrl('ws://mcp.nullnet.app/bridge');
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toMatch(/loopback/);
  });

  it('allows ws:// to a loopback host, which is where the rig runs', () => {
    for (const url of ['ws://127.0.0.1:37149', 'ws://localhost:8787/bridge', 'ws://[::1]:9/x']) {
      expect(validateRemoteTargetUrl(url).ok, url).toBe(true);
    }
  });

  it('refuses a scheme that is not a WebSocket scheme', () => {
    for (const url of ['https://mcp.nullnet.app/bridge', 'file:///etc/passwd']) {
      expect(validateRemoteTargetUrl(url).ok, url).toBe(false);
    }
  });

  it('refuses credentials in the URL — the token has a field of its own', () => {
    const v = validateRemoteTargetUrl('wss://user:pw@mcp.nullnet.app/bridge');
    expect(v.ok).toBe(false);
    if (!v.ok) expect(v.reason).toMatch(/token field/);
  });

  it('refuses something that is not a URL at all', () => {
    expect(validateRemoteTargetUrl('mcp.nullnet.app').ok).toBe(false);
  });
});

describe('validateRemoteTargetToken', () => {
  it('accepts an unpadded base64url device token', () => {
    expect(validateRemoteTargetToken('mcpb_ab-cd_ef123').ok).toBe(true);
  });

  it('refuses what a WebSocket subprotocol cannot carry', () => {
    // Each of these makes `new WebSocket(url, protocols)` throw a SyntaxError,
    // which surfaces at connect time inside a retry loop rather than at save
    // time where the user can read it.
    for (const bad of ['', 'has space', 'padded==', 'a,b', 'a/b']) {
      expect(validateRemoteTargetToken(bad).ok, JSON.stringify(bad)).toBe(false);
    }
  });
});

describe('bridgeSubprotocols', () => {
  it('names the contract first and carries the token second', () => {
    expect(bridgeSubprotocols('mcpb_x')).toEqual([BRIDGE_SUBPROTOCOL, 'fetchproxy.token.mcpb_x']);
  });
});

describe('normaliseRemoteTargets', () => {
  const good = { id: 't1', url: 'wss://mcp.nullnet.app/bridge', token: 'mcpb_x' };

  it('reads a well-formed row and defaults it to enabled', () => {
    expect(normaliseRemoteTargets([good])).toEqual([{ ...good, enabled: true }]);
  });

  it('keeps a disabled row, disabled', () => {
    expect(normaliseRemoteTargets([{ ...good, enabled: false }])[0]?.enabled).toBe(false);
  });

  it('drops rows it cannot validate rather than repairing them', () => {
    const rows = [
      { ...good, url: 'ws://evil.example/bridge' },
      { ...good, token: 'bad token' },
      { ...good, id: '' },
      { url: 'wss://a.example/b', token: 'x' },
      'nonsense',
      null,
      good,
    ];
    expect(normaliseRemoteTargets(rows)).toEqual([{ ...good, enabled: true }]);
  });

  it('drops duplicates by id and by url — one link per target', () => {
    const rows = [
      good,
      { ...good, url: 'wss://other.example/bridge' },
      { id: 't2', url: good.url, token: 'mcpb_y' },
    ];
    expect(normaliseRemoteTargets(rows).map((t) => t.id)).toEqual(['t1']);
  });

  it('caps the list so a hostile storage write cannot fan out sockets', () => {
    const rows = Array.from({ length: MAX_REMOTE_TARGETS + 3 }, (_, i) => ({
      id: `t${i}`,
      url: `wss://h${i}.example/bridge`,
      token: 'mcpb_x',
    }));
    expect(normaliseRemoteTargets(rows)).toHaveLength(MAX_REMOTE_TARGETS);
  });

  it('treats anything that is not an array as no targets', () => {
    for (const stored of [undefined, null, {}, 'wss://x', 7]) {
      expect(normaliseRemoteTargets(stored), String(stored)).toEqual([]);
    }
  });
});

describe('remoteTargetDisplay', () => {
  it('prefers the label but always shows the URL', () => {
    expect(remoteTargetDisplay({ id: 'a', url: 'wss://h/b', token: 't', enabled: true })).toBe(
      'wss://h/b',
    );
    expect(
      remoteTargetDisplay({ id: 'a', url: 'wss://h/b', token: 't', label: 'mcp-host', enabled: true }),
    ).toBe('mcp-host (wss://h/b)');
  });

  it('never shows the token', () => {
    const shown = remoteTargetDisplay({ id: 'a', url: 'wss://h/b', token: 'mcpb_secret', enabled: true });
    expect(shown).not.toContain('mcpb_secret');
  });
});
