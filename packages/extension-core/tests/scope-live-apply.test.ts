import { describe, it, expect } from 'vitest';
import {
  liveScopeApplications,
  applyGrantedScopeToSession,
  sessionScopeSnapshot,
  grantedScopeFromApproval,
  type AnyPendingRecord,
} from '../src/background.js';

// A scope-update record where the MCP grew from ['fetch'] to add
// 'capture_redirect' (the musescore download case). Minimal-but-valid.
function scopeUpdateRecord(
  overrides: Partial<Extract<AnyPendingRecord, { kind: 'scope-update' }>> = {},
): Extract<AnyPendingRecord, { kind: 'scope-update' }> {
  return {
    kind: 'scope-update',
    key: 'idhash:scopehash',
    identityHash: 'idhash',
    serverName: 'musescore-mcp',
    version: '0.5.0',
    mcpIds: ['musescore-mcp:0.5.0:aabb0001'],
    domains: ['musescore.com'],
    identityX25519Pub: 'x',
    identityEd25519Pub: 'e',
    capabilities: ['fetch', 'capture_redirect'],
    cookieKeys: [],
    localStorageKeys: [],
    sessionStorageKeys: [],
    captureHeaders: [],
    indexedDbScopes: [],
    localStoragePointers: [],
    sessionStoragePointers: [],
    previousScope: {
      capabilities: ['fetch'],
      cookieKeys: [],
      localStorageKeys: [],
      sessionStorageKeys: [],
      captureHeaders: [],
      indexedDbScopes: [],
      localStoragePointers: [],
      sessionStoragePointers: [],
    },
    ...overrides,
  };
}

describe('grantedScopeFromApproval', () => {
  it('mirrors the approved record scope tables', () => {
    const rec = scopeUpdateRecord({
      capabilities: ['fetch', 'capture_redirect'],
      captureHeaders: [{ host: 'musescore.com', path: '/x*', headerName: 'cookie' }],
    });
    const scope = grantedScopeFromApproval(rec);
    expect(scope.capabilities).toEqual(['fetch', 'capture_redirect']);
    expect(scope.captureHeaders).toEqual([
      { host: 'musescore.com', path: '/x*', headerName: 'cookie' },
    ]);
  });

  it('defaults capabilities to [fetch] when the record omits them', () => {
    const rec = scopeUpdateRecord({ capabilities: [] });
    expect(grantedScopeFromApproval(rec).capabilities).toEqual(['fetch']);
  });
});

describe('liveScopeApplications', () => {
  it('targets only currently-live mcpIds of a scope-update', () => {
    const rec = scopeUpdateRecord({ mcpIds: ['m-live', 'm-dead'] });
    const apps = liveScopeApplications(rec, (id) => id === 'm-live');
    expect(apps.map((a) => a.mcpId)).toEqual(['m-live']);
    expect(apps[0].scope.capabilities).toContain('capture_redirect');
  });

  it('returns nothing when no targeted session is live', () => {
    const rec = scopeUpdateRecord({ mcpIds: ['m-dead'] });
    expect(liveScopeApplications(rec, () => false)).toEqual([]);
  });

  it('ignores non-scope-update (pair) records even when live', () => {
    // A pair approval establishes its sessions separately (rekey + ReadyFrame),
    // so liveScopeApplications must never target it — even if isLive is true.
    const pair = {
      kind: 'pair',
      key: 'idhash:scopehash',
      identityHash: 'idhash',
      serverName: 'musescore-mcp',
      version: '0.5.0',
      mcpIds: ['m-live'],
      domains: ['musescore.com'],
      identityX25519Pub: 'x',
      identityEd25519Pub: 'e',
      sessionNonces: { 'm-live': 'nonce' },
      capabilities: ['fetch', 'capture_redirect'],
      cookieKeys: [],
      localStorageKeys: [],
      sessionStorageKeys: [],
      captureHeaders: [],
      indexedDbScopes: [],
      localStoragePointers: [],
      sessionStoragePointers: [],
      pairCode: '1234',
    } as unknown as AnyPendingRecord;
    expect(liveScopeApplications(pair, () => true)).toEqual([]);
  });
});

describe('applyGrantedScopeToSession + sessionScopeSnapshot', () => {
  it('returns undefined for an mcpId with no live scope', () => {
    expect(sessionScopeSnapshot('never-seen')).toBeUndefined();
  });

  it('widens a live session capability set in place (no reconnect)', () => {
    const mcpId = 'apply-test:0.5.0:cap';
    // Initial granted scope (post-connect intersection): fetch only.
    applyGrantedScopeToSession(mcpId, grantedScopeFromApproval(
      scopeUpdateRecord({ capabilities: ['fetch'] }),
    ));
    expect(sessionScopeSnapshot(mcpId)?.capabilities).toEqual(['fetch']);

    // User grants the scope-update → re-apply the wider scope live.
    applyGrantedScopeToSession(mcpId, grantedScopeFromApproval(
      scopeUpdateRecord({ capabilities: ['fetch', 'capture_redirect'] }),
    ));
    // The map the request handler reads now includes the new capability —
    // a capture_redirect request would pass the gate without reconnecting.
    expect(sessionScopeSnapshot(mcpId)?.capabilities).toEqual([
      'fetch',
      'capture_redirect',
    ]);
  });

  it('round-trips the non-capability scope tables', () => {
    const mcpId = 'apply-test:0.5.0:tables';
    applyGrantedScopeToSession(mcpId, grantedScopeFromApproval(
      scopeUpdateRecord({
        captureHeaders: [{ host: 'musescore.com', headerName: 'cookie' }],
        cookieKeys: ['sid'],
      }),
    ));
    const snap = sessionScopeSnapshot(mcpId);
    expect(snap?.captureHeaders).toEqual([
      { host: 'musescore.com', headerName: 'cookie' },
    ]);
    expect(snap?.cookieKeys).toEqual(['sid']);
  });
});
