import { describe, it, expect } from 'vitest';
import { validateFrame } from '../src/index.js';

// B-BUG-9: host → extension notice that a peer MCP's socket closed, so the
// extension can drop that mcpId's session instead of keeping it forever.
describe('peer-gone frame', () => {
  const mcpId = 'opentable-mcp:0.9.1:abc1234567890def';

  it('accepts a well-formed notice', () => {
    expect(validateFrame({ type: 'peer-gone', mcpId })).toEqual({ type: 'peer-gone', mcpId });
  });

  it('rejects a missing or malformed mcpId', () => {
    expect(() => validateFrame({ type: 'peer-gone' })).toThrow(/peer-gone\.mcpId/);
    expect(() => validateFrame({ type: 'peer-gone', mcpId: 'nope' })).toThrow(/peer-gone\.mcpId/);
  });

  it('rejects extra fields', () => {
    expect(() => validateFrame({ type: 'peer-gone', mcpId, extra: 1 })).toThrow(/unexpected/);
  });
});

describe('extension hello accepts (B-BUG-9)', () => {
  const ext = {
    type: 'hello',
    protocolVersion: 4,
    role: 'extension',
    platform: 'chrome',
    extensionId: 'fetchproxy',
    version: '3.2.0',
    identityX25519Pub: 'AAAA',
    identityEd25519Pub: 'AAAA',
    sessionNonce: 'AAAA',
  };
  it('accepts an accepts list', () => {
    expect(() => validateFrame({ ...ext, accepts: ['peer-gone', 'future-thing'] })).not.toThrow();
  });
  it('rejects a non-array accepts', () => {
    expect(() => validateFrame({ ...ext, accepts: 'peer-gone' })).toThrow(/accepts/);
  });
});
