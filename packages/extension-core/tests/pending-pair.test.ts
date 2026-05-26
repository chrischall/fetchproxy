import { describe, it, expect } from 'vitest';
import { normalisePendingPair } from '../src/lib/pending-pair.js';

interface Rec {
  mcpId: string;
  serverName: string;
}

describe('normalisePendingPair', () => {
  it('returns empty dict for non-object inputs', () => {
    expect(normalisePendingPair(undefined)).toEqual({});
    expect(normalisePendingPair(null)).toEqual({});
    expect(normalisePendingPair('foo')).toEqual({});
    expect(normalisePendingPair(42)).toEqual({});
    expect(normalisePendingPair(true)).toEqual({});
  });

  it('wraps legacy single-record shape into a one-entry dict', () => {
    const legacy = { mcpId: 'foo:0.0.1:abcdef0123456789', serverName: 'foo-mcp' };
    const out = normalisePendingPair<Rec>(legacy);
    expect(Object.keys(out)).toEqual(['foo:0.0.1:abcdef0123456789']);
    expect(out['foo:0.0.1:abcdef0123456789']).toBe(legacy);
  });

  it('keeps a well-formed dict as-is', () => {
    const dict = {
      'foo:0.0.1:abcdef0123456789': {
        mcpId: 'foo:0.0.1:abcdef0123456789',
        serverName: 'foo-mcp',
      },
      'bar:0.0.1:1234567890abcdef': {
        mcpId: 'bar:0.0.1:1234567890abcdef',
        serverName: 'bar-mcp',
      },
    };
    const out = normalisePendingPair<Rec>(dict);
    expect(Object.keys(out).sort()).toEqual([
      'bar:0.0.1:1234567890abcdef',
      'foo:0.0.1:abcdef0123456789',
    ]);
  });

  it('drops dict entries whose value is not a record with mcpId', () => {
    const dict = {
      good: { mcpId: 'foo:0.0.1:abcdef0123456789', serverName: 'foo-mcp' },
      'no-mcpid': { serverName: 'oops' },
      'string-value': 'nope',
      'null-value': null,
    };
    const out = normalisePendingPair<Rec>(dict);
    expect(Object.keys(out)).toEqual(['good']);
  });

  it('legacy/dict ambiguity: a record with both `mcpId` and other keys is still treated as a single legacy record (mcpId field is the discriminator)', () => {
    const looksLegacy = {
      mcpId: 'foo:0.0.1:abcdef0123456789',
      serverName: 'foo-mcp',
      // Even if other keys look mcpId-shaped, the top-level `mcpId`
      // string wins — back-compat with pre-0.5.2 storage.
      'extra:0.0.0:0000000000000000': 'whatever',
    };
    const out = normalisePendingPair<Rec>(looksLegacy);
    expect(Object.keys(out)).toEqual(['foo:0.0.1:abcdef0123456789']);
  });
});
