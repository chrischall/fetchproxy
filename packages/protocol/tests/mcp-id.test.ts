import { describe, it, expect } from 'vitest';
import { generateMcpId, parseMcpId, isValidMcpId } from '../src/mcp-id.js';

describe('mcp-id', () => {
  it('generates id with shape server:version:rand', () => {
    const id = generateMcpId('opentable-mcp', '0.9.1');
    expect(id).toMatch(/^opentable-mcp:0\.9\.1:[0-9a-f]{16}$/);
  });

  it('two calls produce different rand', () => {
    const a = generateMcpId('a', '1.0.0');
    const b = generateMcpId('a', '1.0.0');
    expect(a).not.toBe(b);
  });

  it('parses valid id', () => {
    const id = 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56';
    expect(parseMcpId(id)).toEqual({
      serverName: 'opentable-mcp',
      version: '0.9.1',
      rand: 'a3f7c91d2e8b4f56',
    });
  });

  it('rejects malformed ids', () => {
    expect(isValidMcpId('')).toBe(false);
    expect(isValidMcpId('no-colons')).toBe(false);
    expect(isValidMcpId('a:b')).toBe(false);
    expect(isValidMcpId('a:b:NOTHEX')).toBe(false);
    expect(isValidMcpId('a:b:abc')).toBe(false);  // wrong length
    expect(isValidMcpId('opentable-mcp:0.9.1:a3f7c91d2e8b4f56')).toBe(true);
  });

  it('rejects colons in server name', () => {
    expect(() => generateMcpId('bad:name', '1.0.0')).toThrow();
  });

  it('rejects colons in version', () => {
    expect(() => generateMcpId('opentable-mcp', '1.0:weird')).toThrow();
  });

  it('parseMcpId throws on malformed input', () => {
    // Mirrors isValidMcpId rejections — parseMcpId must throw, not
    // silently return partial parts. Four colons (extra rand fragment),
    // empty serverName, and missing the rand block all hit the
    // throw-on-invalid path.
    expect(() => parseMcpId('no-colons')).toThrow(/invalid mcpId/);
    expect(() => parseMcpId('opentable-mcp:0.9.1:tooShort')).toThrow(/invalid mcpId/);
    expect(() => parseMcpId(':0.9.1:a3f7c91d2e8b4f56')).toThrow(/invalid mcpId/);
    // Extra colons in version slot: ID_RE uses `[^:]+` so an extra colon
    // breaks the parse entirely. Note: this is rejected via the regex
    // not matching, then the !m branch throws.
    expect(() => parseMcpId('a:b:c:a3f7c91d2e8b4f56')).toThrow(/invalid mcpId/);
  });
});
