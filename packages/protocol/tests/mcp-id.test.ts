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
});
