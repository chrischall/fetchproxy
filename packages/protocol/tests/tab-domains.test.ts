import { describe, it, expect } from 'vitest';
import { validateFrame } from '../src/validate.js';

const hello = {
  type: 'hello',
  protocolVersion: 4,
  role: 'server',
  mcpId: 'teams-mcp:1.0.0:a3f7c91d2e8b4f56',
  serverName: 'teams-mcp',
  version: '1.0.0',
  domains: ['teams.cloud.microsoft', 'sharepoint.com'],
  identityX25519Pub: 'AAAA',
  identityEd25519Pub: 'AAAA',
  sessionNonce: 'AAAA',
  sessionPub: 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=',
  answersExtNonce: 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=',
  sessionSig: 'AAAA',
};

describe('validateFrame (hello.tabDomains)', () => {
  it('accepts a hello without it', () => {
    expect(() => validateFrame(hello)).not.toThrow();
  });

  it('accepts a subset of the declared domains', () => {
    expect(() => validateFrame({ ...hello, tabDomains: ['teams.cloud.microsoft'] })).not.toThrow();
  });

  it.each([
    ['not an array', 'teams.cloud.microsoft'],
    ['empty', []],
    ['a non-string entry', [1]],
    ['a domain that was not declared', ['evil.example']],
    ['a subdomain of a declared domain', ['x.sharepoint.com']],
  ])('rejects %s', (_name, tabDomains) => {
    expect(() => validateFrame({ ...hello, tabDomains })).toThrow(/hello\.tabDomains/);
  });
});
