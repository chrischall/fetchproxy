import { describe, it, expect } from 'vitest';
import { generateIdentity } from '../src/identity.js';
import { buildTestPeerHello } from './helpers/peer-hello.js';
import { FetchproxyServer } from '../src/ws-server.js';

const domains = ['teams.cloud.microsoft', 'sharepoint.com'];
const base = { identity: await generateIdentity(), mcpId: 'x-mcp:1.0.0:a3f7c91d2e8b4f56', serverName: 'x-mcp', version: '1.0.0', domains };

describe('hello tabDomains', () => {
  it('puts tabDomains on the wire when declared', async () => {
    const hello = await buildTestPeerHello({ ...base, tabDomains: ['teams.cloud.microsoft'] });
    expect(hello.tabDomains).toEqual(['teams.cloud.microsoft']);
  });

  it('omits the field when not declared, so a hello is unchanged for everyone else', async () => {
    expect(await buildTestPeerHello(base)).not.toHaveProperty('tabDomains');
  });

  it('refuses at construction a tab domain outside the declared domains', () => {
    expect(() => new FetchproxyServer({ serverName: 'x', version: '1', domains, tabDomains: ['evil.example'] })).toThrow(/tabDomains/);
  });

  it('refuses at construction an empty list', () => {
    expect(() => new FetchproxyServer({ serverName: 'x', version: '1', domains, tabDomains: [] })).toThrow(/tabDomains/);
  });

  it('constructs with a subset', () => {
    expect(() => new FetchproxyServer({ serverName: 'x', version: '1', domains, tabDomains: ['sharepoint.com'] })).not.toThrow();
  });
});
