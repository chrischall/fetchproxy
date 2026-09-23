import { describe, it, expect } from 'vitest';
import { KNOWN_CAPABILITIES } from '@fetchproxy/protocol';
import { FetchproxyServer } from '../src/index.js';

// B-QUAL-2: the unknown-capability error listed only fetch/read_cookies.
describe('unknown capability error', () => {
  it('lists every known capability', () => {
    let message = '';
    try {
      new FetchproxyServer({
        serverName: 't',
        version: '0.0.1',
        domains: ['example.com'],
        capabilities: ['read_cookie' as never],
      });
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/unknown capability "read_cookie"/);
    for (const c of KNOWN_CAPABILITIES) expect(message).toContain(JSON.stringify(c));
  });
});
