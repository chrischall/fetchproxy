import { describe, it, expect } from 'vitest';
import { isPublicSuffix } from '../src/public-suffix.js';
import { validateFrame, ProtocolError } from '../src/validate.js';

describe('isPublicSuffix', () => {
  it('treats any single-label host as a public suffix (every TLD is one)', () => {
    for (const tld of ['com', 'uk', 'app', 'dev', 'io']) {
      expect(isPublicSuffix(tld), tld).toBe(true);
    }
  });

  it('recognises multi-label ccTLD suffixes through the generative rule', () => {
    for (const s of ['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'edu.au', 'co.jp', 'co.za', 'com.br', 'gob.mx']) {
      expect(isPublicSuffix(s), s).toBe(true);
    }
  });

  it('recognises listed ccTLD administrative levels the generative rule leaves out', () => {
    for (const s of ['ne.jp', 'or.jp', 'go.kr', 'me.uk', 'in.th']) {
      expect(isPublicSuffix(s), s).toBe(true);
    }
  });

  it('recognises listed vendor (private) suffixes', () => {
    for (const s of [
      'github.io',
      'vercel.app',
      'herokuapp.com',
      'pages.dev',
      'workers.dev',
      's3.amazonaws.com',
      'azurewebsites.net',
      'blogspot.com',
    ]) {
      expect(isPublicSuffix(s), s).toBe(true);
    }
  });

  it('does not fire on ordinary registrable domains', () => {
    for (const s of [
      'opentable.com',
      'bbc.co.uk',
      'mysite.github.io',
      'example.vercel.app',
      'amazon.com',
      'ourfamilywizard.com',
    ]) {
      expect(isPublicSuffix(s), s).toBe(false);
    }
  });

  it('does not fire on registrable two-label hosts the generative rule deliberately excludes', () => {
    // `ad.nl` (a Dutch newspaper) and `ne.ch` (a Swiss canton) are real
    // registrable domains shaped exactly like a ccTLD administrative level.
    for (const s of ['ad.nl', 'ne.ch', 'gr.ch', 'web.de']) {
      expect(isPublicSuffix(s), s).toBe(false);
    }
  });

  it('normalises case and a trailing dot', () => {
    expect(isPublicSuffix('CO.UK')).toBe(true);
    expect(isPublicSuffix('co.uk.')).toBe(true);
    expect(isPublicSuffix('GitHub.IO')).toBe(true);
    expect(isPublicSuffix('BBC.CO.UK')).toBe(false);
  });

  it('answers false for malformed input rather than throwing', () => {
    for (const s of ['', '.', '..', 'a..b']) {
      expect(isPublicSuffix(s), JSON.stringify(s)).toBe(false);
    }
  });
});

describe('hello.domains refuses a public suffix', () => {
  const validHello = {
    type: 'hello',
    protocolVersion: 3,
    role: 'server',
    mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
    serverName: 'opentable-mcp',
    version: '0.9.1',
    domains: ['opentable.com'],
    identityX25519Pub: 'AAAA',
    identityEd25519Pub: 'AAAA',
    sessionNonce: 'AAAA',
    sessionSig: 'AAAA',
  };

  it('refuses a multi-label suffix', () => {
    expect(() => validateFrame({ ...validHello, domains: ['co.uk'] })).toThrow(ProtocolError);
    expect(() => validateFrame({ ...validHello, domains: ['co.uk'] })).toThrow(
      /hello\.domains.*public suffix/,
    );
  });

  it('refuses a vendor suffix', () => {
    expect(() => validateFrame({ ...validHello, domains: ['github.io'] })).toThrow(
      /hello\.domains.*public suffix/,
    );
  });

  it('refuses a suffix hiding among good entries', () => {
    expect(() =>
      validateFrame({ ...validHello, domains: ['opentable.com', 'vercel.app'] }),
    ).toThrow(/hello\.domains.*public suffix/);
  });

  it('still accepts a registrable domain under one of those suffixes', () => {
    expect(() => validateFrame({ ...validHello, domains: ['bbc.co.uk'] })).not.toThrow();
    expect(() => validateFrame({ ...validHello, domains: ['mysite.github.io'] })).not.toThrow();
  });

  it('a single-label entry is still refused by the hostname shape, before the suffix check', () => {
    expect(() => validateFrame({ ...validHello, domains: ['com'] })).toThrow(/invalid hostname/);
  });
});
