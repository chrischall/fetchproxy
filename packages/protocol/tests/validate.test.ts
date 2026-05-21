import { describe, it, expect } from 'vitest';
import { validateFrame, validateInnerFrame, ProtocolError } from '../src/validate.js';

describe('validateFrame', () => {
  describe('hello (server, v2)', () => {
    const validHello = {
      type: 'hello',
      protocolVersion: 2,
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

    it('accepts valid', () => {
      expect(() => validateFrame(validHello)).not.toThrow();
    });

    it('accepts multiple domains', () => {
      expect(() => validateFrame({ ...validHello, domains: ['a.com', 'b.com'] })).not.toThrow();
    });

    it('rejects when mcpId is missing', () => {
      const { mcpId, ...bad } = validHello;
      expect(() => validateFrame(bad)).toThrow(ProtocolError);
    });

    it('rejects bad mcpId format', () => {
      expect(() => validateFrame({ ...validHello, mcpId: 'no-colons' })).toThrow(/mcpId/);
    });

    it('rejects wrong protocolVersion', () => {
      expect(() => validateFrame({ ...validHello, protocolVersion: 1 })).toThrow(/protocolVersion/);
      expect(() => validateFrame({ ...validHello, protocolVersion: 3 })).toThrow(/protocolVersion/);
    });

    it('rejects non-base64 identityX25519Pub', () => {
      expect(() => validateFrame({ ...validHello, identityX25519Pub: '!!!' })).toThrow(/identityX25519Pub/);
    });

    it('rejects empty domains array', () => {
      expect(() => validateFrame({ ...validHello, domains: [] })).toThrow(/domains/);
    });

    it('rejects non-array domains', () => {
      expect(() => validateFrame({ ...validHello, domains: 'opentable.com' })).toThrow(/domains/);
    });

    it('rejects missing domains field', () => {
      const { domains, ...bad } = validHello;
      expect(() => validateFrame(bad)).toThrow(/domains/);
    });

    it('rejects non-string domain entry', () => {
      expect(() => validateFrame({ ...validHello, domains: ['ok.com', 42] })).toThrow(/domains/);
    });

    it('rejects bad hostname in domains', () => {
      expect(() => validateFrame({ ...validHello, domains: ['not a host'] })).toThrow(/domains/);
      expect(() => validateFrame({ ...validHello, domains: [''] })).toThrow(/domains/);
      expect(() => validateFrame({ ...validHello, domains: ['has/slash.com'] })).toThrow(/domains/);
      expect(() => validateFrame({ ...validHello, domains: ['ok.com', '!!!'] })).toThrow(/domains/);
    });

    it('accepts hello without capabilities (defaults to fetch downstream)', () => {
      expect(() => validateFrame(validHello)).not.toThrow();
    });

    it("accepts capabilities: ['fetch']", () => {
      expect(() =>
        validateFrame({ ...validHello, capabilities: ['fetch'] }),
      ).not.toThrow();
    });

    it("accepts capabilities: ['read_cookies']", () => {
      expect(() =>
        validateFrame({ ...validHello, capabilities: ['read_cookies'] }),
      ).not.toThrow();
    });

    it("accepts capabilities: ['fetch', 'read_cookies']", () => {
      expect(() =>
        validateFrame({ ...validHello, capabilities: ['fetch', 'read_cookies'] }),
      ).not.toThrow();
    });

    it('rejects empty capabilities array', () => {
      expect(() =>
        validateFrame({ ...validHello, capabilities: [] }),
      ).toThrow(/capabilities/);
    });

    it('rejects unknown capability', () => {
      expect(() =>
        validateFrame({ ...validHello, capabilities: ['frobnicate'] }),
      ).toThrow(/capabilities/);
    });

    it('rejects non-array capabilities', () => {
      expect(() =>
        validateFrame({ ...validHello, capabilities: 'fetch' }),
      ).toThrow(/capabilities/);
    });

    it('rejects non-string capability entry', () => {
      expect(() =>
        validateFrame({ ...validHello, capabilities: ['fetch', 42] }),
      ).toThrow(/capabilities/);
    });

    // 0.3.0: three new capabilities for session-bootstrap.
    it("accepts capabilities: ['read_local_storage']", () => {
      expect(() =>
        validateFrame({ ...validHello, capabilities: ['read_local_storage'] }),
      ).not.toThrow();
    });

    it("accepts capabilities: ['read_session_storage']", () => {
      expect(() =>
        validateFrame({ ...validHello, capabilities: ['read_session_storage'] }),
      ).not.toThrow();
    });

    it("accepts capabilities: ['capture_request_header']", () => {
      expect(() =>
        validateFrame({ ...validHello, capabilities: ['capture_request_header'] }),
      ).not.toThrow();
    });

    it('accepts all five 0.3.0 capabilities together', () => {
      expect(() =>
        validateFrame({
          ...validHello,
          capabilities: [
            'fetch',
            'read_cookies',
            'read_local_storage',
            'read_session_storage',
            'capture_request_header',
          ],
        }),
      ).not.toThrow();
    });
  });

  // 0.3.0: declared scope fields on the server hello.
  describe('hello (server, 0.3.0 scope decls)', () => {
    const validHello = {
      type: 'hello',
      protocolVersion: 2,
      role: 'server',
      mcpId: 'ofw-mcp:0.5.0:a3f7c91d2e8b4f56',
      serverName: 'ofw-mcp',
      version: '0.5.0',
      domains: ['ourfamilywizard.com'],
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AAAA',
      sessionSig: 'AAAA',
    };

    it('accepts hello with all four scope fields', () => {
      expect(() =>
        validateFrame({
          ...validHello,
          capabilities: [
            'fetch',
            'read_cookies',
            'read_local_storage',
            'read_session_storage',
            'capture_request_header',
          ],
          cookieKeys: ['MTOKEN', 'CKAT'],
          localStorageKeys: ['auth', 'tokenExpiry'],
          sessionStorageKeys: ['anon-id'],
          captureHeaders: [
            { urlPattern: 'https://api.honeybook.com/api/v2/*', headerName: 'hb-api-fingerprint' },
          ],
        }),
      ).not.toThrow();
    });

    it('accepts hello with only localStorageKeys (others default to absent)', () => {
      expect(() =>
        validateFrame({
          ...validHello,
          capabilities: ['fetch', 'read_local_storage'],
          localStorageKeys: ['auth'],
        }),
      ).not.toThrow();
    });

    it('accepts hello with empty scope arrays', () => {
      expect(() =>
        validateFrame({
          ...validHello,
          cookieKeys: [],
          localStorageKeys: [],
          sessionStorageKeys: [],
          captureHeaders: [],
        }),
      ).not.toThrow();
    });

    it('rejects duplicate cookie keys', () => {
      expect(() =>
        validateFrame({ ...validHello, cookieKeys: ['MTOKEN', 'MTOKEN'] }),
      ).toThrow(/cookieKeys.*duplicate/);
    });

    it('rejects duplicate localStorage keys', () => {
      expect(() =>
        validateFrame({ ...validHello, localStorageKeys: ['x', 'x'] }),
      ).toThrow(/localStorageKeys.*duplicate/);
    });

    it('rejects duplicate sessionStorage keys', () => {
      expect(() =>
        validateFrame({ ...validHello, sessionStorageKeys: ['x', 'x'] }),
      ).toThrow(/sessionStorageKeys.*duplicate/);
    });

    it('rejects illegal chars in cookie keys', () => {
      expect(() =>
        validateFrame({ ...validHello, cookieKeys: ['has space'] }),
      ).toThrow(/cookieKeys.*invalid key/);
    });

    // 0.4.0: glob patterns in declared keys.
    it('accepts trailing-* glob with literal prefix', () => {
      expect(() =>
        validateFrame({ ...validHello, cookieKeys: ['feh--*'] }),
      ).not.toThrow();
    });

    it('accepts trailing-* glob in localStorageKeys', () => {
      expect(() =>
        validateFrame({ ...validHello, localStorageKeys: ['auth_*'] }),
      ).not.toThrow();
    });

    it('rejects bare * glob (no literal prefix)', () => {
      expect(() =>
        validateFrame({ ...validHello, cookieKeys: ['*'] }),
      ).toThrow(/cookieKeys.*invalid key/);
    });

    it('rejects leading-* glob', () => {
      expect(() =>
        validateFrame({ ...validHello, cookieKeys: ['*foo'] }),
      ).toThrow(/cookieKeys.*invalid key/);
    });

    it('rejects middle-* glob', () => {
      expect(() =>
        validateFrame({ ...validHello, cookieKeys: ['foo*bar'] }),
      ).toThrow(/cookieKeys.*invalid key/);
    });

    it('rejects illegal chars in localStorage keys', () => {
      expect(() =>
        validateFrame({ ...validHello, localStorageKeys: ['has/slash'] }),
      ).toThrow(/localStorageKeys.*invalid key/);
    });

    it('rejects empty-string key', () => {
      expect(() =>
        validateFrame({ ...validHello, cookieKeys: [''] }),
      ).toThrow(/cookieKeys.*invalid key/);
    });

    it('rejects non-array cookieKeys', () => {
      expect(() =>
        validateFrame({ ...validHello, cookieKeys: 'MTOKEN' }),
      ).toThrow(/cookieKeys/);
    });

    it('rejects non-array captureHeaders', () => {
      expect(() =>
        validateFrame({ ...validHello, captureHeaders: {} }),
      ).toThrow(/captureHeaders/);
    });

    it('rejects captureHeaders entry missing urlPattern', () => {
      expect(() =>
        validateFrame({
          ...validHello,
          captureHeaders: [{ headerName: 'X-Foo' }],
        }),
      ).toThrow(/captureHeaders.*urlPattern/);
    });

    it('rejects captureHeaders entry missing headerName', () => {
      expect(() =>
        validateFrame({
          ...validHello,
          captureHeaders: [{ urlPattern: 'https://x.com/api/*' }],
        }),
      ).toThrow(/captureHeaders.*headerName/);
    });

    it('rejects captureHeaders entry with non-https urlPattern', () => {
      expect(() =>
        validateFrame({
          ...validHello,
          captureHeaders: [{ urlPattern: 'http://x.com/api/*', headerName: 'X-Foo' }],
        }),
      ).toThrow(/captureHeaders.*urlPattern/);
    });

    it('rejects captureHeaders entry with wildcard in host', () => {
      expect(() =>
        validateFrame({
          ...validHello,
          captureHeaders: [{ urlPattern: 'https://*.x.com/api/*', headerName: 'X-Foo' }],
        }),
      ).toThrow(/captureHeaders.*urlPattern/);
    });

    it('rejects duplicate captureHeader pair', () => {
      expect(() =>
        validateFrame({
          ...validHello,
          captureHeaders: [
            { urlPattern: 'https://x.com/api/*', headerName: 'X-Foo' },
            { urlPattern: 'https://x.com/api/*', headerName: 'X-Foo' },
          ],
        }),
      ).toThrow(/captureHeaders.*duplicate/);
    });

    it('rejects captureHeaders header with illegal chars', () => {
      expect(() =>
        validateFrame({
          ...validHello,
          captureHeaders: [{ urlPattern: 'https://x.com/api/*', headerName: 'has space' }],
        }),
      ).toThrow(/captureHeaders.*headerName/);
    });
  });

  describe('hello (extension, v2)', () => {
    const validExtHello = {
      type: 'hello',
      protocolVersion: 2,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.4.0',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AAAA',
    };

    it('accepts valid', () => {
      expect(() => validateFrame(validExtHello)).not.toThrow();
    });

    it('rejects bad platform', () => {
      expect(() => validateFrame({ ...validExtHello, platform: 'netscape' })).toThrow(/platform/);
    });

    // 0.4.0: mutual-auth identity fields are required on the extension
    // hello. The matching `sessionSig` lives on the subsequent
    // ReadyFrame — see the `ready (v2)` test block.
    it('rejects extension hello missing identityX25519Pub', () => {
      const { identityX25519Pub: _drop, ...bad } = validExtHello;
      expect(() => validateFrame(bad)).toThrow(/identityX25519Pub/);
    });

    it('rejects extension hello missing identityEd25519Pub', () => {
      const { identityEd25519Pub: _drop, ...bad } = validExtHello;
      expect(() => validateFrame(bad)).toThrow(/identityEd25519Pub/);
    });

    it('rejects extension hello missing sessionNonce', () => {
      const { sessionNonce: _drop, ...bad } = validExtHello;
      expect(() => validateFrame(bad)).toThrow(/sessionNonce/);
    });

    it('rejects extension hello with non-base64 identityX25519Pub', () => {
      expect(() =>
        validateFrame({ ...validExtHello, identityX25519Pub: '!!!' }),
      ).toThrow(/identityX25519Pub.*base64/);
    });
  });

  describe('ready (v2)', () => {
    const validReady = {
      type: 'ready',
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      extensionSessionPub: 'AAAA',
      sessionSig: 'AAAA',
    };

    it('accepts valid', () => {
      expect(() => validateFrame(validReady)).not.toThrow();
    });

    it('rejects when mcpId is missing', () => {
      expect(() =>
        validateFrame({ type: 'ready', extensionSessionPub: 'AAAA', sessionSig: 'AAAA' }),
      ).toThrow(/mcpId/);
    });

    it('rejects when extensionSessionPub is missing', () => {
      expect(() =>
        validateFrame({
          type: 'ready',
          mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
          sessionSig: 'AAAA',
        }),
      ).toThrow(/extensionSessionPub/);
    });

    it('rejects when sessionSig is missing (0.4.0 mutual-auth field)', () => {
      const { sessionSig: _drop, ...bad } = validReady;
      expect(() => validateFrame(bad)).toThrow(/sessionSig/);
    });

    it('rejects non-base64 sessionSig', () => {
      expect(() => validateFrame({ ...validReady, sessionSig: '!!!' })).toThrow(/sessionSig.*base64/);
    });
  });

  describe('encrypted frame', () => {
    const valid = {
      type: 'frame',
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      seq: 1,
      iv: 'AAAA',
      ciphertext: 'AAAA',
    };

    it('accepts valid', () => {
      expect(() => validateFrame(valid)).not.toThrow();
    });

    it('rejects seq <= 0', () => {
      expect(() => validateFrame({ ...valid, seq: 0 })).toThrow(/seq/);
      expect(() => validateFrame({ ...valid, seq: -1 })).toThrow(/seq/);
    });

    it('rejects non-integer seq', () => {
      expect(() => validateFrame({ ...valid, seq: 1.5 })).toThrow(/seq/);
    });

    it('rejects non-base64 iv', () => {
      expect(() => validateFrame({ ...valid, iv: 'not base64!@#' })).toThrow(/iv/);
    });

    it('rejects non-base64 ciphertext', () => {
      expect(() => validateFrame({ ...valid, ciphertext: '!!!' })).toThrow(/ciphertext/);
    });
  });

  describe('defensive', () => {
    it('rejects unknown frame type', () => {
      expect(() => validateFrame({ type: 'mystery' })).toThrow(/unknown frame type/);
    });

    it('rejects prototype-pollution keys', () => {
      expect(() => validateFrame({ type: 'ready', __proto__: {} })).toThrow();
      expect(() => validateFrame({ type: 'ready', constructor: {} })).toThrow();
    });

    it('rejects non-object input', () => {
      expect(() => validateFrame('hello')).toThrow();
      expect(() => validateFrame(null)).toThrow();
      expect(() => validateFrame(42)).toThrow();
    });
  });
});

describe('validateInnerFrame', () => {
  it('accepts ping', () => {
    expect(() => validateInnerFrame({ type: 'ping' })).not.toThrow();
  });

  it('accepts pong', () => {
    expect(() => validateInnerFrame({ type: 'pong' })).not.toThrow();
  });

  it('accepts valid request', () => {
    const inner = {
      type: 'request',
      id: 1,
      op: 'fetch',
      init: { url: 'https://x.com/y', method: 'GET', tabUrl: 'https://x.com/' },
    };
    expect(() => validateInnerFrame(inner)).not.toThrow();
  });

  it('rejects request with non-http(s) url', () => {
    const inner = {
      type: 'request',
      id: 1,
      op: 'fetch',
      init: { url: 'javascript:alert(1)', method: 'GET', tabUrl: 'https://x.com/' },
    };
    expect(() => validateInnerFrame(inner)).toThrow(/url/);
  });

  it('rejects request with bad op', () => {
    expect(() => validateInnerFrame({
      type: 'request', id: 1, op: 'eval',
      init: { url: 'https://x', method: 'GET', tabUrl: 'https://x/' },
    })).toThrow(/op/);
  });

  it('rejects request with non-http(s) tabUrl', () => {
    expect(() => validateInnerFrame({
      type: 'request', id: 1, op: 'fetch',
      init: { url: 'https://x', method: 'GET', tabUrl: 'javascript:alert(1)' },
    })).toThrow(/tabUrl/);
  });

  it('rejects request with prototype-pollution in headers', () => {
    expect(() => validateInnerFrame({
      type: 'request', id: 1, op: 'fetch',
      init: {
        url: 'https://x', method: 'GET', tabUrl: 'https://x/',
        headers: JSON.parse('{"__proto__":{"polluted":true}}'),
      },
    })).toThrow();
  });

  it('rejects request with non-string header value', () => {
    expect(() => validateInnerFrame({
      type: 'request', id: 1, op: 'fetch',
      init: {
        url: 'https://x', method: 'GET', tabUrl: 'https://x/',
        headers: { 'X-Foo': 123 as unknown as string },
      },
    })).toThrow(/headers/);
  });

  it('rejects request with non-string body', () => {
    expect(() => validateInnerFrame({
      type: 'request', id: 1, op: 'fetch',
      init: {
        url: 'https://x', method: 'GET', tabUrl: 'https://x/',
        body: 123 as unknown as string,
      },
    })).toThrow(/body/);
  });

  it('accepts response ok=true', () => {
    expect(() => validateInnerFrame({
      type: 'response', id: 1, ok: true, status: 200,
      url: 'https://x.com/', body: 'hello',
    })).not.toThrow();
  });

  it('accepts response ok=false', () => {
    expect(() => validateInnerFrame({
      type: 'response', id: 1, ok: false, error: 'no tab',
    })).not.toThrow();
  });

  it('rejects response with ok=not-boolean', () => {
    expect(() => validateInnerFrame({
      type: 'response', id: 1, ok: 'maybe',
    })).toThrow(/ok/);
  });

  it('rejects unknown inner type', () => {
    expect(() => validateInnerFrame({ type: 'mystery' })).toThrow(/unknown inner frame type/);
  });

  describe('read_cookies', () => {
    it('accepts a valid read_cookies request', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_cookies',
          init: { tabUrl: 'https://opentable.com/' },
        }),
      ).not.toThrow();
    });

    it('rejects read_cookies with non-http tabUrl', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_cookies',
          init: { tabUrl: 'javascript:alert(1)' },
        }),
      ).toThrow(/tabUrl/);
    });

    it('rejects read_cookies with extra init fields', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_cookies',
          init: { tabUrl: 'https://x.com/', url: 'https://x.com/api' },
        }),
      ).toThrow(/unexpected field/);
    });

    it('accepts a successful read_cookies response', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'read_cookies',
          cookies: 'sid=abc; pref=light',
        }),
      ).not.toThrow();
    });

    it('rejects read_cookies response missing cookies', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'read_cookies',
        }),
      ).toThrow(/cookies/);
    });

    it('rejects unknown response op', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'frobnicate',
        }),
      ).toThrow(/op/);
    });

    it('still accepts the legacy fetch response shape (no op field)', () => {
      // 0.1.x senders never carried `op` on responses; validator must keep
      // accepting that shape so old extensions can talk to new servers
      // and vice versa for the fetch verb specifically.
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          status: 200,
          url: 'https://x.com/',
          body: '',
        }),
      ).not.toThrow();
    });

    it("accepts a fetch response with op: 'fetch' set explicitly", () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'fetch',
          status: 200,
          url: 'https://x.com/',
          body: '',
        }),
      ).not.toThrow();
    });

    it('accepts an error response with op echo', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: false,
          op: 'read_cookies',
          error: 'capability not granted',
        }),
      ).not.toThrow();
    });

    it('rejects an error response with unknown op echo', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: false,
          op: 'frobnicate',
          error: 'huh',
        }),
      ).toThrow(/op/);
    });

    // 0.3.0: new read_cookies shape (origin + keys → values).
    it('accepts new read_cookies request shape (origin + keys)', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_cookies',
          init: { origin: 'https://www.honeybook.com', keys: ['MTOKEN', 'CKAT'] },
        }),
      ).not.toThrow();
    });

    it('accepts new read_cookies response shape (values map)', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'read_cookies',
          values: { MTOKEN: 'ey...', CKAT: 'abc' },
        }),
      ).not.toThrow();
    });

    it('rejects read_cookies request mixing tabUrl and keys', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_cookies',
          init: { tabUrl: 'https://x.com/', keys: ['x'] },
        }),
      ).toThrow(/read_cookies/);
    });

    it('rejects new read_cookies request with non-https origin', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_cookies',
          init: { origin: 'http://x.com', keys: ['k'] },
        }),
      ).toThrow(/origin/);
    });

    it('rejects new read_cookies request with empty keys', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_cookies',
          init: { origin: 'https://x.com', keys: [] },
        }),
      ).toThrow(/keys/);
    });

    it('rejects new read_cookies request with duplicate keys', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_cookies',
          init: { origin: 'https://x.com', keys: ['k', 'k'] },
        }),
      ).toThrow(/keys.*duplicate/);
    });

    it('rejects read_cookies response with non-plain values', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'read_cookies',
          values: 'k=v',
        }),
      ).toThrow(/values/);
    });

    it('rejects read_cookies response with non-string value entry', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'read_cookies',
          values: { k: 123 },
        }),
      ).toThrow(/values/);
    });
  });

  describe('read_local_storage / read_session_storage', () => {
    const validLs = {
      type: 'request' as const,
      id: 1,
      op: 'read_local_storage' as const,
      init: { origin: 'https://www.ofw.com', keys: ['auth', 'tokenExpiry'] },
    };
    const validSs = {
      type: 'request' as const,
      id: 1,
      op: 'read_session_storage' as const,
      init: { origin: 'https://www.ofw.com', keys: ['anon-id'] },
    };

    it('accepts a valid read_local_storage request', () => {
      expect(() => validateInnerFrame(validLs)).not.toThrow();
    });

    it('accepts a valid read_session_storage request', () => {
      expect(() => validateInnerFrame(validSs)).not.toThrow();
    });

    it('rejects read_local_storage missing origin', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_local_storage',
          init: { keys: ['k'] },
        }),
      ).toThrow(/origin/);
    });

    it('rejects read_local_storage missing keys', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_local_storage',
          init: { origin: 'https://x.com' },
        }),
      ).toThrow(/keys/);
    });

    it('rejects read_local_storage with non-array keys', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_local_storage',
          init: { origin: 'https://x.com', keys: 'k' },
        }),
      ).toThrow(/keys/);
    });

    it('rejects read_local_storage with empty keys', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_local_storage',
          init: { origin: 'https://x.com', keys: [] },
        }),
      ).toThrow(/keys/);
    });

    it('rejects read_local_storage with duplicate keys', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_local_storage',
          init: { origin: 'https://x.com', keys: ['k', 'k'] },
        }),
      ).toThrow(/keys.*duplicate/);
    });

    it('rejects read_local_storage with http origin', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_local_storage',
          init: { origin: 'http://x.com', keys: ['k'] },
        }),
      ).toThrow(/origin/);
    });

    it('rejects read_local_storage with origin carrying a path', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'read_local_storage',
          init: { origin: 'https://x.com/path', keys: ['k'] },
        }),
      ).toThrow(/origin.*bare/);
    });

    it('accepts read_local_storage success response', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'read_local_storage',
          values: { auth: 'ey...' },
        }),
      ).not.toThrow();
    });

    it('accepts read_session_storage success response', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'read_session_storage',
          values: {},
        }),
      ).not.toThrow();
    });

    it('rejects read_local_storage response missing values', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'read_local_storage',
        }),
      ).toThrow(/values/);
    });

    it('rejects read_local_storage response with non-string entry', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'read_local_storage',
          values: { k: 99 },
        }),
      ).toThrow(/values/);
    });
  });

  describe('capture_request_header', () => {
    const validReq = {
      type: 'request' as const,
      id: 1,
      op: 'capture_request_header' as const,
      init: {
        urlPattern: 'https://api.honeybook.com/api/v2/*',
        headerName: 'hb-api-fingerprint',
      },
    };

    it('accepts a valid capture_request_header request', () => {
      expect(() => validateInnerFrame(validReq)).not.toThrow();
    });

    it('accepts capture_request_header request with timeoutMs', () => {
      expect(() =>
        validateInnerFrame({ ...validReq, init: { ...validReq.init, timeoutMs: 10000 } }),
      ).not.toThrow();
    });

    it('rejects capture_request_header missing urlPattern', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'capture_request_header',
          init: { headerName: 'X-Foo' },
        }),
      ).toThrow(/urlPattern/);
    });

    it('rejects capture_request_header missing headerName', () => {
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'capture_request_header',
          init: { urlPattern: 'https://x.com/api/*' },
        }),
      ).toThrow(/headerName/);
    });

    it('rejects capture_request_header with negative timeoutMs', () => {
      expect(() =>
        validateInnerFrame({ ...validReq, init: { ...validReq.init, timeoutMs: -1 } }),
      ).toThrow(/timeoutMs/);
    });

    it('rejects capture_request_header with non-integer timeoutMs', () => {
      expect(() =>
        validateInnerFrame({ ...validReq, init: { ...validReq.init, timeoutMs: 1.5 } }),
      ).toThrow(/timeoutMs/);
    });

    it('accepts capture_request_header success response', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'capture_request_header',
          value: 'abc-123',
        }),
      ).not.toThrow();
    });

    it('rejects capture_request_header response missing value', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'capture_request_header',
        }),
      ).toThrow(/value/);
    });

    it('rejects capture_request_header response with non-string value', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: true,
          op: 'capture_request_header',
          value: 42,
        }),
      ).toThrow(/value/);
    });

    it('accepts capture_request_header timeout error response', () => {
      expect(() =>
        validateInnerFrame({
          type: 'response',
          id: 1,
          ok: false,
          op: 'capture_request_header',
          error: 'timeout',
        }),
      ).not.toThrow();
    });
  });

  // Edge cases at the protocol boundary. These guard the security
  // invariants the rest of the system trusts — i.e. once validateFrame
  // returns, the consumer doesn't re-check shape or scheme.
  describe('edge cases', () => {
    it('assertHttpUrl rejects un-parseable URL strings', () => {
      // `new URL(...)` throws on completely malformed input — covers the
      // catch branch in assertHttpUrl that produces a friendlier error
      // than the raw TypeError.
      expect(() =>
        validateInnerFrame({
          type: 'request',
          id: 1,
          op: 'fetch',
          init: { url: 'http://[::1', method: 'GET', tabUrl: 'https://x.com/' },
        }),
      ).toThrow(/url.*valid URL/);
    });

    it("rejects hello with role other than 'server' or 'extension'", () => {
      // Hits the trailing throw in validateHello when role is neither.
      // Without this, a future role addition could silently no-op.
      expect(() =>
        validateFrame({
          type: 'hello',
          protocolVersion: 2,
          role: 'mystery',
          // Pad with the rest of the v2 extension/server fields so the
          // role check is what trips, not a missing-field check.
          identityX25519Pub: 'AAAA',
        }),
      ).toThrow(/role/);
    });

    it('rejects ready frame with invalid mcpId format', () => {
      // Ready frames are routed by mcpId — a malformed id would let an
      // attacker target a slot they shouldn't be able to. validateReady
      // catches the bad format before any handler sees it.
      expect(() =>
        validateFrame({
          type: 'ready',
          mcpId: 'not:a:valid-id', // rand fragment isn't 16-hex
          extensionSessionPub: 'AAAA',
        }),
      ).toThrow(/mcpId.*invalid format/);
    });

    it('rejects encrypted frame with invalid mcpId format', () => {
      // Same security argument as ready: the mcpId routes between
      // sessions on the host. validateEncrypted MUST reject before
      // the host's onMessage dispatch sees it.
      expect(() =>
        validateFrame({
          type: 'frame',
          mcpId: 'bad:id',
          seq: 1,
          iv: 'AAAA',
          ciphertext: 'AAAA',
        }),
      ).toThrow(/mcpId.*invalid format/);
    });
  });
});

// 0.4.0: read_indexed_db wire format.
describe('validateFrame (0.4.0 IndexedDb scope decls)', () => {
  const validHello = {
    type: 'hello',
    protocolVersion: 2,
    role: 'server',
    mcpId: 'resy-mcp:0.0.1:a3f7c91d2e8b4f56',
    serverName: 'resy-mcp',
    version: '0.0.1',
    domains: ['resy.com'],
    identityX25519Pub: 'AAAA',
    identityEd25519Pub: 'AAAA',
    sessionNonce: 'AAAA',
    sessionSig: 'AAAA',
  };

  it('accepts hello with indexedDbScopes', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        capabilities: ['read_indexed_db'],
        indexedDbScopes: [
          { origin: 'https://resy.com', database: 'resy', store: 'auth', keys: ['userToken'] },
        ],
      }),
    ).not.toThrow();
  });

  it('accepts hello with empty indexedDbScopes', () => {
    expect(() =>
      validateFrame({ ...validHello, indexedDbScopes: [] }),
    ).not.toThrow();
  });

  it('rejects indexedDbScopes entry missing origin', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        indexedDbScopes: [{ database: 'resy', store: 'auth', keys: ['x'] }],
      }),
    ).toThrow(/indexedDbScopes.*origin/);
  });

  it('rejects indexedDbScopes entry missing database', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        indexedDbScopes: [{ origin: 'https://resy.com', store: 'auth', keys: ['x'] }],
      }),
    ).toThrow(/indexedDbScopes.*database/);
  });

  it('rejects indexedDbScopes entry missing store', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        indexedDbScopes: [{ origin: 'https://resy.com', database: 'resy', keys: ['x'] }],
      }),
    ).toThrow(/indexedDbScopes.*store/);
  });

  it('rejects indexedDbScopes entry with empty keys array', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        indexedDbScopes: [{ origin: 'https://resy.com', database: 'resy', store: 'auth', keys: [] }],
      }),
    ).toThrow(/indexedDbScopes.*keys/);
  });

  it('rejects indexedDbScopes entry with non-https origin', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        indexedDbScopes: [{ origin: 'http://resy.com', database: 'resy', store: 'auth', keys: ['x'] }],
      }),
    ).toThrow(/indexedDbScopes.*origin/);
  });

  it('rejects indexedDbScopes entry with bad chars in database', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        indexedDbScopes: [{ origin: 'https://resy.com', database: 'has space', store: 'auth', keys: ['x'] }],
      }),
    ).toThrow(/indexedDbScopes.*database/);
  });

  it('rejects duplicate IndexedDB scope', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        indexedDbScopes: [
          { origin: 'https://resy.com', database: 'resy', store: 'auth', keys: ['userToken'] },
          { origin: 'https://resy.com', database: 'resy', store: 'auth', keys: ['userToken'] },
        ],
      }),
    ).toThrow(/indexedDbScopes.*duplicate/);
  });
});

describe('validateFrame (0.4.0 storage pointers)', () => {
  const validHello = {
    type: 'hello',
    protocolVersion: 2,
    role: 'server',
    mcpId: 'honeybook-mcp:0.1.0:a3f7c91d2e8b4f56',
    serverName: 'honeybook-mcp',
    version: '0.1.0',
    domains: ['honeybook.com'],
    identityX25519Pub: 'AAAA',
    identityEd25519Pub: 'AAAA',
    sessionNonce: 'AAAA',
    sessionSig: 'AAAA',
  };

  it('accepts localStoragePointers when key matches a localStorageKeys entry', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        capabilities: ['read_local_storage'],
        localStorageKeys: ['jStorage'],
        localStoragePointers: [
          { key: 'jStorage', jsonPointer: '/HB_AUTH_TOKEN' },
          { key: 'jStorage', jsonPointer: '/HB_AUTH_USER_ID' },
        ],
      }),
    ).not.toThrow();
  });

  it('rejects localStoragePointers entry whose key is not in localStorageKeys', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        capabilities: ['read_local_storage'],
        localStorageKeys: ['jStorage'],
        localStoragePointers: [{ key: 'no_such_key', jsonPointer: '/x' }],
      }),
    ).toThrow(/localStoragePointers.*not in declared/);
  });

  it('rejects localStoragePointers entry with invalid pointer (missing leading /)', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        capabilities: ['read_local_storage'],
        localStorageKeys: ['jStorage'],
        localStoragePointers: [{ key: 'jStorage', jsonPointer: 'no-slash' }],
      }),
    ).toThrow(/jsonPointer/);
  });

  it('rejects duplicate (key, jsonPointer)', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        capabilities: ['read_local_storage'],
        localStorageKeys: ['jStorage'],
        localStoragePointers: [
          { key: 'jStorage', jsonPointer: '/a' },
          { key: 'jStorage', jsonPointer: '/a' },
        ],
      }),
    ).toThrow(/localStoragePointers.*duplicate/);
  });

  it('sessionStoragePointers obeys the same rules', () => {
    expect(() =>
      validateFrame({
        ...validHello,
        capabilities: ['read_session_storage'],
        sessionStorageKeys: ['blob'],
        sessionStoragePointers: [{ key: 'blob', jsonPointer: '/inner' }],
      }),
    ).not.toThrow();
  });
});

describe('validateInnerFrame (0.4.0 storage pointers)', () => {
  it('accepts read_local_storage request with pointers', () => {
    expect(() =>
      validateInnerFrame({
        type: 'request',
        id: 1,
        op: 'read_local_storage',
        init: {
          origin: 'https://honeybook.com',
          keys: ['jStorage'],
          pointers: {
            HB_AUTH_TOKEN: { storageKey: 'jStorage', jsonPointer: '/HB_AUTH_TOKEN' },
          },
        },
      }),
    ).not.toThrow();
  });

  it('rejects pointer whose storageKey is not in init.keys', () => {
    expect(() =>
      validateInnerFrame({
        type: 'request',
        id: 1,
        op: 'read_local_storage',
        init: {
          origin: 'https://honeybook.com',
          keys: ['jStorage'],
          pointers: {
            HB_AUTH_TOKEN: { storageKey: 'other', jsonPointer: '/a' },
          },
        },
      }),
    ).toThrow(/storageKey/);
  });

  it('rejects pointer with invalid jsonPointer', () => {
    expect(() =>
      validateInnerFrame({
        type: 'request',
        id: 1,
        op: 'read_local_storage',
        init: {
          origin: 'https://honeybook.com',
          keys: ['jStorage'],
          pointers: { x: { storageKey: 'jStorage', jsonPointer: 'no-slash' } },
        },
      }),
    ).toThrow(/jsonPointer/);
  });
});

describe('validateInnerFrame (0.4.0 read_indexed_db)', () => {
  it('accepts a valid read_indexed_db request', () => {
    expect(() =>
      validateInnerFrame({
        type: 'request',
        id: 1,
        op: 'read_indexed_db',
        init: {
          origin: 'https://resy.com',
          database: 'resy',
          store: 'auth',
          keys: ['userToken', 'userId'],
        },
      }),
    ).not.toThrow();
  });

  it('rejects read_indexed_db request missing database', () => {
    expect(() =>
      validateInnerFrame({
        type: 'request',
        id: 1,
        op: 'read_indexed_db',
        init: { origin: 'https://resy.com', store: 'auth', keys: ['x'] },
      }),
    ).toThrow(/database/);
  });

  it('rejects read_indexed_db request with extra field', () => {
    expect(() =>
      validateInnerFrame({
        type: 'request',
        id: 1,
        op: 'read_indexed_db',
        init: {
          origin: 'https://resy.com',
          database: 'resy',
          store: 'auth',
          keys: ['x'],
          extra: 'no',
        },
      }),
    ).toThrow(/unexpected field/);
  });

  it('rejects read_indexed_db request with non-https origin', () => {
    expect(() =>
      validateInnerFrame({
        type: 'request',
        id: 1,
        op: 'read_indexed_db',
        init: { origin: 'http://resy.com', database: 'resy', store: 'auth', keys: ['x'] },
      }),
    ).toThrow(/origin/);
  });

  it('accepts a read_indexed_db response with string + numeric + object values', () => {
    expect(() =>
      validateInnerFrame({
        type: 'response',
        id: 1,
        ok: true,
        op: 'read_indexed_db',
        values: {
          token: 'ey...',
          expiry: 1730000000000,
          user: { id: 'u-1', name: 'r' },
        },
      }),
    ).not.toThrow();
  });

  it('rejects read_indexed_db response missing values', () => {
    expect(() =>
      validateInnerFrame({
        type: 'response',
        id: 1,
        ok: true,
        op: 'read_indexed_db',
      }),
    ).toThrow(/values/);
  });

  it('rejects read_indexed_db response with non-object values', () => {
    expect(() =>
      validateInnerFrame({
        type: 'response',
        id: 1,
        ok: true,
        op: 'read_indexed_db',
        values: 'oops',
      }),
    ).toThrow(/values/);
  });
});
