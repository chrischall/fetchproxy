import { describe, it, expect } from 'vitest';
import { validateFrame, validateInnerFrame, ProtocolError } from '../src/validate.js';

describe('validateFrame', () => {
  describe('hello (server, v2)', () => {
    const validHello = {
      type: 'hello',
      protocolVersion: 1,
      role: 'server',
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      serverName: 'opentable-mcp',
      version: '0.9.1',
      domain: 'opentable.com',
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'AAAA',
      sessionNonce: 'AAAA',
      sessionSig: 'AAAA',
    };

    it('accepts valid', () => {
      expect(() => validateFrame(validHello)).not.toThrow();
    });

    it('rejects when mcpId is missing', () => {
      const { mcpId, ...bad } = validHello;
      expect(() => validateFrame(bad)).toThrow(ProtocolError);
    });

    it('rejects bad mcpId format', () => {
      expect(() => validateFrame({ ...validHello, mcpId: 'no-colons' })).toThrow(/mcpId/);
    });

    it('rejects wrong protocolVersion', () => {
      expect(() => validateFrame({ ...validHello, protocolVersion: 2 })).toThrow(/protocolVersion/);
    });

    it('rejects non-base64 identityX25519Pub', () => {
      expect(() => validateFrame({ ...validHello, identityX25519Pub: '!!!' })).toThrow(/identityX25519Pub/);
    });
  });

  describe('hello (extension, v2)', () => {
    const validExtHello = {
      type: 'hello',
      protocolVersion: 1,
      role: 'extension',
      platform: 'chrome',
      extensionId: 'fetchproxy',
      version: '0.1.0',
    };

    it('accepts valid', () => {
      expect(() => validateFrame(validExtHello)).not.toThrow();
    });

    it('rejects bad platform', () => {
      expect(() => validateFrame({ ...validExtHello, platform: 'netscape' })).toThrow(/platform/);
    });
  });

  describe('ready (v2)', () => {
    const validReady = {
      type: 'ready',
      mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56',
      extensionSessionPub: 'AAAA',
    };

    it('accepts valid', () => {
      expect(() => validateFrame(validReady)).not.toThrow();
    });

    it('rejects when mcpId is missing', () => {
      expect(() => validateFrame({ type: 'ready', extensionSessionPub: 'AAAA' })).toThrow(/mcpId/);
    });

    it('rejects when extensionSessionPub is missing', () => {
      expect(() => validateFrame({ type: 'ready', mcpId: 'opentable-mcp:0.9.1:a3f7c91d2e8b4f56' })).toThrow(/extensionSessionPub/);
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
});
