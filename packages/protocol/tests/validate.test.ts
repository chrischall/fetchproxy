import { describe, it, expect } from 'vitest';
import { validateFrame, ProtocolError } from '../src/validate.js';

describe('validateFrame', () => {
  it('accepts a valid hello (server) frame', () => {
    const frame = {
      type: 'hello',
      role: 'server',
      server: 'opentable-mcp',
      version: '0.9.1',
      domain: 'opentable.com',
    };
    expect(() => validateFrame(frame)).not.toThrow();
    expect(validateFrame(frame).type).toBe('hello');
  });

  it('accepts a valid hello (extension) frame', () => {
    const frame = {
      type: 'hello',
      role: 'extension',
      version: '1.0.0',
      platform: 'chrome',
      extension_id: 'fetchproxy',
    };
    expect(() => validateFrame(frame)).not.toThrow();
  });

  it('accepts a valid request/fetch frame', () => {
    const frame = {
      type: 'request',
      id: 1,
      op: 'fetch',
      init: {
        url: 'https://www.opentable.com/x',
        method: 'GET',
        tabUrl: 'https://www.opentable.com/',
      },
    };
    expect(() => validateFrame(frame)).not.toThrow();
  });

  it('rejects unknown frame type', () => {
    expect(() => validateFrame({ type: 'mystery' })).toThrow(ProtocolError);
  });

  it('rejects request frame with non-integer id', () => {
    const frame = {
      type: 'request',
      id: 'one',
      op: 'fetch',
      init: { url: 'https://x', method: 'GET', tabUrl: 'https://x/' },
    };
    expect(() => validateFrame(frame)).toThrow(/id/);
  });

  it('rejects request frame with non-https url', () => {
    const frame = {
      type: 'request',
      id: 1,
      op: 'fetch',
      init: { url: 'javascript:alert(1)', method: 'GET', tabUrl: 'https://x/' },
    };
    expect(() => validateFrame(frame)).toThrow(/url/);
  });

  it('rejects prototype-pollution keys', () => {
    expect(() => validateFrame({ type: 'ping', __proto__: {} })).toThrow();
    expect(() => validateFrame({ type: 'ping', constructor: {} })).toThrow();
  });

  it('rejects non-object input', () => {
    expect(() => validateFrame('hello')).toThrow();
    expect(() => validateFrame(null)).toThrow();
    expect(() => validateFrame(42)).toThrow();
  });
});
