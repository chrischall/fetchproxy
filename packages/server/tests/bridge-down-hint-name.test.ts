import { describe, it, expect } from 'vitest';
import { FetchproxyBridgeDownError } from '../src/index.js';

/**
 * The bridge-down hint is the text an MCP shows a user whose browser stopped
 * answering, so it names the extension they installed: ContextMint Bridge.
 * Every other typed error's hint already does (scope, capability, hello
 * rejection); this one still said "the fetchproxy extension".
 */
describe('FetchproxyBridgeDownError.hint', () => {
  it('names ContextMint Bridge, not the fetchproxy extension', () => {
    const err = new FetchproxyBridgeDownError({ originalError: 'content_script_unreachable' });
    expect(err.hint).toMatch(/ContextMint Bridge's service worker is not responding/);
    expect(err.hint).not.toMatch(/fetchproxy extension/);
    expect(err.hint).toContain('"content_script_unreachable"');
  });
});
