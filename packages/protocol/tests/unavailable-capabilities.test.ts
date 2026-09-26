import { describe, it, expect } from 'vitest';
import {
  validateFrame,
  validateInnerFrame,
  capabilityUnavailableMessage,
  parseCapabilityUnavailable,
  parseUnsupportedCapabilityReason,
  unavailableCapabilitiesHelloField,
  CAPABILITY_UNAVAILABLE_CODE,
  MAX_UNAVAILABLE_CAPABILITIES,
  UNSUPPORTED_CAPABILITY_REASON_PREFIX,
  type HelloFrameFromExtension,
} from '../src/index.js';

/**
 * #418: the extension says which capabilities THIS browser cannot serve, so an
 * MCP can be granted the subset that works instead of being refused whole.
 *
 * Additive inside protocol 4 — no version bump and nothing a signature covers
 * changes — so these tests pin the parts an old or new peer relies on: the
 * shape the validator admits, the fixed error wording, and the reason prefix.
 */
const extHello = {
  type: 'hello',
  protocolVersion: 4,
  role: 'extension',
  platform: 'safari',
  extensionId: 'contextmint-bridge',
  version: '1.4.0',
  identityX25519Pub: 'AAAA',
  identityEd25519Pub: 'AAAA',
  sessionNonce: 'AAAA',
};

describe('HelloFrameFromExtension.unavailableCapabilities — validator', () => {
  it('accepts a hello without the field (every extension before #418)', () => {
    expect(() => validateFrame(extHello)).not.toThrow();
  });

  it('accepts a list and passes it through untouched', () => {
    const f = validateFrame({ ...extHello, unavailableCapabilities: ['download', 'graphql'] });
    expect((f as HelloFrameFromExtension).unavailableCapabilities).toEqual(['download', 'graphql']);
  });

  it('accepts capability names this build does not know — a newer extension must not get its hello refused', () => {
    expect(() =>
      validateFrame({ ...extHello, unavailableCapabilities: ['download', 'teleport_tab'] }),
    ).not.toThrow();
  });

  it('refuses a non-array', () => {
    expect(() => validateFrame({ ...extHello, unavailableCapabilities: 'download' })).toThrow(
      /unavailableCapabilities/,
    );
  });

  it('refuses a non-string entry', () => {
    expect(() => validateFrame({ ...extHello, unavailableCapabilities: [1] })).toThrow(
      /unavailableCapabilities/,
    );
  });

  it('refuses an empty or over-long entry', () => {
    expect(() => validateFrame({ ...extHello, unavailableCapabilities: [''] })).toThrow(
      /unavailableCapabilities/,
    );
    expect(() => validateFrame({ ...extHello, unavailableCapabilities: ['x'.repeat(65)] })).toThrow(
      /unavailableCapabilities/,
    );
    expect(() =>
      validateFrame({ ...extHello, unavailableCapabilities: ['x'.repeat(64)] }),
    ).not.toThrow();
  });

  it(`refuses more than ${MAX_UNAVAILABLE_CAPABILITIES} entries`, () => {
    const ok = Array.from({ length: MAX_UNAVAILABLE_CAPABILITIES }, (_, i) => `c${i}`);
    expect(() => validateFrame({ ...extHello, unavailableCapabilities: ok })).not.toThrow();
    expect(() =>
      validateFrame({ ...extHello, unavailableCapabilities: [...ok, 'one-more'] }),
    ).toThrow(/unavailableCapabilities/);
  });
});

describe('unavailableCapabilitiesHelloField — what the extension spreads into its hello', () => {
  it('is empty for an empty list, so Chrome’s hello stays byte-identical', () => {
    expect(unavailableCapabilitiesHelloField([])).toEqual({});
    expect(JSON.stringify({ ...extHello, ...unavailableCapabilitiesHelloField(new Set()) })).toBe(
      JSON.stringify(extHello),
    );
  });

  it('sorts and de-duplicates', () => {
    expect(
      unavailableCapabilitiesHelloField(['graphql', 'download', 'graphql', 'capture_redirect']),
    ).toEqual({ unavailableCapabilities: ['capture_redirect', 'download', 'graphql'] });
  });
});

describe('InnerResponseError.code', () => {
  const base = { type: 'response', id: 7, ok: false, op: 'download' };

  it('accepts the capability_unavailable code', () => {
    const f = validateInnerFrame({
      ...base,
      error: capabilityUnavailableMessage('download', 'safari'),
      code: CAPABILITY_UNAVAILABLE_CODE,
    });
    expect((f as { code?: string }).code).toBe('capability_unavailable');
  });

  it('accepts an unknown code string (forward-compatible)', () => {
    expect(() =>
      validateInnerFrame({ ...base, error: 'x', code: 'some_future_code' }),
    ).not.toThrow();
  });

  it('refuses a non-string code', () => {
    expect(() => validateInnerFrame({ ...base, error: 'x', code: 3 })).toThrow(/inner\.code/);
  });
});

describe('the fixed capability-unavailable wording', () => {
  it('names the capability and the browser', () => {
    expect(capabilityUnavailableMessage('download', 'safari')).toBe(
      'capability "download" is not available in this browser (safari)',
    );
  });

  it('never contains "not granted" — an old classifier must not read it as capability_denied', () => {
    const msg = capabilityUnavailableMessage('graphql', 'safari');
    expect(msg).not.toMatch(/not granted/);
    // The exact pattern every published server classifies as capability_denied.
    expect(/^capability .+ not granted/.test(msg)).toBe(false);
  });

  it('round-trips through the parser', () => {
    expect(parseCapabilityUnavailable(capabilityUnavailableMessage('download', 'safari'))).toEqual({
      capability: 'download',
      platform: 'safari',
    });
  });

  it('also parses the pre-#418 bridge wording, which named no browser', () => {
    expect(
      parseCapabilityUnavailable('capability "download" is not available in this browser'),
    ).toEqual({ capability: 'download', platform: null });
  });

  it('returns null for anything else', () => {
    expect(
      parseCapabilityUnavailable('capability "download" not granted (declared: [fetch])'),
    ).toBeNull();
    expect(parseCapabilityUnavailable('no tab matching https://x.com/')).toBeNull();
  });
});

describe('the unsupported-capability hello-rejected reason', () => {
  it('has a documented prefix', () => {
    expect(UNSUPPORTED_CAPABILITY_REASON_PREFIX).toBe('unsupported-capability:');
  });

  it('parses the capability list out of the reason the bridge sends', () => {
    expect(
      parseUnsupportedCapabilityReason(
        'unsupported-capability: download, graphql (not available in this browser)',
      ),
    ).toEqual(['download', 'graphql']);
  });

  it('parses a single capability', () => {
    expect(
      parseUnsupportedCapabilityReason(
        'unsupported-capability: download (not available in this browser)',
      ),
    ).toEqual(['download']);
  });

  it('returns null for other reasons', () => {
    expect(parseUnsupportedCapabilityReason('sessionSig invalid')).toBeNull();
  });
});
