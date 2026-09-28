import { describe, it, expect } from 'vitest';
import {
  ACCOUNT_ATTEST_FRAME,
  ACCOUNT_KEY_FRAME,
  validateFrame,
  type AccountAttestFrame,
  type AccountKeyFrame,
} from '../src/index.js';

const b64 = (n: number, fill = 7): string =>
  btoa(String.fromCharCode(...new Uint8Array(n).fill(fill)));

const KEY: AccountKeyFrame = {
  type: 'account-key',
  accountId: 'acc_f05c0ebf831e35df687660d1',
  slug: 'chris',
  displayName: 'Chris Hall',
  confirmedBy: 'c•••@gmail.com',
  tokenId: 'brt_0123456789abcdef01234567',
  kid: '9f2c41ab7de05613',
  publicKey: b64(32),
  generation: 3,
  bridgedRegistrations: 19,
};

const ATTEST: AccountAttestFrame = {
  type: 'account-attest',
  mcpId: 'zillow-mcp:0.12.0:770a8e083b612779',
  accountId: 'acc_f05c0ebf831e35df687660d1',
  generation: 3,
  tokenId: 'brt_0123456789abcdef01234567',
  kid: '9f2c41ab7de05613',
  registrationId: 'reg_89abcdef0123456789abcdef',
  slug: 'zillow',
  identityHash: 'ab'.repeat(32),
  identityEd25519Pub: b64(32),
  scopeDigest: '0'.repeat(64),
  consent: 'silent',
  notAfter: 1788063212,
  sig: b64(64),
};

const withField = (base: object, k: string, v: unknown): unknown => ({ ...base, [k]: v });
const without = (base: object, k: string): unknown => {
  const o = { ...base } as Record<string, unknown>;
  delete o[k];
  return o;
};

describe('frame-type constants', () => {
  it('names the two relay-minted account frames', () => {
    expect(ACCOUNT_KEY_FRAME).toBe('account-key');
    expect(ACCOUNT_ATTEST_FRAME).toBe('account-attest');
  });
});

describe('account-key frame validator', () => {
  it('accepts the fixture and returns a rebuilt copy', () => {
    const got = validateFrame(structuredClone(KEY));
    expect(got).toEqual(KEY);
  });

  it('accepts an empty displayName and zero bridged registrations', () => {
    expect(() => validateFrame({ ...KEY, displayName: '', bridgedRegistrations: 0 })).not.toThrow();
  });

  for (const k of Object.keys(KEY).filter((k) => k !== 'type')) {
    it(`rejects a missing ${k}`, () => {
      expect(() => validateFrame(without(KEY, k))).toThrow(new RegExp(`account-key\\.${k}`));
    });
  }

  const BAD: [string, unknown[]][] = [
    ['accountId', [42, '', 'acc f05c', 'acc\u0000x', 'a'.repeat(129)]],
    ['slug', [1, '', 'ch ris', 'x\u0000', 'a'.repeat(129)]],
    [
      'displayName',
      [1, 'a'.repeat(129), 'Chris\u0000', 'Chris\u001b[31m', 'Chris‮Hall', 'a⁦b', 'a\u0085b'],
    ],
    ['confirmedBy', [1, '', 'a'.repeat(257), 'c\u0007@x', 'c‮@x']],
    ['tokenId', [1, '', 'brt/../x']],
    ['kid', ['9F2C41AB7DE05613', '9f2c41ab7de0561', '9f2c41ab7de056133', 'zf2c41ab7de05613', 7]],
    ['publicKey', [b64(31), b64(33), 'not base64!', b64(32).replace(/=$/, ''), 5]],
    ['generation', [0, -1, 1.5, '3', Number.NaN, 2 ** 53]],
    ['bridgedRegistrations', [-1, 1.5, '19', Number.NaN]],
  ];
  for (const [k, values] of BAD) {
    for (const v of values) {
      it(`rejects ${k} = ${JSON.stringify(v)}`, () => {
        expect(() => validateFrame(withField(KEY, k, v))).toThrow(new RegExp(`account-key\\.${k}`));
      });
    }
  }

  it('rejects an unexpected field', () => {
    expect(() => validateFrame({ ...KEY, trusted: true })).toThrow(/unexpected field/);
  });

  it('rejects a prototype-pollution key', () => {
    const raw = JSON.parse(
      `{"__proto__":{"polluted":1},${JSON.stringify(KEY).slice(1)}`,
    ) as unknown;
    expect(() => validateFrame(raw)).toThrow(/forbidden key/);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(() => validateFrame({ ...KEY, constructor: 1 })).toThrow(/forbidden key/);
  });

  it('rejects a non-plain object', () => {
    class K {
      constructor() {
        Object.assign(this, KEY);
      }
    }
    expect(() => validateFrame(new K())).toThrow(/non-plain/);
  });
});

describe('account-attest frame validator', () => {
  it('accepts the fixture and returns a rebuilt copy', () => {
    expect(validateFrame(structuredClone(ATTEST))).toEqual(ATTEST);
  });

  it('accepts every consent value', () => {
    for (const consent of ['silent', 'confirm', 'confirm-each']) {
      expect(() => validateFrame({ ...ATTEST, consent })).not.toThrow();
    }
  });

  for (const k of Object.keys(ATTEST).filter((k) => k !== 'type')) {
    it(`rejects a missing ${k}`, () => {
      expect(() => validateFrame(without(ATTEST, k))).toThrow(new RegExp(`account-attest\\.${k}`));
    });
  }

  const BAD: [string, unknown[]][] = [
    ['mcpId', ['zillow-mcp', 'zillow-mcp:0.12.0:770A8E083B612779', 3]],
    ['accountId', ['', 'acc\u0000x', 'acc x', 9]],
    ['generation', [0, -1, 1.5, '3', 2 ** 53]],
    ['tokenId', ['', 'brt\u0000', 'brt x']],
    ['kid', ['9F2C41AB7DE05613', 'abc', 1]],
    ['registrationId', ['', 'reg\u0000', 'reg x']],
    ['slug', ['', 'zil low', 'z\u0000']],
    ['identityHash', ['AB'.repeat(32), 'ab'.repeat(31), 'ab'.repeat(33), 'zz'.repeat(32), 1]],
    ['identityEd25519Pub', [b64(31), b64(33), '!!!!', 1]],
    ['scopeDigest', ['0'.repeat(63), 'A'.repeat(64), 'g'.repeat(64), 0]],
    ['consent', ['SILENT', 'allow', '', 'confirm_each', 1]],
    ['notAfter', [0, -1, 1.5, '1788063212', 2 ** 53]],
    ['sig', [b64(63), b64(65), b64(32), '%%%%', 1]],
  ];
  for (const [k, values] of BAD) {
    for (const v of values) {
      it(`rejects ${k} = ${JSON.stringify(v)}`, () => {
        expect(() => validateFrame(withField(ATTEST, k, v))).toThrow(
          new RegExp(`account-attest\\.${k}`),
        );
      });
    }
  }

  it('rejects an unexpected field (the nonces and origin are NOT carried)', () => {
    for (const k of ['gatewayOrigin', 'mcpHelloNonce', 'answersExtNonce', 'extra']) {
      expect(() => validateFrame({ ...ATTEST, [k]: 'x' })).toThrow(/unexpected field/);
    }
  });

  it('rejects a prototype-pollution key', () => {
    const raw = JSON.parse(
      `{"__proto__":{"polluted":1},${JSON.stringify(ATTEST).slice(1)}`,
    ) as unknown;
    expect(() => validateFrame(raw)).toThrow(/forbidden key/);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(() => validateFrame({ ...ATTEST, prototype: 1 })).toThrow(/forbidden key/);
  });

  it('returns a copy that shares nothing with the input', () => {
    const raw = structuredClone(ATTEST) as unknown as Record<string, unknown>;
    const got = validateFrame(raw) as unknown as Record<string, unknown>;
    expect(got).not.toBe(raw);
  });
});
