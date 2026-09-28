import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  ACCOUNT_ATTEST_DOMAIN,
  ACCOUNT_ATTEST_CONSENTS,
  ACCOUNT_SCOPE_FIELDS,
  NO_SCOPE_DIGEST,
  accountAttestPayload,
  accountKeyId,
  canonicalScope,
  scopeDigest,
  type AccountAttestPayloadFields,
  type DeclaredScope,
} from '../src/index.js';
import { ed25519Sign, ed25519Verify, sha256 } from '../src/crypto.js';
import { fromB64, toB64, toHex } from '../src/encoding.js';

// The vector file is generated from the SPEC by `vectors/account-attest.gen.mjs`
// (a hand-joined string and hand-written canonical scopes, never this
// package's implementation). mcp-host transcribes against the same file (I-19).
const vectorPath = fileURLToPath(new URL('./vectors/account-attest.json', import.meta.url));
const V = JSON.parse(readFileSync(vectorPath, 'utf8')) as {
  accountKey: { seedHex: string; publicKeyB64: string; kid: string };
  attest: {
    identityX25519PubB64: string;
    fields: Record<string, string | number>;
    fieldOrder: string[];
    payloadHex: string;
    sigB64: string;
  };
  scopes: { name: string; input: DeclaredScope; canonical: string; digest: string }[];
};

function fromHex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const SEED = fromHex(V.accountKey.seedHex);
const PUB = fromB64(V.accountKey.publicKeyB64);
const SIG = fromB64(V.attest.sigB64);

/** The vector's fields in the function's input shape (byte fields decoded). */
function vectorFields(): AccountAttestPayloadFields {
  const f = V.attest.fields;
  return {
    gatewayOrigin: f.gatewayOrigin as string,
    accountId: f.accountId as string,
    generation: f.generation as number,
    tokenId: f.tokenId as string,
    registrationId: f.registrationId as string,
    slug: f.slug as string,
    identityHash: f.identityHash as string,
    identityEd25519Pub: fromB64(f.identityEd25519Pub as string),
    scopeDigest: f.scopeDigest as string,
    consent: f.consent as AccountAttestPayloadFields['consent'],
    mcpId: f.mcpId as string,
    mcpHelloNonce: fromB64(f.mcpHelloNonce as string),
    answersExtNonce: fromB64(f.answersExtNonce as string),
    notAfter: f.notAfter as number,
  };
}

const bytes = (fill: number, n: number): Uint8Array => new Uint8Array(n).fill(fill);

describe('accountAttestPayload — exact bytes (spec §4.6)', () => {
  it('equals the vector file byte for byte', () => {
    expect(toHex(accountAttestPayload(vectorFields()))).toBe(V.attest.payloadHex);
  });

  it('is the domain label, NUL, then the 14 fields NUL-separated in spec order', () => {
    const f = vectorFields();
    const expected = [
      'fetchproxy/4/account-attest',
      f.gatewayOrigin,
      f.accountId,
      String(f.generation),
      f.tokenId,
      f.registrationId,
      f.slug,
      f.identityHash,
      toB64(f.identityEd25519Pub),
      f.scopeDigest,
      f.consent,
      f.mcpId,
      toB64(f.mcpHelloNonce),
      toB64(f.answersExtNonce),
      String(f.notAfter),
    ].join('\u0000');
    expect(new TextDecoder().decode(accountAttestPayload(f))).toBe(expected);
    expect(ACCOUNT_ATTEST_DOMAIN).toBe('fetchproxy/4/account-attest');
  });

  it('names exactly the 14 spec fields, in order', () => {
    expect(V.attest.fieldOrder).toEqual([
      'gatewayOrigin',
      'accountId',
      'generation',
      'tokenId',
      'registrationId',
      'slug',
      'identityHash',
      'identityEd25519Pub',
      'scopeDigest',
      'consent',
      'mcpId',
      'mcpHelloNonce',
      'answersExtNonce',
      'notAfter',
    ]);
    expect(Object.keys(vectorFields()).sort()).toEqual([...V.attest.fieldOrder].sort());
  });

  it('the vector signature verifies under the vector key, and signing is reproducible', async () => {
    const payload = accountAttestPayload(vectorFields());
    expect(await ed25519Verify(PUB, payload, SIG)).toBe(true);
    expect(toB64(await ed25519Sign(SEED, payload))).toBe(V.attest.sigB64);
  });

  it('the vector identityHash is sha256 of the vector identityX25519Pub', async () => {
    const h = toHex(await sha256(fromB64(V.attest.identityX25519PubB64)));
    expect(h).toBe(V.attest.fields.identityHash);
  });
});

/**
 * I-2 mutation table: for each of the 14 fields, one altered value. A
 * signature over the vector payload must NOT verify against the altered
 * payload — so an implementation that dropped any one field from the bytes
 * would fail here.
 */
const MUTATIONS: Record<keyof AccountAttestPayloadFields, (f: AccountAttestPayloadFields) => void> =
  {
    gatewayOrigin: (f) => void (f.gatewayOrigin = 'https://mcp.example.app'),
    accountId: (f) => void (f.accountId = 'acc_000000000000000000000000'),
    generation: (f) => void (f.generation = 4),
    tokenId: (f) => void (f.tokenId = 'brt_ffffffffffffffffffffffff'),
    registrationId: (f) => void (f.registrationId = 'reg_000000000000000000000000'),
    slug: (f) => void (f.slug = 'zi11ow'),
    identityHash: (f) => void (f.identityHash = 'f'.repeat(64)),
    identityEd25519Pub: (f) => void (f.identityEd25519Pub = bytes(0x23, 32)),
    scopeDigest: (f) => void (f.scopeDigest = NO_SCOPE_DIGEST),
    consent: (f) => void (f.consent = 'confirm'),
    mcpId: (f) => void (f.mcpId = 'zillow-mcp:0.12.0:770a8e083b61277a'),
    mcpHelloNonce: (f) => void (f.mcpHelloNonce = bytes(0x34, 32)),
    answersExtNonce: (f) => void (f.answersExtNonce = bytes(0x45, 32)),
    notAfter: (f) => void (f.notAfter = 1788063213),
  };

describe('I-2 mutation table: every field is bound by the signature', () => {
  it('covers all 14 fields', () => {
    expect(Object.keys(MUTATIONS).sort()).toEqual([...V.attest.fieldOrder].sort());
  });

  for (const [field, mutate] of Object.entries(MUTATIONS)) {
    it(`altering ${field} changes the bytes and breaks the signature`, async () => {
      const f = vectorFields();
      mutate(f);
      const altered = accountAttestPayload(f);
      expect(toHex(altered)).not.toBe(V.attest.payloadHex);
      expect(await ed25519Verify(PUB, altered, SIG)).toBe(false);
    });
  }

  // A swap keeps every value present but moves it — an encoding that lost the
  // field ORDER (a sorted or keyed encoding) would pass the table above and
  // fail here.
  const SWAPS: [keyof AccountAttestPayloadFields, keyof AccountAttestPayloadFields][] = [
    ['mcpHelloNonce', 'answersExtNonce'],
    ['accountId', 'tokenId'],
    ['tokenId', 'registrationId'],
    ['identityHash', 'scopeDigest'],
    ['generation', 'notAfter'],
  ];
  for (const [a, b] of SWAPS) {
    it(`swapping ${a} and ${b} breaks the signature`, async () => {
      const f = vectorFields() as unknown as Record<string, unknown>;
      const t = f[a];
      f[a] = f[b];
      f[b] = t;
      const swapped = accountAttestPayload(f as unknown as AccountAttestPayloadFields);
      expect(await ed25519Verify(PUB, swapped, SIG)).toBe(false);
    });
  }

  it('a signature over the payload does not verify under a different account key', async () => {
    const other = await ed25519Sign(bytes(0x09, 32), accountAttestPayload(vectorFields()));
    expect(await ed25519Verify(PUB, accountAttestPayload(vectorFields()), other)).toBe(false);
  });
});

describe('accountAttestPayload — refuses inputs that would make the encoding ambiguous', () => {
  const STRING_FIELDS = [
    'gatewayOrigin',
    'accountId',
    'tokenId',
    'registrationId',
    'slug',
    'identityHash',
    'scopeDigest',
    'consent',
    'mcpId',
  ] as const;

  for (const k of STRING_FIELDS) {
    it(`throws on a NUL in ${k}`, () => {
      const f = vectorFields() as unknown as Record<string, unknown>;
      f[k] = `${String(f[k])}\u0000x`;
      expect(() => accountAttestPayload(f as unknown as AccountAttestPayloadFields)).toThrow();
    });
    it(`throws on an empty ${k}`, () => {
      const f = vectorFields() as unknown as Record<string, unknown>;
      f[k] = '';
      expect(() => accountAttestPayload(f as unknown as AccountAttestPayloadFields)).toThrow();
    });
  }

  it('the NUL refusal names NUL for the free-form id fields', () => {
    for (const k of ['accountId', 'tokenId', 'registrationId', 'slug'] as const) {
      const f = vectorFields();
      f[k] = 'a\u0000b';
      expect(() => accountAttestPayload(f)).toThrow(/NUL/);
    }
  });

  it('throws on a consent outside the enum', () => {
    for (const bad of ['SILENT', 'allow', 'confirm_each', ' silent']) {
      const f = vectorFields() as unknown as Record<string, unknown>;
      f.consent = bad;
      expect(() => accountAttestPayload(f as unknown as AccountAttestPayloadFields)).toThrow(
        /consent/,
      );
    }
    expect([...ACCOUNT_ATTEST_CONSENTS]).toEqual(['silent', 'confirm', 'confirm-each']);
  });

  for (const k of ['mcpHelloNonce', 'answersExtNonce'] as const) {
    it(`throws on a ${k} that is not 32 bytes`, () => {
      for (const n of [0, 16, 31, 33]) {
        const f = vectorFields();
        f[k] = bytes(0x33, n);
        expect(() => accountAttestPayload(f)).toThrow(new RegExp(k));
      }
    });
  }

  it('throws on an identityEd25519Pub that is not 32 bytes', () => {
    const f = vectorFields();
    f.identityEd25519Pub = bytes(0x22, 31);
    expect(() => accountAttestPayload(f)).toThrow(/identityEd25519Pub/);
  });

  it('throws on an identityHash or scopeDigest that is not 64 lowercase hex', () => {
    for (const k of ['identityHash', 'scopeDigest'] as const) {
      for (const bad of ['A'.repeat(64), 'a'.repeat(63), 'a'.repeat(65), 'g'.repeat(64)]) {
        const f = vectorFields();
        f[k] = bad;
        expect(() => accountAttestPayload(f)).toThrow(new RegExp(k));
      }
    }
  });

  it('throws on a generation that is not a positive safe integer', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
      const f = vectorFields();
      f.generation = bad;
      expect(() => accountAttestPayload(f)).toThrow(/generation/);
    }
  });

  it('throws on a notAfter that is not a positive safe integer', () => {
    for (const bad of [0, -1, 1.5, Number.NaN, 1e21]) {
      const f = vectorFields();
      f.notAfter = bad;
      expect(() => accountAttestPayload(f)).toThrow(/notAfter/);
    }
  });

  it('throws on an invalid mcpId', () => {
    const f = vectorFields();
    f.mcpId = 'zillow-mcp';
    expect(() => accountAttestPayload(f)).toThrow(/mcpId/);
  });

  it('throws on a gatewayOrigin that is not a canonical http(s) origin', () => {
    for (const bad of [
      'https://mcp.nullnet.app/',
      'https://MCP.nullnet.app',
      'https://mcp.nullnet.app/path',
      'wss://mcp.nullnet.app',
      'mcp.nullnet.app',
    ]) {
      const f = vectorFields();
      f.gatewayOrigin = bad;
      expect(() => accountAttestPayload(f)).toThrow(/gatewayOrigin/);
    }
  });
});

describe('accountKeyId (spec §4.2: kid = hex(sha256(pk))[0:16])', () => {
  it('matches the vector', async () => {
    expect(await accountKeyId(PUB)).toBe(V.accountKey.kid);
  });
  it('refuses a key that is not 32 bytes', async () => {
    await expect(accountKeyId(bytes(1, 31))).rejects.toThrow(/32/);
  });
});

// --- canonical scope ---------------------------------------------------------

const RICH = (): DeclaredScope => structuredClone(V.scopes[2]!.input);

describe('canonicalScope / scopeDigest — vectors', () => {
  for (const c of V.scopes) {
    it(`matches the vector: ${c.name}`, async () => {
      expect(canonicalScope(c.input)).toBe(c.canonical);
      expect(await scopeDigest(c.input)).toBe(c.digest);
    });
  }

  it('scopeDigest is hex(sha256(utf8(canonicalScope)))', async () => {
    const s = RICH();
    const want = toHex(await sha256(new TextEncoder().encode(canonicalScope(s))));
    expect(await scopeDigest(s)).toBe(want);
  });

  it('NO_SCOPE_DIGEST is 64 zeros and no scope digests to it', async () => {
    expect(NO_SCOPE_DIGEST).toBe('0'.repeat(64));
    expect(await scopeDigest({})).not.toBe(NO_SCOPE_DIGEST);
  });

  it('names exactly the 12 scope-bearing hello fields', () => {
    expect([...ACCOUNT_SCOPE_FIELDS].sort()).toEqual(
      [
        'domains',
        'capabilities',
        'cookieKeys',
        'localStorageKeys',
        'sessionStorageKeys',
        'captureHeaders',
        'indexedDbScopes',
        'domSelectors',
        'domListSelectors',
        'graphqlOps',
        'localStoragePointers',
        'sessionStoragePointers',
      ].sort(),
    );
  });
});

describe('canonicalScope — normalises only where the extension matcher does', () => {
  const TOP_LEVEL_SETS = [
    'domains',
    'capabilities',
    'cookieKeys',
    'localStorageKeys',
    'sessionStorageKeys',
    'captureHeaders',
    'indexedDbScopes',
    'domSelectors',
    'domListSelectors',
    'graphqlOps',
    'localStoragePointers',
  ] as const;

  /** RICH, with a second DISTINCT element in the arrays that hold only one. */
  const RICH2 = (): DeclaredScope => {
    const s = RICH();
    s.indexedDbScopes!.push({
      origin: 'https://zillow.com',
      database: 'a',
      store: 'b',
      keys: ['c'],
    });
    s.domListSelectors!.push({ name: 'cards', itemSelector: 'div.card', fields: [{ name: 'x' }] });
    s.graphqlOps!.push({ name: 'detail', operationName: 'DetailQuery' });
    return s;
  };

  for (const k of TOP_LEVEL_SETS) {
    it(`is order-insensitive for ${k}`, () => {
      const b = RICH2();
      const arr = b[k] as unknown[];
      expect(arr.length).toBeGreaterThanOrEqual(2); // a one-element array proves nothing
      arr.reverse();
      expect(canonicalScope(b)).toBe(canonicalScope(RICH2()));
    });
  }

  it('is order-insensitive for sessionStoragePointers', () => {
    const a: DeclaredScope = {
      sessionStoragePointers: [
        { key: 'a', jsonPointer: '/x' },
        { key: 'b', jsonPointer: '/y' },
      ],
    };
    const b: DeclaredScope = {
      sessionStoragePointers: [
        { key: 'b', jsonPointer: '/y' },
        { key: 'a', jsonPointer: '/x' },
      ],
    };
    expect(canonicalScope(a)).toBe(canonicalScope(b));
  });

  it('is order-insensitive inside indexedDbScopes[].keys and domListSelectors[].fields', () => {
    const a = RICH();
    const b = RICH();
    b.indexedDbScopes![0]!.keys.reverse();
    b.domListSelectors![0]!.fields.reverse();
    expect(canonicalScope(b)).toBe(canonicalScope(a));
  });

  it('is order-insensitive for object KEYS inside elements', () => {
    const a: DeclaredScope = { captureHeaders: [{ host: 'a.example.com', headerName: 'X' }] };
    const b: DeclaredScope = { captureHeaders: [{ headerName: 'X', host: 'a.example.com' }] };
    expect(canonicalScope(a)).toBe(canonicalScope(b));
  });

  it('is case-insensitive for domains', () => {
    expect(canonicalScope({ domains: ['Zillow.COM'] })).toBe(
      canonicalScope({ domains: ['zillow.com'] }),
    );
  });

  it('is case-SENSITIVE everywhere else (the extension matches those exactly)', () => {
    const pairs: [DeclaredScope, DeclaredScope][] = [
      [{ cookieKeys: ['SID'] }, { cookieKeys: ['sid'] }],
      [{ localStorageKeys: ['Tok'] }, { localStorageKeys: ['tok'] }],
      [{ sessionStorageKeys: ['Tok'] }, { sessionStorageKeys: ['tok'] }],
      [
        { graphqlOps: [{ name: 'q', operationName: 'Search' }] },
        { graphqlOps: [{ name: 'q', operationName: 'search' }] },
      ],
      [
        { domSelectors: [{ name: 'n', selector: 'DIV' }] },
        { domSelectors: [{ name: 'n', selector: 'div' }] },
      ],
    ];
    for (const [a, b] of pairs) expect(canonicalScope(a)).not.toBe(canonicalScope(b));
  });

  it('gives the same digest for an absent array and an empty one', async () => {
    for (const k of ACCOUNT_SCOPE_FIELDS) {
      if (k === 'capabilities') continue; // absent means ['fetch'], below
      const withEmpty = { [k]: [] } as DeclaredScope;
      expect(await scopeDigest(withEmpty)).toBe(await scopeDigest({}));
    }
  });

  it('treats absent capabilities as the hello does: ["fetch"]', () => {
    expect(canonicalScope({})).toBe(canonicalScope({ capabilities: ['fetch'] }));
    expect(canonicalScope({})).not.toBe(canonicalScope({ capabilities: ['read_cookies'] }));
  });

  it('ignores every non-scope field of a full server hello', () => {
    const hello = {
      type: 'hello',
      protocolVersion: 4,
      role: 'server',
      mcpId: 'zillow-mcp:0.12.0:770a8e083b612779',
      serverName: 'zillow-mcp',
      version: '0.12.0',
      accepts: ['hello-rejected'],
      identityX25519Pub: 'AAAA',
      identityEd25519Pub: 'BBBB',
      sessionNonce: 'CCCC',
      sessionPub: 'DDDD',
      answersExtNonce: 'EEEE',
      sessionSig: 'FFFF',
      ...RICH(),
    } as unknown as DeclaredScope;
    expect(canonicalScope(hello)).toBe(canonicalScope(RICH()));
  });

  it('does not mutate its input', () => {
    const s = RICH();
    const before = JSON.stringify(s);
    canonicalScope(s);
    expect(JSON.stringify(s)).toBe(before);
  });
});

describe('canonicalScope — changing any element changes the digest (injective)', () => {
  const EDITS: [string, (s: DeclaredScope) => void][] = [
    ['domains: add one', (s) => s.domains!.push('zillowstatic.com')],
    ['domains: change one', (s) => (s.domains![1] = 'zillow.co')],
    ['capabilities: drop one', (s) => s.capabilities!.pop()],
    ['capabilities: add write_cookies', (s) => s.capabilities!.push('write_cookies')],
    ['cookieKeys: change one', (s) => (s.cookieKeys![0] = 'zguid2')],
    ['localStorageKeys: add one', (s) => s.localStorageKeys!.push('c')],
    ['sessionStorageKeys: drop one', (s) => s.sessionStorageKeys!.pop()],
    ['captureHeaders: header name', (s) => (s.captureHeaders![0]!.headerName = 'X-Other')],
    ['captureHeaders: host', (s) => (s.captureHeaders![0]!.host = 'www2.zillow.com')],
    ['captureHeaders: drop path', (s) => delete s.captureHeaders![0]!.path],
    ['indexedDbScopes: origin', (s) => (s.indexedDbScopes![0]!.origin = 'https://zillow.com')],
    ['indexedDbScopes: database', (s) => (s.indexedDbScopes![0]!.database = 'db2')],
    ['indexedDbScopes: store', (s) => (s.indexedDbScopes![0]!.store = 'st2')],
    ['indexedDbScopes: add a key', (s) => s.indexedDbScopes![0]!.keys.push('k3')],
    ['domSelectors: selector', (s) => (s.domSelectors![0]!.selector = 'h2')],
    ['domSelectors: attribute', (s) => (s.domSelectors![1]!.attribute = 'data-w')],
    ['domListSelectors: itemSelector', (s) => (s.domListSelectors![0]!.itemSelector = 'li')],
    ['domListSelectors: maxItems', (s) => (s.domListSelectors![0]!.maxItems = 51)],
    [
      'domListSelectors: field selector',
      (s) => (s.domListSelectors![0]!.fields[0]!.selector = '.y'),
    ],
    ['graphqlOps: operationName', (s) => (s.graphqlOps![0]!.operationName = 'Other')],
    ['localStoragePointers: pointer', (s) => (s.localStoragePointers![0]!.jsonPointer = '/x/z')],
    [
      'sessionStoragePointers: add one',
      (s) => s.sessionStoragePointers!.push({ key: 's1', jsonPointer: '/a' }),
    ],
    [
      'move a key between cookie and localStorage',
      (s) => {
        s.cookieKeys!.push('a');
        s.localStorageKeys!.splice(s.localStorageKeys!.indexOf('a'), 1);
      },
    ],
  ];

  for (const [name, edit] of EDITS) {
    it(name, async () => {
      const s = RICH();
      edit(s);
      expect(await scopeDigest(s)).not.toBe(await scopeDigest(RICH()));
    });
  }

  it('a string element cannot spell an array boundary', () => {
    expect(canonicalScope({ cookieKeys: ['a","b'] })).not.toBe(
      canonicalScope({ cookieKeys: ['a', 'b'] }),
    );
  });
});

describe('canonicalScope — refuses what it cannot encode canonically', () => {
  it('throws on a non-array scope field', () => {
    expect(() => canonicalScope({ domains: 'zillow.com' } as unknown as DeclaredScope)).toThrow(
      /domains/,
    );
  });
  it('throws on a non-finite number inside an element', () => {
    const s: DeclaredScope = {
      domListSelectors: [{ name: 'r', itemSelector: 'li', fields: [{ name: 'a' }], maxItems: NaN }],
    };
    expect(() => canonicalScope(s)).toThrow();
  });
});
