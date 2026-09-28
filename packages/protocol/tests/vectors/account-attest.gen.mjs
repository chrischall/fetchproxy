// Independent generator for packages/protocol/tests/vectors/account-attest.json.
// Built from the spec text (mcp-host spec §4.2, §4.6; plan A1), NOT from the
// implementation under test: the payload is a hand-joined string and the
// canonical scopes are hand-written literals.
//
// Usage (from packages/protocol/tests): node vectors/account-attest.gen.mjs vectors/account-attest.json
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const out = process.argv[2];
const fill = (b, n) => Buffer.alloc(n, b);
const b64 = (buf) => Buffer.from(buf).toString('base64');
const hex = (buf) => Buffer.from(buf).toString('hex');
const sha256 = (buf) => createHash('sha256').update(buf).digest();

// --- account key -----------------------------------------------------------
const seed = Buffer.from(Array.from({ length: 32 }, (_, i) => i)); // 00 01 .. 1f
const pkcs8 = Buffer.concat([
  Buffer.from('302e020100300506032b657004220420', 'hex'),
  seed,
]);
const priv = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
const pubDer = createPublicKey(priv).export({ format: 'der', type: 'spki' });
const pub = pubDer.subarray(pubDer.length - 32);
const kid = hex(sha256(pub)).slice(0, 16);

// --- canonical scopes (hand-written expected outputs) ---------------------
const scopeCases = [
  {
    name: 'absent everything: capabilities defaults to fetch, every array is []',
    input: {},
    canonical:
      '{"capabilities":["fetch"],"captureHeaders":[],"cookieKeys":[],"domListSelectors":[],"domSelectors":[],"domains":[],"graphqlOps":[],"indexedDbScopes":[],"localStorageKeys":[],"localStoragePointers":[],"sessionStorageKeys":[],"sessionStoragePointers":[]}',
  },
  {
    name: 'minimal fetch-only hello',
    input: { domains: ['zillow.com'] },
    canonical:
      '{"capabilities":["fetch"],"captureHeaders":[],"cookieKeys":[],"domListSelectors":[],"domSelectors":[],"domains":["zillow.com"],"graphqlOps":[],"indexedDbScopes":[],"localStorageKeys":[],"localStoragePointers":[],"sessionStorageKeys":[],"sessionStoragePointers":[]}',
  },
  {
    name: 'every scope field, shuffled order, mixed-case domains',
    input: {
      domains: ['WWW.Zillow.com', 'zillow.com'],
      capabilities: [
        'read_session_storage',
        'read_cookies',
        'fetch',
        'read_indexed_db',
        'capture_request_header',
        'read_dom_list',
        'read_dom',
        'graphql',
        'read_local_storage',
      ],
      cookieKeys: ['zguid', 'JSESSIONID'],
      localStorageKeys: ['b', 'a'],
      sessionStorageKeys: ['s2', 's1'],
      captureHeaders: [
        { host: 'api.zillow.com', path: '/v2/*', headerName: 'X-Token' },
        { headerName: 'Authorization', host: 'www.zillow.com' },
      ],
      indexedDbScopes: [
        { store: 'st', origin: 'https://www.zillow.com', keys: ['k2', 'k1'], database: 'db' },
      ],
      domSelectors: [
        { selector: 'h1', name: 'title' },
        { name: 'price', selector: '.price', attribute: 'data-v' },
      ],
      domListSelectors: [
        {
          name: 'rows',
          itemSelector: 'li.row',
          maxItems: 50,
          fields: [{ selector: '.z', name: 'z' }, { name: 'a' }],
        },
      ],
      graphqlOps: [{ operationName: 'SearchQuery', name: 'search' }],
      localStoragePointers: [
        { key: 'b', jsonPointer: '/x/y' },
        { jsonPointer: '/t', key: 'a' },
      ],
      sessionStoragePointers: [],
    },
    canonical:
      '{"capabilities":["capture_request_header","fetch","graphql","read_cookies","read_dom","read_dom_list","read_indexed_db","read_local_storage","read_session_storage"],' +
      '"captureHeaders":[{"headerName":"Authorization","host":"www.zillow.com"},{"headerName":"X-Token","host":"api.zillow.com","path":"/v2/*"}],' +
      '"cookieKeys":["JSESSIONID","zguid"],' +
      '"domListSelectors":[{"fields":[{"name":"a"},{"name":"z","selector":".z"}],"itemSelector":"li.row","maxItems":50,"name":"rows"}],' +
      '"domSelectors":[{"attribute":"data-v","name":"price","selector":".price"},{"name":"title","selector":"h1"}],' +
      '"domains":["www.zillow.com","zillow.com"],' +
      '"graphqlOps":[{"name":"search","operationName":"SearchQuery"}],' +
      '"indexedDbScopes":[{"database":"db","keys":["k1","k2"],"origin":"https://www.zillow.com","store":"st"}],' +
      '"localStorageKeys":["a","b"],' +
      '"localStoragePointers":[{"jsonPointer":"/t","key":"a"},{"jsonPointer":"/x/y","key":"b"}],' +
      '"sessionStorageKeys":["s1","s2"],' +
      '"sessionStoragePointers":[]}',
  },
];
for (const c of scopeCases) {
  JSON.parse(c.canonical); // well-formed
  c.digest = hex(sha256(Buffer.from(c.canonical, 'utf8')));
}

// --- attestation ------------------------------------------------------------
const identityX25519Pub = fill(0x11, 32);
const fields = {
  gatewayOrigin: 'https://mcp.nullnet.app',
  accountId: 'acc_f05c0ebf831e35df687660d1',
  generation: 3,
  tokenId: 'brt_0123456789abcdef01234567',
  registrationId: 'reg_89abcdef0123456789abcdef',
  slug: 'zillow',
  identityHash: hex(sha256(identityX25519Pub)),
  identityEd25519Pub: b64(fill(0x22, 32)),
  scopeDigest: scopeCases[2].digest,
  consent: 'silent',
  mcpId: 'zillow-mcp:0.12.0:770a8e083b612779',
  mcpHelloNonce: b64(fill(0x33, 32)),
  answersExtNonce: b64(fill(0x44, 32)),
  notAfter: 1788063212,
};
const order = [
  'gatewayOrigin', 'accountId', 'generation', 'tokenId', 'registrationId', 'slug',
  'identityHash', 'identityEd25519Pub', 'scopeDigest', 'consent', 'mcpId',
  'mcpHelloNonce', 'answersExtNonce', 'notAfter',
];
const text = ['fetchproxy/4/account-attest', ...order.map((k) => String(fields[k]))].join('\u0000');
const payload = Buffer.from(text, 'utf8');
const sig = sign(null, payload, priv);

const vector = {
  description:
    'fetchproxy protocol 4 account-attest test vectors. Generated from the spec (mcp-host docs/superpowers/specs/2026-09-27-account-level-bridge-pairing-design.md §4.2, §4.6), independently of the implementation. Byte fields are standard padded base64; hashes are lowercase hex. Every transcription (mcp-host) is tested against this file (I-19).',
  accountKey: {
    seedHex: hex(seed),
    publicKeyB64: b64(pub),
    kid,
  },
  attest: {
    identityX25519PubB64: b64(identityX25519Pub),
    fields,
    fieldOrder: order,
    payloadHex: hex(payload),
    sigB64: b64(sig),
  },
  scopes: scopeCases,
};
writeFileSync(out, JSON.stringify(vector, null, 2) + '\n');
console.log('kid', kid, 'payload bytes', payload.length);
