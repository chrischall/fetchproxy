/**
 * Account attestation (mcp-host spec 2026-09-27 "One bridge pairing per
 * account", §4.2 and §4.6): the signed payload of an `account-attest` frame,
 * the key id of an `account-key` frame, and the canonical form of a declared
 * scope that an attestation's `scopeDigest` commits to.
 *
 * One implementation of each, here (I-19). mcp-host's `BridgeRoom` signs with
 * a transcription of these functions and the extension verifies with these
 * ones; `tests/vectors/account-attest.json` is the file every transcription
 * is tested against.
 */
import type { AccountAttestConsent, HelloFrameFromServer } from './frames.js';
import { sha256 } from './crypto.js';
import { toB64, toHex } from './encoding.js';
import { isValidMcpId } from './mcp-id.js';

/**
 * Domain label at the front of every attestation payload, so the bytes can
 * never be mistaken for another signed or authenticated string in this
 * protocol (`fetchproxy/4/frame`, `fetchproxy/4/pair`).
 */
export const ACCOUNT_ATTEST_DOMAIN = 'fetchproxy/4/account-attest' as const;

/** Every value {@link AccountAttestConsent} may take, in the spec's order. */
export const ACCOUNT_ATTEST_CONSENTS: readonly AccountAttestConsent[] = Object.freeze([
  'silent',
  'confirm',
  'confirm-each',
]);

/** The `scopeDigest` of an attestation for a registration with NO approved scope. */
export const NO_SCOPE_DIGEST = '0'.repeat(64);

/**
 * Charset for the relay-issued ids and slugs an account frame carries
 * (`acc_…`, `brt_…`, `reg_…`, `zillow`). Bounded, no NUL, no whitespace, no
 * separator any encoding here depends on. mcp-host's `newId` and slug grammar
 * both fit inside it with room to spare, and a relay MUST NOT send a frame
 * this refuses: the extension's validator closes the socket 1002 on it.
 */
export const ACCOUNT_ID_RE = /^[A-Za-z0-9_.\-]{1,128}$/;
/** Lowercase hex SHA-256 — `identityHash` and `scopeDigest`. */
export const HEX64_RE = /^[0-9a-f]{64}$/;
/** `accountKeyId`'s output: the first 16 lowercase hex chars of SHA-256(pk). */
export const ACCOUNT_KID_RE = /^[0-9a-f]{16}$/;

/**
 * Inputs to {@link accountAttestPayload}. Byte fields are raw bytes, not
 * base64, so the one canonical encoding (`toB64`, padded) is applied here and
 * nowhere else: a verifier that re-encoded a received string differently
 * would otherwise verify different bytes from the ones signed.
 */
export interface AccountAttestPayloadFields {
  /** The relay's origin — must equal the link's target origin, e.g. `https://mcp.nullnet.app`. */
  gatewayOrigin: string;
  accountId: string;
  generation: number;
  /** The bridge token (`brt_…`) of the browser this was minted for. */
  tokenId: string;
  registrationId: string;
  slug: string;
  /** `hex(sha256(identityX25519Pub))`, lowercase. */
  identityHash: string;
  /** Raw 32 bytes. */
  identityEd25519Pub: Uint8Array;
  /** Lowercase hex, or {@link NO_SCOPE_DIGEST}. */
  scopeDigest: string;
  consent: AccountAttestConsent;
  mcpId: string;
  /** The server hello's `sessionNonce` — exactly ONE hello. Raw 32 bytes. */
  mcpHelloNonce: Uint8Array;
  /** The link's extension-hello `sessionNonce`. Raw 32 bytes. */
  answersExtNonce: Uint8Array;
  /** Unix seconds. */
  notAfter: number;
}

const enc = new TextEncoder();

function fail(field: string, why: string): never {
  throw new Error(`accountAttestPayload: ${field} ${why}`);
}

function checkText(field: string, v: unknown): string {
  if (typeof v !== 'string') fail(field, 'must be a string');
  if (v.length === 0) fail(field, 'must be non-empty');
  if (v.includes('\u0000')) fail(field, 'must not contain NUL');
  return v;
}

function checkPattern(field: string, v: unknown, re: RegExp, what: string): string {
  const s = checkText(field, v);
  if (!re.test(s)) fail(field, `must be ${what}`);
  return s;
}

function checkBytes(field: string, v: unknown, n: number): Uint8Array {
  if (!(v instanceof Uint8Array) || v.length !== n) fail(field, `must be exactly ${n} bytes`);
  return v;
}

function checkPositiveInt(field: string, v: unknown): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v <= 0) {
    fail(field, 'must be a positive safe integer');
  }
  return v;
}

function checkOrigin(v: unknown): string {
  const s = checkText('gatewayOrigin', v);
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return fail('gatewayOrigin', 'must be an origin');
  }
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.origin !== s) {
    fail('gatewayOrigin', 'must be a canonical http(s) origin (scheme://host[:port], no path)');
  }
  return s;
}

/**
 * The exact bytes an `account-attest` signature covers (spec §4.6):
 *
 * ```
 * utf8("fetchproxy/4/account-attest") ‖ NUL
 * ‖ gatewayOrigin ‖ NUL ‖ accountId ‖ NUL ‖ decimal(generation) ‖ NUL
 * ‖ tokenId ‖ NUL ‖ registrationId ‖ NUL ‖ slug ‖ NUL
 * ‖ identityHash ‖ NUL ‖ b64(identityEd25519Pub) ‖ NUL
 * ‖ scopeDigest ‖ NUL ‖ consent ‖ NUL ‖ mcpId ‖ NUL
 * ‖ b64(mcpHelloNonce) ‖ NUL ‖ b64(answersExtNonce) ‖ NUL ‖ decimal(notAfter)
 * ```
 *
 * Every field is bound, and the spec's table says what each one's absence
 * would allow (I-2). The encoding is unambiguous because no field can contain
 * NUL and the field count is fixed — which is why this THROWS rather than
 * encoding a NUL, an out-of-enum consent, a nonce that is not 32 bytes, a hex
 * field that is not 64 lowercase characters, or a number `decimal()` would
 * spell two ways (`1e21`, `1.5`). A throw here is a refusal to sign or to
 * verify, never a reason to fall back to something weaker.
 */
export function accountAttestPayload(f: AccountAttestPayloadFields): Uint8Array {
  const gatewayOrigin = checkOrigin(f.gatewayOrigin);
  const accountId = checkText('accountId', f.accountId);
  const generation = checkPositiveInt('generation', f.generation);
  const tokenId = checkText('tokenId', f.tokenId);
  const registrationId = checkText('registrationId', f.registrationId);
  const slug = checkText('slug', f.slug);
  const identityHash = checkPattern('identityHash', f.identityHash, HEX64_RE, '64 lowercase hex');
  const identityEd25519Pub = checkBytes('identityEd25519Pub', f.identityEd25519Pub, 32);
  const scopeDigest = checkPattern('scopeDigest', f.scopeDigest, HEX64_RE, '64 lowercase hex');
  const consent = checkText('consent', f.consent);
  if (!(ACCOUNT_ATTEST_CONSENTS as readonly string[]).includes(consent)) {
    fail('consent', `must be one of ${ACCOUNT_ATTEST_CONSENTS.join(', ')}`);
  }
  const mcpId = checkText('mcpId', f.mcpId);
  if (!isValidMcpId(mcpId)) fail('mcpId', 'is not a valid mcpId');
  const mcpHelloNonce = checkBytes('mcpHelloNonce', f.mcpHelloNonce, 32);
  const answersExtNonce = checkBytes('answersExtNonce', f.answersExtNonce, 32);
  const notAfter = checkPositiveInt('notAfter', f.notAfter);

  return enc.encode(
    [
      ACCOUNT_ATTEST_DOMAIN,
      gatewayOrigin,
      accountId,
      String(generation),
      tokenId,
      registrationId,
      slug,
      identityHash,
      toB64(identityEd25519Pub),
      scopeDigest,
      consent,
      mcpId,
      toB64(mcpHelloNonce),
      toB64(answersExtNonce),
      String(notAfter),
    ].join('\u0000'),
  );
}

/**
 * The key id an `account-key` / `account-attest` frame carries (spec §4.2):
 * `hex(SHA-256(publicKey))[0:16]`. It SELECTS a key and proves nothing — the
 * extension verifies against the public key it stored when the person
 * approved the account, and refuses a `kid` that does not match that key.
 */
export async function accountKeyId(publicKey: Uint8Array): Promise<string> {
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new Error('accountKeyId: publicKey must be exactly 32 bytes');
  }
  return toHex(await sha256(publicKey)).slice(0, 16);
}

// --- canonical scope ---------------------------------------------------------

/**
 * Every scope-bearing field of a server hello — the fields whose values change
 * what the extension would grant. {@link canonicalScope} covers exactly these.
 */
export const ACCOUNT_SCOPE_FIELDS = [
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
] as const satisfies readonly (keyof HelloFrameFromServer)[];

type ScopeField = (typeof ACCOUNT_SCOPE_FIELDS)[number];

/**
 * The server hello's fields that are NOT scope: identity, session and
 * transport. Listed so that the check below is a two-sided partition.
 */
const NON_SCOPE_HELLO_FIELDS = [
  'type',
  'protocolVersion',
  'role',
  'mcpId',
  'serverName',
  'version',
  'accepts',
  'identityX25519Pub',
  'identityEd25519Pub',
  'sessionNonce',
  'sessionPub',
  'answersExtNonce',
  'sessionSig',
] as const satisfies readonly (keyof HelloFrameFromServer)[];

/**
 * I-20, at compile time: every field of `HelloFrameFromServer` is classified
 * as scope or not-scope. Adding a field to the hello without adding it to one
 * of the two lists above fails `tsc` (the build and `npm run typecheck`) on
 * this line — a new scope field silently left out of the digest would let two
 * scopes the extension grants differently share one.
 */
type Unclassified = Exclude<
  keyof HelloFrameFromServer,
  ScopeField | (typeof NON_SCOPE_HELLO_FIELDS)[number]
>;
type Overlap = Extract<ScopeField, (typeof NON_SCOPE_HELLO_FIELDS)[number]>;
const helloFieldsPartitioned: [Unclassified, Overlap] extends [never, never] ? true : never = true;
void helloFieldsPartitioned;

/**
 * The declared scope {@link canonicalScope} reads. A whole server hello is
 * accepted as-is; only the scope fields are read from it.
 */
export type DeclaredScope = Partial<Pick<HelloFrameFromServer, ScopeField>>;

/**
 * Canonical JSON of a JSON value: no whitespace, object keys sorted by UTF-16
 * code unit (`Array.prototype.sort`'s default), `undefined` members omitted,
 * strings as `JSON.stringify` spells them. Throws on anything JSON cannot
 * carry exactly (a non-finite number, a function, a symbol, a bigint).
 */
function canonicalJson(v: unknown, at: string): string {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error(`canonicalScope: ${at} is not a finite number`);
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map((e, i) => canonicalJson(e, `${at}[${i}]`)).join(',')}]`;
  if (typeof v === 'object') return canonicalObject(v as Record<string, unknown>, at);
  throw new Error(`canonicalScope: ${at} is not JSON (${typeof v})`);
}

/**
 * {@link canonicalJson} of an object, except that the member named
 * `setMember`, when it is an array, is encoded as a SET ({@link canonicalSet}).
 */
function canonicalObject(o: Record<string, unknown>, at: string, setMember?: string): string {
  const keys = Object.keys(o)
    .filter((k) => o[k] !== undefined)
    .sort();
  const parts = keys.map((k) => {
    const v = o[k];
    const where = `${at}.${k}`;
    const enc =
      k === setMember && Array.isArray(v)
        ? canonicalSet(v.map((x, j) => canonicalJson(x, `${where}[${j}]`)))
        : canonicalJson(v, where);
    return `${JSON.stringify(k)}:${enc}`;
  });
  return `{${parts.join(',')}}`;
}

/** Sort already-canonical element strings (by code unit) into a JSON array. */
function canonicalSet(elements: readonly string[]): string {
  return `[${[...elements].sort().join(',')}]`;
}

function arrayField(declared: DeclaredScope, k: ScopeField): unknown[] {
  const v = declared[k];
  if (v === undefined) return [];
  if (!Array.isArray(v)) throw new Error(`canonicalScope: ${k} must be an array`);
  return v;
}

/**
 * Nested arrays that are SETS to the extension's matcher, by parent field:
 * `indexedDbScopes[].keys` (a request's keys must be ⊆ them) and
 * `domListSelectors[].fields` (names are unique; each becomes a key of the
 * output row). Any other nested array keeps its order — normalising less than
 * the matcher does costs a card, never a wrong grant.
 */
const NESTED_SETS: Partial<Record<ScopeField, string>> = {
  indexedDbScopes: 'keys',
  domListSelectors: 'fields',
};

/**
 * The canonical JSON string of a declared servable scope (spec §4.5, §4.6).
 * An attestation's `scopeDigest` is {@link scopeDigest} of it, and the
 * extension attaches silently only on an exact digest match (I-11).
 *
 * - All twelve {@link ACCOUNT_SCOPE_FIELDS} are present, keys sorted. An
 *   absent array is `[]`; absent `capabilities` is `["fetch"]`, which is what
 *   the hello means by it.
 * - Every top-level array is a set, sorted by its elements' canonical JSON,
 *   as are the nested sets in `NESTED_SETS`.
 * - `domains` are lowercased. Nothing else is: I-20 requires the form to be
 *   INJECTIVE over what the extension grants, so it normalises only where the
 *   extension's own matcher does (set order; hostname case). Cookie, storage
 *   and header names, selectors and GraphQL names are matched exactly, so
 *   they are digested exactly. Duplicates are kept, not merged.
 * - Elements are encoded whole, every member included, so a field added to a
 *   declaration type later is covered without an edit here. What the
 *   compile-time check above guards is the TOP-level list.
 *
 * The digest is taken over the scope AS DECLARED, before a browser's
 * unavailable capabilities are subtracted — the runner cannot know which
 * browser will attach (spec §4.8.2).
 */
export function canonicalScope(declared: DeclaredScope): string {
  const members: string[] = [];
  for (const k of [...ACCOUNT_SCOPE_FIELDS].sort()) {
    let arr = arrayField(declared, k);
    if (k === 'capabilities' && declared.capabilities === undefined) arr = ['fetch'];
    const nested = NESTED_SETS[k];
    const elements = arr.map((e, i) => {
      const at = `${k}[${i}]`;
      if (k === 'domains') {
        if (typeof e !== 'string') throw new Error(`canonicalScope: ${at} must be a string`);
        return JSON.stringify(e.toLowerCase());
      }
      if (nested !== undefined && typeof e === 'object' && e !== null && !Array.isArray(e)) {
        return canonicalObject(e as Record<string, unknown>, at, nested);
      }
      return canonicalJson(e, at);
    });
    members.push(`${JSON.stringify(k)}:${canonicalSet(elements)}`);
  }
  return `{${members.join(',')}}`;
}

/** `hex(sha256(utf8(canonicalScope(declared))))`, lowercase. */
export async function scopeDigest(declared: DeclaredScope): Promise<string> {
  return toHex(await sha256(enc.encode(canonicalScope(declared))));
}
