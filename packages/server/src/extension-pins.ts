/**
 * A HOST-MANAGED extension pin set — the alternative to trust on first use.
 *
 * `extension-trust.ts` pins ONE extension per MCP: whichever completes a
 * handshake first, remembered. That is right on a laptop and wrong under a
 * hosting provider, which already knows which browsers belong to an account.
 * With first-use pins, every new registration, re-placed snapshot row and
 * identity reset trusts whichever extension arrives first — a thief holding a
 * stolen relay credential, if theirs is attached — and a second, legitimate
 * browser is refused by every child that already pinned the first, with no
 * way out a hosted user can reach.
 *
 * So a host can PROVIDE the set instead: `<trustDir>/<serverName>.extension-pins.json`,
 * `{ "v": 1, "managed": true, "extensions": [{ "x25519Pub", "ed25519Pub", "label"? }] }`,
 * turned on with `FETCHPROXY_EXTENSION_PINS=managed` (or the `extensionPins:
 * 'managed'` option). In that mode:
 *
 *  - The set is read on EVERY handshake and never cached: it is how the host
 *    admits a newly confirmed browser and revokes an old one, and a cached
 *    copy would keep admitting a revoked browser until the child restarts.
 *  - An extension is accepted only when ONE entry matches BOTH its X25519 and
 *    its Ed25519 key, and its `ready` signature verifies under that Ed25519
 *    key (host.ts / peer.ts verify the signature against the hello's key,
 *    which this check has just tied to the entry). One key is never enough: a
 *    browser holding a listed signing key could otherwise present anyone's
 *    agreement key, or the reverse.
 *  - Nothing is ever written and nothing falls back to first use. The
 *    first-use pin file is neither read nor written, and
 *    `FETCHPROXY_TRUST_NEW_EXTENSION` is ignored.
 *  - A missing, unreadable or malformed file refuses every extension. The log
 *    names the path and never a key.
 *
 * No wire change: this decides which extension hellos the server accepts,
 * nothing about what goes on the wire.
 */
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fromB64, toB64 } from '@fetchproxy/protocol';
import { safeIdentityFileBase } from './identity.js';

/** The pin-set file format this build reads and a host should write. */
export const EXTENSION_PINS_FILE_VERSION = 1;

/** `managed` switches this MCP to the host-managed pin set. */
export const EXTENSION_PINS_ENV = 'FETCHPROXY_EXTENSION_PINS';

export type ExtensionPinsMode = 'managed' | 'first-use';

/** One browser the host has admitted. Keys are canonical base64 of 32 raw bytes. */
export interface ManagedExtensionPin {
  x25519Pub: string;
  ed25519Pub: string;
  label?: string;
}

export interface ExtensionPinSet {
  v: typeof EXTENSION_PINS_FILE_VERSION;
  managed: true;
  /** Who writes this file, for `fpx trust` to name. Optional. */
  managedBy?: string;
  extensions: ManagedExtensionPin[];
}

export type ExtensionPinsErrorCode = 'EXTENSION_PINS_MISSING' | 'EXTENSION_PINS_MALFORMED';

export class ExtensionPinsError extends Error {
  readonly code: ExtensionPinsErrorCode;
  constructor(code: ExtensionPinsErrorCode, message: string) {
    super(message);
    this.name = 'ExtensionPinsError';
    this.code = code;
  }
}

function malformed(why: string): ExtensionPinsError {
  // `why` is always a description of the SHAPE, never a value out of the file:
  // this message is logged by a child the host runs, and the file holds the
  // account's browser keys.
  return new ExtensionPinsError('EXTENSION_PINS_MALFORMED', `malformed extension pin set: ${why}`);
}

function isKey(x: unknown): x is string {
  if (typeof x !== 'string' || x === '') return false;
  let raw: Uint8Array;
  try {
    raw = fromB64(x);
  } catch {
    return false;
  }
  // Canonical only. The hello's key is compared as a string, so a set written
  // in another spelling of the same bytes would refuse the browser it lists —
  // fail closed, but for a reason nobody could see. Refusing the FILE says so.
  return raw.length === 32 && toB64(raw) === x;
}

/**
 * Parse and validate a pin-set file's text. Pure: a host validates what it
 * writes with this same function, so the two cannot disagree about the format.
 *
 * Throws `ExtensionPinsError` (`EXTENSION_PINS_MALFORMED`) on anything that is
 * not exactly the documented shape. An EMPTY `extensions` array is valid — it
 * is what "every browser revoked" looks like, and it refuses everyone.
 */
export function parseExtensionPins(text: string): ExtensionPinSet {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw malformed('not JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw malformed('not an object');
  }
  const r = parsed as Record<string, unknown>;
  if (r.v !== EXTENSION_PINS_FILE_VERSION) {
    throw malformed(`"v" is not ${EXTENSION_PINS_FILE_VERSION}`);
  }
  if (r.managed !== true) throw malformed('"managed" is not true');
  if (r.managedBy !== undefined && typeof r.managedBy !== 'string') {
    throw malformed('"managedBy" is not a string');
  }
  if (!Array.isArray(r.extensions)) throw malformed('"extensions" is not an array');
  const extensions: ManagedExtensionPin[] = r.extensions.map((e: unknown, i: number) => {
    if (!e || typeof e !== 'object' || Array.isArray(e)) {
      throw malformed(`extensions[${i}] is not an object`);
    }
    const x = e as Record<string, unknown>;
    if (!isKey(x.x25519Pub)) {
      throw malformed(`extensions[${i}].x25519Pub is not canonical base64 of 32 bytes`);
    }
    if (!isKey(x.ed25519Pub)) {
      throw malformed(`extensions[${i}].ed25519Pub is not canonical base64 of 32 bytes`);
    }
    if (x.label !== undefined && typeof x.label !== 'string') {
      throw malformed(`extensions[${i}].label is not a string`);
    }
    return {
      x25519Pub: x.x25519Pub,
      ed25519Pub: x.ed25519Pub,
      ...(x.label !== undefined ? { label: x.label } : {}),
    };
  });
  return {
    v: EXTENSION_PINS_FILE_VERSION,
    managed: true,
    ...(r.managedBy !== undefined ? { managedBy: r.managedBy as string } : {}),
    extensions,
  };
}

/** Where a host puts the set for `serverName`, under the trust directory. */
export function extensionPinsPath(serverName: string, trustDir: string): string {
  return join(trustDir, `${safeIdentityFileBase(serverName)}.extension-pins.json`);
}

/**
 * Read and parse the set from disk. Throws `ExtensionPinsError`:
 * `EXTENSION_PINS_MISSING` when the file cannot be read (absent, or
 * unreadable — either way there is no set), `EXTENSION_PINS_MALFORMED` when it
 * can but is not a valid set. Both messages name the path and no key.
 */
export async function readExtensionPinsAt(path: string): Promise<ExtensionPinSet> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (e: unknown) {
    const code = (e as NodeJS.ErrnoException).code ?? 'read failed';
    throw new ExtensionPinsError(
      'EXTENSION_PINS_MISSING',
      `no managed extension pin set at ${path} (${code})`,
    );
  }
  try {
    return parseExtensionPins(text);
  } catch (e: unknown) {
    const why = e instanceof ExtensionPinsError ? e.message : 'malformed extension pin set';
    throw new ExtensionPinsError('EXTENSION_PINS_MALFORMED', `${why} at ${path}`);
  }
}

export function readExtensionPins(serverName: string, trustDir: string): Promise<ExtensionPinSet> {
  return readExtensionPinsAt(extensionPinsPath(serverName, trustDir));
}

/** How the host and peer paths reach the managed set. */
export interface ManagedExtensionPinsPort {
  /** Read the set afresh. Called once per handshake; never cache it. */
  read(): Promise<ExtensionPinSet>;
  /** The file, for log lines. */
  location: string;
}

export type ManagedTrustOutcome =
  | { decision: 'pinned' }
  | {
      decision: 'refused';
      code: ExtensionPinsErrorCode | 'EXTENSION_NOT_PINNED';
      message: string;
    };

/**
 * Is this extension in the set? Both keys, from ONE entry.
 *
 * There is no `first-use` and no `replace` answer, and no `allowNew` input:
 * managed mode has no path by which an extension the host did not list
 * becomes accepted.
 */
export function decideManagedExtensionTrust(args: {
  set: ExtensionPinSet;
  hello: { identityX25519Pub: string; identityEd25519Pub: string };
  serverName: string;
  location?: string;
}): ManagedTrustOutcome {
  const { set, hello, serverName } = args;
  const listed = set.extensions.some(
    (e) =>
      e.x25519Pub === hello.identityX25519Pub && e.ed25519Pub === hello.identityEd25519Pub,
  );
  if (listed) return { decision: 'pinned' };
  return {
    decision: 'refused',
    code: 'EXTENSION_NOT_PINNED',
    message:
      `[fetchproxy] ${serverName}: refusing an extension that is not in the host-managed ` +
      `pin set${args.location ? ` (${args.location})` : ''}. The host that runs this MCP ` +
      `decides which browsers it accepts; confirm this browser there.`,
  };
}

/**
 * Read the set and decide, in one step that never throws: every failure to
 * obtain a set is a refusal, carrying the code the log line names.
 */
export async function evaluateManagedExtensionTrust(
  port: ManagedExtensionPinsPort,
  hello: { identityX25519Pub: string; identityEd25519Pub: string },
  serverName: string,
): Promise<ManagedTrustOutcome> {
  let set: ExtensionPinSet;
  try {
    set = await port.read();
  } catch (e: unknown) {
    const code: ExtensionPinsErrorCode =
      e instanceof ExtensionPinsError ? e.code : 'EXTENSION_PINS_MISSING';
    const detail =
      e instanceof ExtensionPinsError ? e.message : `could not read ${port.location}`;
    return {
      decision: 'refused',
      code,
      message:
        `[fetchproxy] ${serverName}: ${code}: ${detail} — refusing every extension until the ` +
        `host that manages this MCP's pins writes a valid set.`,
    };
  }
  return decideManagedExtensionTrust({ set, hello, serverName, location: port.location });
}

/**
 * Managed or not: the option, else the environment. Either one saying
 * `managed` is enough, and there is no way for one to veto the other — a host
 * that set the variable has declared that it owns the pins.
 *
 * An environment value that is set but is not `managed` FAILS CLOSED, loudly:
 * a typo must not quietly hand a hosted child back to trust on first use.
 */
export function resolveExtensionPinsMode(
  explicit: 'managed' | undefined,
  env: Record<string, string | undefined> = process.env,
): ExtensionPinsMode {
  if (explicit === 'managed') return 'managed';
  const raw = env[EXTENSION_PINS_ENV];
  if (raw === undefined || raw.trim() === '') return 'first-use';
  if (raw === 'managed') return 'managed';
  console.warn(
    `[fetchproxy] ${EXTENSION_PINS_ENV}=${JSON.stringify(raw)} is not "managed" — treating it ` +
      `as managed anyway, because a set variable means a host manages this MCP's extension ` +
      `pins. Unset it for trust on first use.`,
  );
  return 'managed';
}
