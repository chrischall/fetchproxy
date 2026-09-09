import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { homedir } from 'node:os';
import {
  generateX25519,
  generateEd25519,
  toB64,
  fromB64,
} from '@fetchproxy/protocol';

/**
 * Long-term identity keys for one fetchproxy MCP server. Persisted on
 * disk (chmod 0600) so the extension's trust record — keyed off the
 * SHA-256 of `x25519Pub` — survives process restarts.
 */
export interface Identity {
  x25519Priv: Uint8Array;
  x25519Pub: Uint8Array;
  ed25519Priv: Uint8Array;
  ed25519Pub: Uint8Array;
  createdAt: number;
}

// Allow plain names like `opentable-mcp` or scoped packages like
// `@fetchproxy/example-mcp`. Disallow bare `a/b` (no `@` prefix) so we don't
// silently treat random paths as legal identity names.
const SAFE_PLAIN = /^[A-Za-z0-9._-]+$/;
const SAFE_SCOPED = /^@[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;

/**
 * The `FETCHPROXY_IDENTITY_DIR` fallback for `FetchproxyServerOpts.identityDir`.
 *
 * Honours an ABSOLUTE path and nothing else. A relative one is ignored, not
 * resolved: it would land against the child's working directory, which is not
 * a place the operator wrote down and can differ between the process that
 * minted the identity and the next one to look for it — which is the whole
 * failure this variable exists to fix, reintroduced by the fix. As with
 * `envWsPort` and `envWsHost` in ws-server.ts, `undefined` — not the default —
 * is returned for anything unusable, so a stray or mistyped variable falls
 * through to `$HOME` and the identity lands exactly where it always has,
 * rather than in a directory nobody chose.
 *
 * The variable exists for ONE topology (#316): a host that runs a separate
 * child per CALLER, because a stdio MCP reads its credentials from the
 * environment and an environment belongs to a process. Each such child gets
 * its own `$HOME`, so without this it gets its own identity — and the
 * extension, whose trust store is keyed by the sha256 of that identity, asks
 * to pair with every one of them. The identity answers "which MCP is the
 * browser talking to", which is a property of the server and not of the
 * caller, so a host that knows the two are different needs somewhere to say
 * so. It is not a knob for a laptop.
 */
function envIdentityDir(): string | undefined {
  const raw = process.env.FETCHPROXY_IDENTITY_DIR;
  if (raw === undefined) return undefined;
  const dir = raw.trim();
  if (dir === '' || !isAbsolute(dir)) return undefined;
  return dir;
}

/**
 * `$HOME/.fetchproxy/identity`, or `FETCHPROXY_IDENTITY_DIR` when it names an
 * absolute path. Override in code via the `dir` arg or `identityDir`, which
 * both still win — an explicit option beats an ambient one, as it does for the
 * host and port.
 */
export function defaultIdentityDir(): string {
  return envIdentityDir() ?? join(homedir(), '.fetchproxy', 'identity');
}

/**
 * The filename stem for `serverName`, rejecting anything that could escape the
 * identity directory. Scoped packages (`@fetchproxy/example-mcp`) are legal and
 * get their `/` translated to `_` — which means the stem is NOT a round-trip of
 * the server name, so callers that hold a stem must not feed it back in here.
 */
export function safeIdentityFileBase(serverName: string): string {
  // Reject empty, path-traversal, and disallowed characters.
  if (
    !serverName ||
    serverName === '..' ||
    serverName.includes('..') ||
    (!SAFE_PLAIN.test(serverName) && !SAFE_SCOPED.test(serverName))
  ) {
    throw new Error(`unsafe serverName for identity file: ${JSON.stringify(serverName)}`);
  }
  // Allow scoped packages (@scope/name) by translating / to _.
  return serverName.replace(/\//g, '_');
}

/**
 * The path this package stores `serverName`'s identity at, under `dir`.
 *
 * Exported because a host that PROVISIONS an identity (#319) has to write the
 * same path this package will later read, and deriving it by string-joining
 * `${serverName}.json` would skip `safeIdentityFileBase` — which is where the
 * scoped-package translation and the traversal refusal live.
 */
export function identityFilePath(dir: string, serverName: string): string {
  return join(dir, `${safeIdentityFileBase(serverName)}.json`);
}

/** A fresh long-term identity. Keygen only — nothing is written. */
export async function generateIdentity(): Promise<Identity> {
  const x = await generateX25519();
  const ed = await generateEd25519();
  return {
    x25519Priv: x.privateKey,
    x25519Pub: x.publicKey,
    ed25519Priv: ed.privateKey,
    ed25519Pub: ed.publicKey,
    createdAt: Date.now(),
  };
}

/**
 * The exact bytes this package writes. THE format, not a description of it.
 *
 * `serializeIdentity` and `parseIdentity` are inverses and both are exported,
 * so a host provisioning an identity is held to the same shape rather than
 * copying it out of this file — which is the coupling #319 exists to move from
 * the consumer to here. `tests/identity-format.test.ts` pins the bytes against
 * a committed vector, so changing the shape is a decision with a failing test
 * attached rather than a silent break in somebody else's repo.
 */
export function serializeIdentity(id: Identity): string {
  return JSON.stringify(
    {
      x25519Priv: toB64(id.x25519Priv),
      x25519Pub: toB64(id.x25519Pub),
      ed25519Priv: toB64(id.ed25519Priv),
      ed25519Pub: toB64(id.ed25519Pub),
      createdAt: id.createdAt,
    },
    null,
    2,
  );
}

/** The inverse of {@link serializeIdentity}. */
export function parseIdentity(text: string): Identity {
  const j = JSON.parse(text);
  return {
    x25519Priv: fromB64(j.x25519Priv),
    x25519Pub: fromB64(j.x25519Pub),
    ed25519Priv: fromB64(j.ed25519Priv),
    ed25519Pub: fromB64(j.ed25519Pub),
    createdAt: j.createdAt,
  };
}

/**
 * Write `id` where this package will find it, and return the path.
 *
 * 0600 twice over: `writeFile`'s mode is subject to the umask on some systems,
 * so the explicit `chmod` is what actually guarantees it. The directory is
 * 0700 for the same reason it always was.
 */
export async function writeIdentityFile(
  dir: string,
  serverName: string,
  id: Identity,
): Promise<string> {
  const path = identityFilePath(dir, serverName);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await writeFile(path, serializeIdentity(id), { mode: 0o600 });
  await chmod(path, 0o600);
  return path;
}

/**
 * Read the identity for `serverName` from `dir`, generating and persisting a
 * fresh X25519/Ed25519 keypair if no file exists. The file is written mode
 * 0600 (single-user only). Callers must use a safe `serverName` — scoped
 * packages like `@fetchproxy/example-mcp` are OK and get their `/` translated
 * to `_` for the filename.
 *
 * Since #319 this is a composition of the exported pieces rather than the place
 * the format is defined: `identityFilePath`, `parseIdentity`,
 * `generateIdentity` and `writeIdentityFile` each do one part, so a host that
 * provisions an identity is held to the same shape this reads.
 */
export async function loadOrCreateIdentity(
  serverName: string,
  dir: string = defaultIdentityDir(),
): Promise<Identity> {
  const path = identityFilePath(dir, serverName);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  try {
    return parseIdentity(await readFile(path, 'utf8'));
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }
  // Doesn't exist — generate fresh keypair. Built FROM the exported pieces, so
  // there is one definition of the format rather than two that can drift.
  const id = await generateIdentity();
  await writeIdentityFile(dir, serverName, id);
  return id;
}
