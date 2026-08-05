/**
 * The MCP side's pin on the extension's identity (#208).
 *
 * The trust relationship has been asymmetric since 0.4.0 and the asymmetry is
 * invisible on loopback. The extension pins the MCP: `trustedMcps`, keyed by
 * the SHA-256 of its X25519 pub, checked on every connection, with a re-pair
 * prompt when it changes. The MCP pins nothing. `host.ts` verifies
 * `ready.sessionSig` against the identity presented in the SAME connection —
 * which proves the connecting party holds the key it just showed us, and says
 * nothing about whether it is the party we talked to last time — and `peer.ts`
 * verifies nothing at all.
 *
 * On `127.0.0.1` that is a deliberate, documented scope: the only thing that
 * can reach the port is a local process, and the local trust boundary is the
 * product's stated model. The moment the far end of that socket can be
 * something other than a process on this machine, "whichever extension said
 * hello" stops being an answer — because a stolen relay credential then buys
 * an attacker a working session with every bridged MCP, seeing the requests
 * they make and answering them, with no prompt anywhere.
 *
 * So this module is the other half of `trustedMcps`: first contact is trusted
 * and remembered (TOFU, matching what the extension does), and a DIFFERENT
 * identity afterwards is refused rather than silently accepted.
 *
 * WHAT THIS IS NOT. The pin lives in a file next to the MCP's own private key,
 * so a local process that can write there can delete the pin and force a fresh
 * first contact. That is the same trust boundary the identity key itself has
 * (mode 0600, single user), and closing it is not something a file store can
 * do. What the pin closes is the REMOTE case, where the attacker is not on
 * this machine and cannot touch this file.
 */
import { readFile, writeFile, rename, unlink, mkdir, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { defaultIdentityDir, safeIdentityFileBase } from './identity.js';

/** The extension identity an MCP has committed to, base64 raw 32B each. */
export interface ExtensionPin {
  identityX25519Pub: string;
  identityEd25519Pub: string;
  pinnedAt: number;
}

/** The identity material an extension hello carries. */
export interface ExtensionIdentityClaim {
  identityX25519Pub: string;
  identityEd25519Pub: string;
}

/**
 * How the host and peer paths reach the pin. A port rather than a path so the
 * decision and the storage can be tested apart — and so a caller has to say
 * what its trust store IS, rather than getting a default that silently writes
 * into `$HOME` from a unit test.
 */
export interface ExtensionTrustPort {
  read(): Promise<ExtensionPin | null>;
  write(pin: ExtensionPin): Promise<void>;
  /** The operator has allowed a new identity to replace the pinned one. */
  allowNew: boolean;
  /**
   * Where the pin actually lives, for the refusal message. Without it a
   * refusal can only guess at the default location — and an MCP with an
   * `identityDir` of its own would tell the user to delete a file that is not
   * the one blocking them.
   */
  location?: string;
}

/** The file-backed port: the pin beside the MCP's own identity. */
export function fileExtensionTrust(args: {
  serverName: string;
  dir?: string;
  allowNew: boolean;
}): ExtensionTrustPort {
  return {
    allowNew: args.allowNew,
    location: extensionTrustPath(args.serverName, args.dir ?? defaultIdentityDir()),
    read: () => readExtensionPin(args.serverName, args.dir ?? defaultIdentityDir()),
    write: (pin) => writeExtensionPin(args.serverName, pin, args.dir ?? defaultIdentityDir()),
  };
}

export type TrustOutcome =
  /** Nothing pinned yet: accept, and pin once the signature proves the key. */
  | { decision: 'first-use' }
  /** Same identity as last time. */
  | { decision: 'pinned' }
  /** Different identity, and the operator has not allowed one: refuse. */
  | { decision: 'refused'; message: string }
  /** Different identity, explicitly allowed: accept and re-pin, loudly. */
  | { decision: 'replace'; message: string };

/**
 * Environment escape hatch, read only when the caller expressed no opinion.
 *
 * An option would be cleaner, and one exists — but the MCPs that construct
 * `FetchproxyServer` are thirteen separate packages, and an operator whose
 * extension re-install has just bricked all of them cannot patch thirteen
 * packages to get out of it. This is the one lever that reaches an
 * unmodified consumer.
 */
export const TRUST_NEW_EXTENSION_ENV = 'FETCHPROXY_TRUST_NEW_EXTENSION';

export function allowNewExtensionIdentity(
  explicit: boolean | undefined,
  env: Record<string, string | undefined> = process.env,
): boolean {
  if (explicit !== undefined) return explicit;
  return env[TRUST_NEW_EXTENSION_ENV] === '1';
}

export function decideExtensionTrust(args: {
  pin: ExtensionPin | null;
  hello: ExtensionIdentityClaim;
  allowNew: boolean;
  serverName: string;
  /** Where the pin lives; falls back to the default location when unknown. */
  location?: string;
}): TrustOutcome {
  const { pin, hello, allowNew, serverName } = args;
  if (!pin) return { decision: 'first-use' };
  // Both keys, not either: a rotation of one is a different extension, and
  // accepting a half-match would let an attacker keep the ECDH key it needs
  // while swapping the signing key it doesn't hold, or the reverse.
  if (
    pin.identityX25519Pub === hello.identityX25519Pub &&
    pin.identityEd25519Pub === hello.identityEd25519Pub
  ) {
    return { decision: 'pinned' };
  }
  const trustPath = args.location ?? extensionTrustPathHint(serverName);
  if (allowNew) {
    return {
      decision: 'replace',
      message:
        `[fetchproxy] ${serverName}: accepting a NEW extension identity because ` +
        `${TRUST_NEW_EXTENSION_ENV}=1 — re-pinning. Unset it once the browser you ` +
        `expect is connected.`,
    };
  }
  return {
    decision: 'refused',
    message:
      `[fetchproxy] ${serverName}: refusing an extension whose identity is not the ` +
      `one this MCP paired with. If you re-installed the extension or moved to ` +
      `another browser, re-pair deliberately: run this MCP once with ` +
      `${TRUST_NEW_EXTENSION_ENV}=1, or delete ${trustPath}. If you did neither, ` +
      `something else is answering as your browser.`,
  };
}

/** Where the pin lives — beside the identity, one per MCP. */
export function extensionTrustPath(serverName: string, dir: string = defaultIdentityDir()): string {
  return join(dir, `${safeIdentityFileBase(serverName)}.extension-trust.json`);
}

/** Same path, but never throws — for use inside an error message. */
function extensionTrustPathHint(serverName: string): string {
  try {
    return extensionTrustPath(serverName);
  } catch {
    return join(defaultIdentityDir(), '<server-name>.extension-trust.json');
  }
}

function isPin(x: unknown): x is ExtensionPin {
  if (!x || typeof x !== 'object') return false;
  const r = x as Record<string, unknown>;
  return (
    typeof r.identityX25519Pub === 'string' &&
    typeof r.identityEd25519Pub === 'string' &&
    typeof r.pinnedAt === 'number'
  );
}

export async function readExtensionPin(
  serverName: string,
  dir: string = defaultIdentityDir(),
): Promise<ExtensionPin | null> {
  const path = extensionTrustPath(serverName, dir);
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw e;
  }
  // Fail closed. Treating an unreadable pin as "no pin" would turn any
  // scribble on this file into a fresh trust-on-first-use, which is exactly
  // the state an attacker wants the MCP in.
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`unreadable extension pin at ${path} (not JSON) — delete it to re-pair`);
  }
  if (!isPin(parsed)) {
    throw new Error(`unreadable extension pin at ${path} (wrong shape) — delete it to re-pair`);
  }
  return {
    identityX25519Pub: parsed.identityX25519Pub,
    identityEd25519Pub: parsed.identityEd25519Pub,
    pinnedAt: parsed.pinnedAt,
  };
}

export async function writeExtensionPin(
  serverName: string,
  pin: ExtensionPin,
  dir: string = defaultIdentityDir(),
): Promise<void> {
  const path = extensionTrustPath(serverName, dir);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  // Write-then-rename: a torn file here reads as "unreadable" and refuses
  // every connection, so it must never be possible to observe half of one.
  const tmp = `${path}.tmp`;
  await writeFile(tmp, JSON.stringify(pin, null, 2), { mode: 0o600 });
  await chmod(tmp, 0o600);
  await rename(tmp, path);
}

/** Drop the pin. Returns whether there was one. */
export async function clearExtensionPin(
  serverName: string,
  dir: string = defaultIdentityDir(),
): Promise<boolean> {
  const path = extensionTrustPath(serverName, dir);
  try {
    await unlink(path);
    return true;
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return false;
    throw e;
  }
}
