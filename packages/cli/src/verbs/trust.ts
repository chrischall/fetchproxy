import { readdir, readFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { clearExtensionPin, defaultIdentityDir, safeIdentityFileBase } from '@fetchproxy/server';
import type { Command } from '../args.js';
import { EXIT, printJson, UsageError, type Io } from '../output.js';

/**
 * `fpx trust` — see and drop the extension identities MCPs have pinned (#208).
 *
 * The pin is what stops a stranger answering as your browser, and the cost of
 * that is a legitimate re-install locking every MCP out at once. The refusal
 * message names the exact file to delete, and `FETCHPROXY_TRUST_NEW_EXTENSION=1`
 * re-pairs an MCP whose source you don't own — this is the same escape hatch
 * with a way to look at the state first, because "delete a file you cannot see
 * the contents of" is a poor answer to a security prompt.
 *
 * It works directly on the identity directory rather than through a bridge
 * connection: an operator reaching for this has an MCP that is refusing to
 * connect, so requiring a connection would be circular.
 */

const SUFFIX = '.extension-trust.json';

/**
 * Best-effort inverse of the identity-file naming: a scoped package's `/` is
 * stored as `_`, so `@fetchproxy_example-mcp` came from
 * `@fetchproxy/example-mcp`.
 *
 * The mapping is LOSSY, and an earlier version of this comment claimed
 * otherwise. `_` is legal on both sides of the `/` (`SAFE_SCOPED` in
 * `identity.ts`), so `@my_org/tool-mcp` and `@my/org_tool-mcp` share the stem
 * `@my_org_tool-mcp` and neither can be recovered from it. Guessing produces a
 * name for a package that may not exist; only the unambiguous case — a leading
 * `@` and exactly one `_` — is translated, and everything else is left as the
 * stem, which `clear` still resolves (see `pinFileFor`).
 *
 * This exists because a listing whose names `clear` refuses sends the reader
 * to the wrong conclusion at the worst possible moment.
 */
function serverNameFromPinFile(stem: string): string {
  if (!stem.startsWith('@')) return stem;
  const parts = stem.split('_');
  if (parts.length !== 2) return stem;
  return `${parts[0]}/${parts[1]}`;
}

interface PinnedEntry {
  /** What to hand back to `fpx trust clear`. */
  serverName: string;
  /**
   * The pin FILE's stem, which is not always the server name: a scoped MCP
   * (`@fetchproxy/example-mcp`) stores its pin as `@fetchproxy_example-mcp`,
   * and feeding that back in as a server name is refused as unsafe (it has an
   * `@` but no `/`). So this is labelled for what it is, and anything that
   * deletes works from `file` rather than re-deriving a path from it.
   */
  pinFile: string;
  identityX25519Pub: string;
  identityEd25519Pub: string;
  pinnedAt: string;
  file: string;
}

async function listPins(dir: string): Promise<PinnedEntry[]> {
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return [];
  }
  const entries: PinnedEntry[] = [];
  for (const name of names.filter((n) => n.endsWith(SUFFIX)).sort()) {
    const file = join(dir, name);
    try {
      const raw = JSON.parse(await readFile(file, 'utf8')) as Record<string, unknown>;
      entries.push({
        serverName: serverNameFromPinFile(name.slice(0, -SUFFIX.length)),
        pinFile: name.slice(0, -SUFFIX.length),
        identityX25519Pub: String(raw.identityX25519Pub ?? '(unreadable)'),
        identityEd25519Pub: String(raw.identityEd25519Pub ?? '(unreadable)'),
        pinnedAt:
          typeof raw.pinnedAt === 'number' ? new Date(raw.pinnedAt).toISOString() : '(unreadable)',
        file,
      });
    } catch {
      // A corrupt pin is exactly what someone runs this to find: the MCP
      // refuses every connection over it, so listing must show it rather than
      // skip it.
      entries.push({
        serverName: serverNameFromPinFile(name.slice(0, -SUFFIX.length)),
        pinFile: name.slice(0, -SUFFIX.length),
        identityX25519Pub: '(unreadable)',
        identityEd25519Pub: '(unreadable)',
        pinnedAt: '(unreadable)',
        file,
      });
    }
  }
  return entries;
}

/**
 * Clear one pin by whatever the operator had to hand: a server name, or the
 * file stem the listing printed when the name could not be recovered from it.
 * The stem path exists so that everything `list` prints is something `clear`
 * accepts — a scoped name whose stem is ambiguous would otherwise be legible
 * and unusable at the same time.
 */
async function clearPin(nameOrStem: string, identityDir: string): Promise<boolean> {
  // Ask FIRST whether this is a legal server name, rather than trying and
  // treating any throw as "must have been a stem". A `catch` here swallows
  // real filesystem failures — an EACCES on the identity directory would come
  // back as "no extension pin for X", sending someone to look for a missing
  // file when the problem is permissions on one that exists.
  let isServerName = true;
  try {
    safeIdentityFileBase(nameOrStem);
  } catch {
    isServerName = false;
  }
  if (isServerName) return clearExtensionPin(nameOrStem, identityDir);

  // Otherwise it can only be the stem the listing printed for a name it could
  // not recover. Anything that goes wrong from here is reported as itself.
  const pins = await listPins(identityDir);
  const match = pins.find((p) => p.pinFile === nameOrStem);
  if (!match) throw new UsageError(`no extension pin for ${nameOrStem}`);
  await unlink(match.file);
  return true;
}

export async function runTrust(
  cmd: Extract<Command, { kind: 'trust' }>,
  io: Io,
  identityDir: string = defaultIdentityDir(),
): Promise<number> {
  if (cmd.action === 'list') {
    const pins = await listPins(identityDir);
    if (pins.length === 0) {
      io.out(`no extension pins in ${identityDir}`);
      return EXIT.OK;
    }
    if (cmd.json) {
      printJson(io, pins);
      return EXIT.OK;
    }
    // Default to something readable. Someone running this is usually staring
    // at a refusal and wants to know which browser is pinned and since when,
    // not to parse 32 bytes of base64.
    for (const pin of pins) {
      io.out(`${pin.serverName}  pinned ${pin.pinnedAt}  x25519=${pin.identityX25519Pub}`);
    }
    return EXIT.OK;
  }

  if (cmd.all) {
    const pins = await listPins(identityDir);
    if (pins.length === 0) {
      io.err(`nothing pinned in ${identityDir}`);
      return EXIT.OK;
    }
    // Delete by PATH, not by re-deriving one from the file stem: a scoped
    // MCP's stem is not a legal server name, and the previous version threw on
    // the first one — aborting partway and leaving the fleet half-cleared
    // while reporting nothing.
    const failed: string[] = [];
    for (const pin of pins) {
      try {
        await unlink(pin.file);
      } catch {
        failed.push(pin.serverName);
      }
    }
    const cleared = pins.length - failed.length;
    io.err(
      `cleared ${cleared} extension pin(s): ${pins
        .filter((p) => !failed.includes(p.serverName))
        .map((p) => p.serverName)
        .join(', ')} — each re-pins on the next browser to complete a handshake with it`,
    );
    if (failed.length > 0) {
      // Say which ones survived rather than reporting a clean sweep: an
      // operator who thinks the fleet is cleared and finds one MCP still
      // refusing has no way to tell that from a new attack.
      io.err(`could not clear: ${failed.join(', ')} — delete them by hand in ${identityDir}`);
    }
    return EXIT.OK;
  }

  const had = await clearPin(cmd.serverName!, identityDir);
  if (had) {
    io.err(
      `cleared the extension pin for ${cmd.serverName} — the next browser to complete a ` +
        `handshake with it becomes the pinned one`,
    );
  } else {
    io.err(`nothing pinned for ${cmd.serverName} in ${identityDir}`);
  }
  return EXIT.OK;
}
