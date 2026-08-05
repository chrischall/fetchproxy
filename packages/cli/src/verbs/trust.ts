import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { clearExtensionPin, defaultIdentityDir } from '@fetchproxy/server';
import type { Command } from '../args.js';
import { EXIT, printJson, type Io } from '../output.js';

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

interface PinnedEntry {
  serverName: string;
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
        serverName: name.slice(0, -SUFFIX.length),
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
        serverName: name.slice(0, -SUFFIX.length),
        identityX25519Pub: '(unreadable)',
        identityEd25519Pub: '(unreadable)',
        pinnedAt: '(unreadable)',
        file,
      });
    }
  }
  return entries;
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
    printJson(io, pins);
    return EXIT.OK;
  }

  if (cmd.all) {
    const pins = await listPins(identityDir);
    if (pins.length === 0) {
      io.err(`nothing pinned in ${identityDir}`);
      return EXIT.OK;
    }
    for (const pin of pins) await clearExtensionPin(pin.serverName, identityDir);
    io.err(
      `cleared ${pins.length} extension pin(s): ${pins.map((p) => p.serverName).join(', ')} — ` +
        `each re-pins on the next browser to complete a handshake with it`,
    );
    return EXIT.OK;
  }

  const had = await clearExtensionPin(cmd.serverName!, identityDir);
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
