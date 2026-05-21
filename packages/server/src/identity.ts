import { readFile, writeFile, mkdir, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import {
  generateX25519,
  generateEd25519,
  toB64,
  fromB64,
} from '@fetchproxy/protocol';

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

export function defaultIdentityDir(): string {
  return join(homedir(), '.fetchproxy', 'identity');
}

export async function loadOrCreateIdentity(
  serverName: string,
  dir: string = defaultIdentityDir(),
): Promise<Identity> {
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
  const safeFile = serverName.replace(/\//g, '_');
  const path = join(dir, `${safeFile}.json`);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  try {
    const raw = await readFile(path, 'utf8');
    const j = JSON.parse(raw);
    return {
      x25519Priv: fromB64(j.x25519Priv),
      x25519Pub: fromB64(j.x25519Pub),
      ed25519Priv: fromB64(j.ed25519Priv),
      ed25519Pub: fromB64(j.ed25519Pub),
      createdAt: j.createdAt,
    };
  } catch (e: unknown) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }
  // Doesn't exist — generate fresh keypair.
  const x = await generateX25519();
  const ed = await generateEd25519();
  const id: Identity = {
    x25519Priv: x.privateKey,
    x25519Pub: x.publicKey,
    ed25519Priv: ed.privateKey,
    ed25519Pub: ed.publicKey,
    createdAt: Date.now(),
  };
  const j = {
    x25519Priv: toB64(id.x25519Priv),
    x25519Pub: toB64(id.x25519Pub),
    ed25519Priv: toB64(id.ed25519Priv),
    ed25519Pub: toB64(id.ed25519Pub),
    createdAt: id.createdAt,
  };
  await writeFile(path, JSON.stringify(j, null, 2), { mode: 0o600 });
  // Belt-and-suspenders on umask-affected systems where {mode} on writeFile
  // may not produce 0600 reliably.
  await chmod(path, 0o600);
  return id;
}
