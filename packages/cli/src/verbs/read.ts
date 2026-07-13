import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor } from '../server-opts.js';
import { EXIT, UsageError, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { defaultServerFactory, pairCodePrinter, type VerbServerFactory } from './fetch.js';
import { VERSION } from '../version.js';

const DECLARE_FLAG: Record<string, string> = {
  cookies: '--cookie',
  localStorage: '--local-storage',
  sessionStorage: '--session-storage',
};

/** Same split bootstrap() uses on the bridge's `k=v; k2=v2` join. */
function cookieRecord(joined: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const piece of joined.split('; ')) {
    if (!piece) continue;
    const eq = piece.indexOf('=');
    if (eq < 0) continue;
    out[piece.slice(0, eq)] = piece.slice(eq + 1);
  }
  return out;
}

function narrowKeys(requested: string[], declared: string[], bucket: string): string[] {
  if (declared.length === 0) {
    throw new UsageError(
      `profile declares no ${bucket} scope — declare it first: ` +
        `fpx profile declare <name> ${DECLARE_FLAG[bucket]} <key>`,
    );
  }
  if (requested.length === 0) return declared;
  const undeclared = requested.filter((k) => !declared.includes(k));
  if (undeclared.length > 0) {
    throw new UsageError(
      `key(s) not in the profile's declared ${bucket} scope: ${undeclared.join(', ')} — ` +
        `widen the scope with: fpx profile declare <name> ${DECLARE_FLAG[bucket]} <key> (forces a re-pair)`,
    );
  }
  return requested;
}

export async function runRead(
  cmd: Extract<Command, { kind: 'read' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  // Validate scope narrowing BEFORE connecting — usage errors must not
  // cost a bridge round-trip (and must not trigger pairing).
  const scope = { domain: cmd.storageDomain, subdomain: cmd.storageSubdomain };
  let keys: string[] = [];
  if (cmd.bucket === 'indexedDb') {
    if (cmd.keys.length > 0) {
      throw new UsageError('indexeddb does not take key arguments — it reads all declared scopes',
        'edit the profile\'s "indexedDb" array in profiles.json to change scopes');
    }
    if (profile.indexedDb.length === 0) {
      throw new UsageError('profile declares no indexedDb scopes',
        'add entries to the profile\'s "indexedDb" array in profiles.json (forces a re-pair)');
    }
  } else {
    keys = narrowKeys(cmd.keys, profile[cmd.bucket], cmd.bucket);
  }

  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    switch (cmd.bucket) {
      case 'cookies':
        printJson(io, cookieRecord(await server.readCookies({ keys, ...scope })));
        break;
      case 'localStorage':
        printJson(io, await server.readLocalStorage({ keys, ...scope }));
        break;
      case 'sessionStorage':
        printJson(io, await server.readSessionStorage({ keys, ...scope }));
        break;
      case 'indexedDb': {
        const out: Record<string, Record<string, unknown>> = {};
        for (const s of profile.indexedDb) {
          out[`${s.database}/${s.store}`] = await server.readIndexedDb({
            database: s.database, store: s.store, keys: [...s.keys], ...scope,
          });
        }
        printJson(io, out);
        break;
      }
    }
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
