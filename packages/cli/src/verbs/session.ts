import { bootstrap } from '@fetchproxy/bootstrap';
import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { EXIT, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { pairCodePrinter } from './fetch.js';
import { VERSION } from '../version.js';

export async function runSession(
  cmd: Extract<Command, { kind: 'session' }>,
  profile: Profile,
  io: Io,
  bootstrapFn: typeof bootstrap = bootstrap,
): Promise<number> {
  try {
    const session = await bootstrapFn({
      serverName: `fpx-${cmd.profile}`,
      version: VERSION,
      domains: [...profile.domains],
      declare: {
        cookies: [...profile.cookies],
        localStorage: [...profile.localStorage],
        sessionStorage: [...profile.sessionStorage],
        captureHeaders: profile.captureHeaders.map((d) => ({ ...d })),
        indexedDb: profile.indexedDb.map((d) => ({ ...d, keys: [...d.keys] })),
        localStoragePointers: profile.localStoragePointers.map((p) => ({ ...p })),
        sessionStoragePointers: profile.sessionStoragePointers.map((p) => ({ ...p })),
      },
      storageDomain: cmd.storageDomain,
      storageSubdomain: cmd.storageSubdomain,
      onPairCode: pairCodePrinter(io),
      onWaiting: (hint) => io.err(`waiting: ${hint}`),
    });
    printJson(io, session);
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  }
}
