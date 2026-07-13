import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor } from '../server-opts.js';
import { EXIT, UsageError, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import {
  assertUrlOnProfile, defaultServerFactory, pairCodePrinter, type VerbServerFactory,
} from './fetch.js';
import { VERSION } from '../version.js';

export async function runDownload(
  cmd: Extract<Command, { kind: 'download' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  // Validate BEFORE connecting — usage errors must not cost a bridge
  // round-trip (and must not trigger pairing).
  if (!profile.download) {
    throw new UsageError(
      'this profile does not allow downloads — run: fpx profile declare <name> --allow-download',
    );
  }
  assertUrlOnProfile(cmd.url, profile);

  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    const result = await server.download({ url: cmd.url, filename: cmd.filename });
    printJson(io, result);
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
