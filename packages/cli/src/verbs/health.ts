import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor } from '../server-opts.js';
import { EXIT, UsageError, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { defaultServerFactory, pairCodePrinter, type VerbServerFactory } from './fetch.js';
import { VERSION } from '../version.js';

export async function runHealth(
  cmd: Extract<Command, { kind: 'health' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    printJson(io, server.bridgeHealth());
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}

export async function runPair(
  cmd: Extract<Command, { kind: 'pair' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  const domain =
    cmd.domain ??
    (profile.domains.length === 1
      ? profile.domains[0]
      : ((): string => {
          throw new UsageError(
            `profile declares multiple domains (${profile.domains.join(', ')}) — pick one with --domain`,
          );
        })());
  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    // HEAD / through the tab: any HttpResponse — any status — proves the
    // extension is paired and a matching tab answered. Bridge-level
    // failures throw and map to EXIT.BRIDGE instead.
    const res = await server.request('HEAD', '/', { domain });
    io.err(`paired ✓ (${cmd.profile} → ${domain}, HTTP ${res.status})`);
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
