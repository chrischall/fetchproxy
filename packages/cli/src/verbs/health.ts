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
    //
    // The fetch tab-matcher is strict-prefix by design (a fetch inherits the
    // tab's origin context), so a profile declaring the apex will NOT match a
    // `www.` tab. `--subdomain` lets the user aim at the host they actually
    // have open instead of being told, unhelpfully, that no tab matches.
    const host = cmd.subdomain ? `${cmd.subdomain}.${domain}` : domain;
    const res = await server.request('HEAD', '/', {
      domain,
      ...(cmd.subdomain !== undefined ? { subdomain: cmd.subdomain } : {}),
    });
    io.err(`paired ✓ (${cmd.profile} → ${host}, HTTP ${res.status})`);
    return EXIT.OK;
  } catch (err) {
    // The bridge's "no tab matching <apex>" is accurate but leaves the user
    // stuck when their tab is on a subdomain — name the escape hatch.
    if (err instanceof Error && /^no tab matching /.test(err.message) && !cmd.subdomain) {
      io.err(
        `no tab open on ${domain} — if your signed-in tab is on a subdomain ` +
          `(e.g. www.${domain}), retry with --subdomain www`,
      );
    }
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
