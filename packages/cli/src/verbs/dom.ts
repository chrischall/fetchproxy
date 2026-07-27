import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor } from '../server-opts.js';
import { requireStorageDomain } from '../storage-scope.js';
import { EXIT, UsageError, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { defaultServerFactory, pairCodePrinter, type VerbServerFactory } from './fetch.js';
import { VERSION } from '../version.js';

function narrowDomNames(requested: string[], declared: string[]): string[] {
  if (declared.length === 0) {
    throw new UsageError(
      'profile declares no DOM selectors — declare one first: ' +
        'fpx profile declare <name> --dom-selector <handle>=<css>',
    );
  }
  if (requested.length === 0) return declared;
  const undeclared = requested.filter((n) => !declared.includes(n));
  if (undeclared.length > 0) {
    throw new UsageError(
      `name(s) not in the profile's declared DOM selectors: ${undeclared.join(', ')} — ` +
        'widen the scope with: fpx profile declare <name> --dom-selector <handle>=<css> (forces a re-pair)',
    );
  }
  return requested;
}

export async function runDom(
  cmd: Extract<Command, { kind: 'dom' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  // Validate scope narrowing BEFORE connecting — usage errors must not
  // cost a bridge round-trip (and must not trigger pairing).
  requireStorageDomain(profile, cmd.storageDomain);
  const names = narrowDomNames(cmd.names, profile.domSelectors.map((d) => d.name));

  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    const result = await server.readDom({
      names, domain: cmd.storageDomain, subdomain: cmd.storageSubdomain,
    });
    printJson(io, result);
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
