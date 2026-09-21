import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor } from '../server-opts.js';
import { requireStorageDomain } from '../storage-scope.js';
import { EXIT, UsageError, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { defaultServerFactory, pairCodePrinter, type VerbServerFactory } from './fetch.js';
import { VERSION } from '../version.js';

function requireDeclaredDomList(name: string, declared: string[]): void {
  if (declared.length === 0) {
    throw new UsageError(
      'profile declares no DOM list selectors — declare one first: ' +
        'fpx profile declare <name> --dom-list-selector <handle>=<item-css>::<field>:<selector>,...',
    );
  }
  if (!declared.includes(name)) {
    throw new UsageError(
      `name not in the profile's declared DOM list selectors: ${name} — ` +
        'widen the scope with: fpx profile declare <name> --dom-list-selector ... (forces a re-pair)',
    );
  }
}

export async function runDomList(
  cmd: Extract<Command, { kind: 'dom-list' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  // Validate scope narrowing BEFORE connecting — usage errors must not
  // cost a bridge round-trip (and must not trigger pairing).
  requireStorageDomain(profile, cmd.storageDomain);
  requireDeclaredDomList(cmd.name, profile.domListSelectors.map((d) => d.name));

  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    const result = await server.readDomList({
      name: cmd.name, domain: cmd.storageDomain, subdomain: cmd.storageSubdomain,
    });
    printJson(io, result);
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
