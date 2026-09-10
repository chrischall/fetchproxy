import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor } from '../server-opts.js';
import { EXIT, UsageError, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import {
  assertUrlOnProfile,
  defaultServerFactory,
  pairCodePrinter,
  type VerbServerFactory,
} from './fetch.js';
import { VERSION } from '../version.js';

/**
 * `fpx graphql <name> [--var k=v]…` — run a DECLARED GraphQL operation
 * through the page's own Apollo client.
 *
 * Not a fetch. The extension resolves the declared `name` to an
 * `operationName`, finds the live DocumentNode the page's client already
 * observed, and invokes `client.query(...)` in the MAIN world — the same path
 * the site itself uses, so per-request bot telemetry runs automatically. That
 * is the whole reason the verb exists rather than being a POST you could hand
 * to `fpx post-json`.
 *
 * It follows that a name must be DECLARED: an undeclared one would be an
 * arbitrary query on the user's live session, which is a different privilege
 * from the ones already approved. Narrowed here, before the bridge is dialled,
 * and the server enforces it again.
 */
export async function runGraphql(
  cmd: Extract<Command, { kind: 'graphql' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  if (profile.graphqlOps.length === 0) {
    throw new UsageError(
      'profile declares no GraphQL operations — declare one first: ' +
        'fpx profile declare <name> --graphql-op <handle>=<OperationName>',
    );
  }
  const declared = profile.graphqlOps.map((op) => op.name);
  if (!declared.includes(cmd.name)) {
    throw new UsageError(
      `operation ${JSON.stringify(cmd.name)} is not declared by this profile`,
      `declared: ${declared.join(', ')}`,
    );
  }

  // Checked the same way, and at the same time, as `fpx get --via-tab`. The
  // server guards it too, but that guard only fires after the bridge is up,
  // turning a typo into exit 2 ("bridge error") when it is plainly a usage
  // error — and making the user wait on a connection to be told so (#209).
  // Adding a second call site for this flag without the check is how that
  // regression comes back.
  if (cmd.viaTab !== undefined) assertUrlOnProfile(cmd.viaTab, profile);

  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    const data = await server.graphqlQuery({
      name: cmd.name,
      variables: cmd.variables,
      ...(cmd.viaTab !== undefined ? { tabUrl: cmd.viaTab } : {}),
    });
    printJson(io, data);
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
