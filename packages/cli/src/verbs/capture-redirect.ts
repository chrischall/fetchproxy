import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor } from '../server-opts.js';
import { EXIT, UsageError, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import {
  assertHostOnProfile, bridgeDeadlineFor, defaultServerFactory, pairCodePrinter,
  type VerbServerFactory,
} from './fetch.js';
import { VERSION } from '../version.js';

/**
 * `fpx capture-redirect <host>[/path]` — snapshot where the next matching
 * request gets REDIRECTED to.
 *
 * The case it exists for: an endpoint that 302s cross-origin to a presigned
 * URL. A page-level fetch sees an opaque redirect and can tell you nothing;
 * `onBeforeRedirect` sees the target. That is a diagnosis you reach for a
 * shell to make, which is why the CLI having no surface for it mattered
 * (chrischall/fetchproxy#341).
 *
 * Unlike `capture`, there is no per-entry declaration to narrow against —
 * scope is the profile's declared `domains`, so the host goes through
 * `assertHostOnProfile` before the bridge is dialled. That is the SAME
 * function `fpx get` reaches through `assertUrlOnProfile`, so the refusal a
 * user reads is one sentence with one place to change it.
 */
export async function runCaptureRedirect(
  cmd: Extract<Command, { kind: 'capture-redirect' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  if (profile.captureRedirect !== true) {
    throw new UsageError(
      'this profile may not capture redirects',
      'grant it with: fpx profile declare <name> --allow-capture-redirect ' +
        '(re-pair once, since trust is keyed to the capability set)',
    );
  }
  assertHostOnProfile(cmd.host, profile);

  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    // As in `capture`: the transport's 30s default silently caps a longer
    // `--capture-timeout` (chrischall/fetchproxy#342).
    fetchTimeoutMs: bridgeDeadlineFor(cmd.timeoutMs),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    const url = await server.captureRedirect({
      host: cmd.host,
      ...(cmd.path !== undefined ? { path: cmd.path } : {}),
      ...(cmd.timeoutMs !== undefined ? { timeoutMs: cmd.timeoutMs } : {}),
    });
    printJson(io, { host: cmd.host, path: cmd.path ?? null, redirectUrl: url });
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
