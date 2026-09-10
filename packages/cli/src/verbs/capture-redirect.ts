import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor } from '../server-opts.js';
import { EXIT, UsageError, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { defaultServerFactory, pairCodePrinter, type VerbServerFactory } from './fetch.js';
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
 * scope is the profile's declared `domains`, so the host is checked against
 * those here, before the bridge is dialled.
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
  const onDomain = profile.domains.some(
    (d) => cmd.host === d || cmd.host.endsWith(`.${d}`),
  );
  if (!onDomain) {
    throw new UsageError(
      `${cmd.host} is not on this profile's declared domains (${profile.domains.join(', ')})`,
      'add a domain with: fpx profile add <name> --domain … (new profile) or edit profiles.json',
    );
  }

  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
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
