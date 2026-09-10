import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor } from '../server-opts.js';
import { requireStorageDomain } from '../storage-scope.js';
import { EXIT, UsageError, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { defaultServerFactory, pairCodePrinter, type VerbServerFactory } from './fetch.js';
import { VERSION } from '../version.js';

/**
 * `fpx write-cookies` — set cookies the profile already declares.
 *
 * Same gap as `fpx capture`: `--allow-cookie-write` derived the
 * `write_cookies` capability and put it in the pair prompt, and nothing could
 * then exercise it. Approving a privilege the tool cannot use is worse than
 * not offering it.
 *
 * Two refusals happen HERE rather than at the bridge, so a mistake costs no
 * round trip and no pair prompt: writing without `--allow-cookie-write`
 * declared, and writing a name outside the profile's declared `cookies`. The
 * server enforces the second too — this is the readable copy, not the
 * security boundary.
 */
export async function runWriteCookies(
  cmd: Extract<Command, { kind: 'write-cookies' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  if (profile.cookieWrite !== true) {
    throw new UsageError(
      'this profile may not write cookies',
      'grant it with: fpx profile declare <name> --allow-cookie-write ' +
        '(re-pair once, since trust is keyed to the capability set)',
    );
  }
  const names = Object.keys(cmd.cookies);
  if (names.length === 0) {
    throw new UsageError('fpx write-cookies requires at least one name=value pair');
  }
  const undeclared = names.filter((n) => !profile.cookies.includes(n));
  if (undeclared.length > 0) {
    throw new UsageError(
      `cookie name(s) not declared by this profile: ${undeclared.join(', ')}`,
      'declare them with: fpx profile declare <name> --cookie <key> (forces a re-pair)',
    );
  }
  requireStorageDomain(profile, cmd.storageDomain);

  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    const written = await server.writeCookies({
      cookies: cmd.cookies,
      domain: cmd.storageDomain,
      subdomain: cmd.storageSubdomain,
    });
    // Echo what the BROWSER says it set, not what we asked for: a cookie the
    // page refused is the thing worth seeing.
    printJson(io, { written });
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
