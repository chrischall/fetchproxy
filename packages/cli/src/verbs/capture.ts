import type { Command } from '../args.js';
import type { CaptureHeaderDecl } from '@fetchproxy/protocol';

import type { Profile } from '../profiles.js';
import { serverOptsFor } from '../server-opts.js';
import { EXIT, UsageError, printJson, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { defaultServerFactory, pairCodePrinter, type VerbServerFactory } from './fetch.js';
import { VERSION } from '../version.js';

/**
 * `header@host[/path]` — byte for byte how the declaration is written on the
 * command line, and how it is keyed in output.
 *
 * The PATH is part of the key, not decoration. `--capture-header` accepts a
 * path, so a profile may legitimately declare the same header on the same host
 * twice with different paths — and keying on `header@host` alone collapsed
 * them, so the second result overwrote the first and one capture vanished from
 * the JSON with nothing to say it had.
 */
export const captureKey = (d: CaptureHeaderDecl): string =>
  `${d.headerName}@${d.host}${d.path ?? ''}`;

function narrowCaptures(requested: string[], declared: CaptureHeaderDecl[]): CaptureHeaderDecl[] {
  if (declared.length === 0) {
    throw new UsageError(
      'profile declares no capture headers — declare one first: ' +
        'fpx profile declare <name> --capture-header <header>@<host>[/path]',
    );
  }
  if (requested.length === 0) return declared;
  // Three spellings accepted, narrowest to broadest: the full key, the
  // `header@host` pair, or the bare header name. Typing the path is noise when
  // nothing is ambiguous, and a broader spelling selecting SEVERAL declarations
  // is the useful behaviour rather than an error — that is what asking for a
  // header on a host means.
  const spellings = (d: CaptureHeaderDecl): string[] => [
    captureKey(d),
    `${d.headerName}@${d.host}`,
    d.headerName,
  ];
  const picked = declared.filter((d) => spellings(d).some((sp) => requested.includes(sp)));
  const matched = new Set(picked.flatMap(spellings));
  const unknown = requested.filter((r) => !matched.has(r));
  if (unknown.length > 0) {
    throw new UsageError(
      `not in the profile's declared capture headers: ${unknown.join(', ')} — ` +
        'declared: ' + declared.map(captureKey).join(', '),
    );
  }
  return picked;
}

/**
 * `fpx capture` — snapshot a header off a request the PAGE makes.
 *
 * The CLI could already DECLARE `--capture-header`, which derives the
 * `capture_request_header` capability and puts it in the pair prompt, and then
 * had no way to use it: the user approved a scope nothing could exercise.
 * Diagnosing chrischall/fetchproxy#324 needed exactly this verb and had to be
 * done with a throwaway script instead, which is how the gap surfaced.
 *
 * All requested headers are captured CONCURRENTLY on purpose. A capture
 * resolves on the NEXT matching request, so one window serves every
 * declaration — asking for them in sequence would wait for a separate page
 * request per header and usually time out on all but the first.
 *
 * A header that does not arrive is reported as `null` rather than failing the
 * command, because a partial answer is the useful one: knowing WHICH of three
 * headers the page sends is the point of asking for three.
 */
export async function runCapture(
  cmd: Extract<Command, { kind: 'capture' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  // Narrow before connecting: a usage error must not cost a round trip, and
  // must not trigger pairing.
  const decls = narrowCaptures(cmd.names, profile.captureHeaders);

  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    const settled = await Promise.allSettled(
      decls.map((d) =>
        server.captureRequestHeader({
          headerName: d.headerName,
          host: d.host,
          ...(d.path !== undefined ? { path: d.path } : {}),
          ...(cmd.timeoutMs !== undefined ? { timeoutMs: cmd.timeoutMs } : {}),
        }),
      ),
    );
    const out: Record<string, string | null> = {};
    settled.forEach((r, i) => {
      out[captureKey(decls[i]!)] =
        r.status === 'fulfilled' && typeof r.value === 'string' && r.value.length > 0
          ? r.value
          : null;
    });
    printJson(io, out);
    // Nothing captured at all is a failure worth an exit code — it is the
    // idle-tab case, and a script should be able to tell it from a hit.
    return Object.values(out).some((v) => v !== null) ? EXIT.OK : EXIT.BRIDGE;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
