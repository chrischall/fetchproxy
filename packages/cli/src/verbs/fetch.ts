import { classifyBotWall, FetchproxyServer } from '@fetchproxy/server';
import type { Command } from '../args.js';
import type { Profile } from '../profiles.js';
import { serverOptsFor, type DerivedServerOpts } from '../server-opts.js';
import { EXIT, UsageError, fetchEnvelope, type Io } from '../output.js';
import { mapBridgeError } from '../bridge-errors.js';
import { VERSION } from '../version.js';

/** The surface every fpx verb touches on FetchproxyServer (mock-friendly). */
export interface VerbServer {
  listen(): Promise<void>;
  close(): Promise<void>;
  request(
    method: string,
    path: string,
    opts?: {
      headers?: Record<string, string>; body?: string; domain?: string; viaTab?: string;
    },
  ): Promise<{ status: number; body: string; url: string }>;
  readCookies(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<string>;
  readLocalStorage(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<Record<string, string>>;
  readSessionStorage(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<Record<string, string>>;
  readIndexedDb(o: {
    database: string; store: string; keys: string[]; domain?: string; subdomain?: string;
  }): Promise<Record<string, unknown>>;
  readDom(o: { names: string[]; domain?: string; subdomain?: string }): Promise<Record<string, string>>;
  download(o: { url: string; filename?: string }): Promise<{
    path: string; bytes: number; mime?: string; finalUrl?: string;
  }>;
  bridgeHealth(): unknown;
}

export type VerbServerFactory = (
  opts: DerivedServerOpts & { onPairCode: (code: string) => void },
) => VerbServer;

export const defaultServerFactory: VerbServerFactory = (opts) =>
  new FetchproxyServer(opts) as unknown as VerbServer;

export function pairCodePrinter(io: Io): (code: string) => void {
  return (code) =>
    io.err(`fetchproxy pair code: ${code} — approve in the Transporter extension popup`);
}

/**
 * Assert the URL's host is on one of the profile's declared domains and return
 * the matching declared apex. `runFetch` threads that apex to `request()` as
 * `{ domain }`: the server calls `resolveBaseDomain(opts.domain)` eagerly (even
 * for absolute URLs) and throws when a profile declares >1 domain and none is
 * passed, so a multi-domain profile needs the resolved domain on every call.
 */
export function assertUrlOnProfile(url: string, profile: Profile): string {
  let host: string;
  try {
    host = new URL(url).host;
  } catch {
    throw new UsageError(`not a valid URL: ${JSON.stringify(url)}`);
  }
  const matched = profile.domains.find((d) => host === d || host.endsWith(`.${d}`));
  if (matched === undefined) {
    throw new UsageError(
      `${host} is not on this profile's declared domains (${profile.domains.join(', ')})`,
      'add a domain with: fpx profile add <name> --domain … (new profile) or edit profiles.json',
    );
  }
  return matched;
}

export async function runFetch(
  cmd: Extract<Command, { kind: 'fetch' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  const domain = assertUrlOnProfile(cmd.url, profile);
  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    const res = await server.request(cmd.method, cmd.url, {
      headers: Object.keys(cmd.headers).length ? cmd.headers : undefined,
      body: cmd.body,
      domain,
      viaTab: cmd.viaTab,
    });
    io.out(cmd.json ? fetchEnvelope(res) : res.body);
    const wall = classifyBotWall(res.body, res.status);
    if (wall.blocked) {
      io.err(`bot wall detected (${wall.vendor}) — open ${cmd.url} in Chrome, pass the check, retry.`);
      return EXIT.BOTWALL;
    }
    if (res.status < 200 || res.status >= 300) {
      io.err(`HTTP ${res.status} ${res.url}`);
      return EXIT.HTTP;
    }
    return EXIT.OK;
  } catch (err) {
    return mapBridgeError(err, io);
  } finally {
    await server.close().catch(() => {});
  }
}
