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
    opts?: { headers?: Record<string, string>; body?: string; domain?: string },
  ): Promise<{ status: number; body: string; url: string }>;
  readCookies(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<string>;
  readLocalStorage(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<Record<string, string>>;
  readSessionStorage(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<Record<string, string>>;
  readIndexedDb(o: {
    database: string; store: string; keys: string[]; domain?: string; subdomain?: string;
  }): Promise<Record<string, unknown>>;
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

export function assertUrlOnProfile(url: string, profile: Profile): void {
  let host: string;
  try {
    host = new URL(url).host;
  } catch {
    throw new UsageError(`not a valid URL: ${JSON.stringify(url)}`);
  }
  const ok = profile.domains.some((d) => host === d || host.endsWith(`.${d}`));
  if (!ok) {
    throw new UsageError(
      `${host} is not on this profile's declared domains (${profile.domains.join(', ')})`,
      'add a domain with: fpx profile add <name> --domain … (new profile) or edit profiles.json',
    );
  }
}

export async function runFetch(
  cmd: Extract<Command, { kind: 'fetch' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  assertUrlOnProfile(cmd.url, profile);
  const server = makeServer({
    ...serverOptsFor(cmd.profile, profile, VERSION),
    onPairCode: pairCodePrinter(io),
  });
  try {
    await server.listen();
    const res = await server.request(cmd.method, cmd.url, {
      headers: Object.keys(cmd.headers).length ? cmd.headers : undefined,
      body: cmd.body,
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
