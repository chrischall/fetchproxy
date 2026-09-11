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
      inPage?: boolean;
      credentials?: 'include' | 'omit';
    },
  ): Promise<{ status: number; body: string; url: string }>;
  readCookies(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<string>;
  readLocalStorage(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<Record<string, string>>;
  readSessionStorage(o: { keys: string[]; domain?: string; subdomain?: string }): Promise<Record<string, string>>;
  readIndexedDb(o: {
    database: string; store: string; keys: string[]; domain?: string; subdomain?: string;
  }): Promise<Record<string, unknown>>;
  captureRequestHeader(o: {
    headerName: string; host: string; path?: string; timeoutMs?: number;
  }): Promise<string>;
  captureRedirect(o: { host: string; path?: string; timeoutMs?: number }): Promise<string>;
  graphqlQuery(o: {
    name: string; variables: Record<string, unknown>; tabUrl?: string;
  }): Promise<unknown>;
  writeCookies(o: {
    cookies: Record<string, string>; domain?: string; subdomain?: string; path?: string;
  }): Promise<string[]>;
  readDom(o: { names: string[]; domain?: string; subdomain?: string }): Promise<Record<string, string>>;
  download(o: { url: string; filename?: string }): Promise<{
    path: string; bytes: number; mime?: string; finalUrl?: string;
  }>;
  bridgeHealth(): unknown;
}

export type VerbServerFactory = (
  opts: DerivedServerOpts & {
    onPairCode: (code: string) => void;
    /**
     * The transport deadline every verb's reply wait is raced against. Only
     * the capture verbs set it — see `bridgeDeadlineFor`, which is the whole
     * reason this field is on the factory's opts rather than on
     * `DerivedServerOpts`: it is a per-CALL deadline, not something derived
     * from the profile.
     */
    fetchTimeoutMs?: number;
  },
) => VerbServer;

export const defaultServerFactory: VerbServerFactory = (opts) =>
  new FetchproxyServer(opts) as unknown as VerbServer;

export function pairCodePrinter(io: Io): (code: string) => void {
  return (code) =>
    io.err(`fetchproxy pair code: ${code} — approve in the Transporter extension popup`);
}

/**
 * Assert a HOST is on one of the profile's declared domains and return the
 * matching declared apex.
 *
 * Shared with `capture-redirect`, whose target is a bare host rather than a
 * URL: that verb re-implemented this rule inline and copied this error text,
 * so the two spellings of "not on this profile" could drift apart with nothing
 * to catch it.
 */
export function assertHostOnProfile(host: string, profile: Profile): string {
  const matched = profile.domains.find((d) => host === d || host.endsWith(`.${d}`));
  if (matched === undefined) {
    throw new UsageError(
      `${host} is not on this profile's declared domains (${profile.domains.join(', ')})`,
      'add a domain with: fpx profile add <name> --domain … (new profile) or edit profiles.json',
    );
  }
  return matched;
}

/**
 * The same rule for a URL, returning the matching declared apex.
 *
 * `runFetch` threads that apex to `request()` as `{ domain }`: the server calls
 * `resolveBaseDomain(opts.domain)` eagerly (even for absolute URLs) and throws
 * when a profile declares >1 domain and none is passed, so a multi-domain
 * profile needs the resolved domain on every call.
 *
 * `hostname`, never `host`: `host` carries the port, and both layers that
 * actually ENFORCE this rule compare the port-less name — the server's
 * `assertUrlInDomains` and the extension's `isUrlAllowedForDomain`. On `host`,
 * a profile declaring `example.com` refused `https://example.com:8443/x` here
 * and the bridge accepted it one hop later, so the pre-flight refusal
 * contradicted the rule it exists to report early.
 */
export function assertUrlOnProfile(url: string, profile: Profile): string {
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    throw new UsageError(`not a valid URL: ${JSON.stringify(url)}`);
  }
  return assertHostOnProfile(host, profile);
}

/**
 * The transport deadline a capture window needs.
 *
 * `FetchproxyServer.fetchTimeoutMs` (default 30_000) bounds EVERY verb's reply
 * wait, and a per-call `timeoutMs` cannot raise it — the server says so in the
 * timeout it throws: "A per-call timeoutMs cannot exceed it; raise
 * fetchTimeoutMs on the transport to wait longer." The CLI set it nowhere, so
 * `--capture-timeout` was inert above 30s: `_withVerbTimeout` fired at the
 * default whatever the call asked for.
 *
 * The margin exists so the PER-CALL timer is the one that fires. That way the
 * user is told the header never arrived in the window they asked for, rather
 * than reading a transport timeout about a number they never typed. Same
 * reasoning as resy-mcp's `BRIDGE_DEADLINE_MS`, and the same shape.
 */
export function bridgeDeadlineFor(timeoutMs: number | undefined): number {
  return Math.max((timeoutMs ?? 0) + 15_000, 30_000);
}

export async function runFetch(
  cmd: Extract<Command, { kind: 'fetch' }>,
  profile: Profile,
  io: Io,
  makeServer: VerbServerFactory = defaultServerFactory,
): Promise<number> {
  const domain = assertUrlOnProfile(cmd.url, profile);
  // Same reasoning as the relay-tab check below: the extension refuses an
  // undeclared capability, but that refusal arrives after the bridge is up and
  // reads as a bridge error rather than the usage error it is. Worse here,
  // because the whole point of --in-page is diagnosing a failure, and a
  // misleading failure is what #324 already cost two rounds to.
  if (cmd.inPage && profile.inPage !== true) {
    throw new UsageError(
      "--in-page needs a profile that declares it: this one does not",
      'declare it with: fpx profile declare <name> --allow-in-page … ' +
        '(re-pair once, since trust is keyed to the capability set)',
    );
  }
  // Check the relay tab the same way and at the same time as the request URL.
  // The server guards it too, but that guard only fires after the bridge is
  // up, turning a typo into exit 2 ("bridge error") when it is plainly a usage
  // error — and making the user wait on a connection to be told so (#209).
  if (cmd.viaTab !== undefined) assertUrlOnProfile(cmd.viaTab, profile);
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
      // Spread rather than a bare `inPage: cmd.inPage`, matching the server's
      // own call site: the wire validator treats a present `false` differently
      // from an absent field.
      ...(cmd.inPage ? { inPage: true } : {}),
      ...(cmd.noCredentials ? { credentials: 'omit' as const } : {}),
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
