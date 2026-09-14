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
     * The transport deadline every verb's reply wait is raced against.
     *
     * Nothing in the CLI sets it since #237: the capture verbs used to, to buy
     * a longer wait on one verb by lengthening all of them, and the server now
     * derives that per verb from the window the call asked for. Kept on the
     * factory's opts rather than on `DerivedServerOpts` because it is a
     * transport-level deadline and not something derived from the profile —
     * and kept at all so a caller with a genuinely slow bridge still has it.
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
 *
 * Case-INSENSITIVELY, because a host name is, and because the layer that
 * ENFORCES this rule says so: the server's `assertUrlInDomains` lowercases the
 * URL's hostname AND each declared domain before comparing. Compared raw, a
 * profile declaring `Example.com` refused `https://example.com/x` here while
 * the bridge would have accepted it one hop later — the same class of
 * divergence as the port one below, with the same resolution: the protocol's
 * rule binds and this pre-flight only reports it early. `capture-redirect`'s
 * bare host is the argument that can arrive cased in either direction, since
 * `new URL()` has already lowercased a hostname for `assertUrlOnProfile`.
 *
 * The DECLARED spelling comes back, never a normalised copy: the return is
 * threaded to `request()` as `{ domain }`, which the server resolves with an
 * exact `domains.includes(domain)` against the very array the profile
 * supplied.
 */
export function assertHostOnProfile(host: string, profile: Profile): string {
  const needle = host.toLowerCase();
  const matched = profile.domains.find((d) => {
    const declared = d.toLowerCase();
    return needle === declared || needle.endsWith(`.${declared}`);
  });
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

// `bridgeDeadlineFor` lived here until #237.
// It computed `max(timeoutMs + 15_000, 30_000)` and handed it to the server as
// `fetchTimeoutMs`, because a per-call `timeoutMs` could not raise the
// transport deadline it was raced against — so `--capture-timeout` was inert
// above 30s and the server's own timeout said to raise the transport instead.
// The server computes that now, per verb, from the window the call asked for
// (`verbDeadlineMs`). Keeping a copy here would mean two answers to one
// question, and this one lengthened EVERY verb on the transport to buy a
// longer wait on one — the coupling #237 exists to remove. The same shape was
// hand-rolled in resy-mcp, @chrischall/mcp-utils and onehome-mcp; it belongs
// in the library, and this is the deletion that says so.

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
