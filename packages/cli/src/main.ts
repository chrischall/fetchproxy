import { rmSync } from 'node:fs';
import type { bootstrap } from '@fetchproxy/bootstrap';
import { parseCliArgs } from './args.js';
import {
  cliHome, emptyProfile, getProfile, identityPath, loadProfiles, saveProfiles,
} from './profiles.js';
import { EXIT, UsageError, printJson, type Io } from './output.js';
import { runFetch, type VerbServerFactory } from './verbs/fetch.js';
import { runRead } from './verbs/read.js';
import { runSession } from './verbs/session.js';
import { runDom } from './verbs/dom.js';
import { runDownload } from './verbs/download.js';
import { runHealth, runPair } from './verbs/health.js';
import { runTrust } from './verbs/trust.js';
import { VERSION } from './version.js';

const USAGE = `fpx ${VERSION} — fetchproxy CLI: authenticated fetches through your signed-in browser tab

  fpx profile add <name> --domain <apex> [--domain <apex>]…
  fpx profile declare <name> [--cookie k]… [--local-storage k]… [--session-storage k]… [--capture-header name@host[/path]]… [--dom-selector handle=css]… [--allow-download] [--allow-cookie-write]
  fpx profile list | show <name> | remove <name>
  fpx pair -p <name> [--domain <apex>] [--subdomain <label>]
  fpx health -p <name>
  fpx trust list | clear <server-name> | clear --all
  fpx get <url> -p <name> [--json] [-H 'K: V']… [--via-tab <url>]
  fpx post-json <url> <body|@file> -p <name> [--json] [-H …]… [--via-tab <url>]
  fpx request <url> -p <name> [-X METHOD] [-H …]… [-d body|@file] [--json] [--via-tab <url>]
  fpx cookies|local-storage|session-storage|indexeddb [keys…] -p <name> [--storage-domain d] [--storage-subdomain s]
  fpx session -p <name> [--storage-domain d] [--storage-subdomain s]
  fpx dom <name…> -p <name> [--storage-domain d] [--storage-subdomain s]
  fpx download <url> -p <name> [--filename f]

--via-tab picks which open tab relays the request. Default: a tab on the
request's own host. Needed for API hosts that serve no page — e.g. fetch
api.example.com through --via-tab https://www.example.com/. Must be on a
declared domain.

Data on stdout, everything else on stderr.
Exit codes: 0 ok · 1 usage · 2 bridge unavailable · 3 bot wall · 4 upstream HTTP error`;

export interface CliDeps {
  home?: string;
  identityDir?: string;
  makeServer?: VerbServerFactory;
  bootstrapFn?: typeof bootstrap;
  readFile?: (p: string) => string;
}

const uniqMerge = (base: string[], extra: string[]): string[] => [...new Set([...base, ...extra])];

export async function runCli(argv: string[], io: Io, deps: CliDeps = {}): Promise<number> {
  const home = deps.home ?? cliHome();
  try {
    const cmd = parseCliArgs(argv, deps.readFile);
    switch (cmd.kind) {
      case 'help':
        io.err(USAGE);
        return EXIT.OK;
      case 'version':
        io.out(VERSION);
        return EXIT.OK;
      case 'profile-list': {
        const all = loadProfiles(home);
        for (const [name, p] of Object.entries(all).sort(([a], [b]) => a.localeCompare(b))) {
          io.out(`${name}\t${p.domains.join(',')}`);
        }
        return EXIT.OK;
      }
      case 'profile-show':
        printJson(io, getProfile(cmd.name, home));
        return EXIT.OK;
      case 'profile-add': {
        const all = loadProfiles(home);
        if (all[cmd.name]) {
          throw new UsageError(`profile "${cmd.name}" already exists`,
            `edit its scope with: fpx profile declare ${cmd.name} …`);
        }
        all[cmd.name] = emptyProfile(cmd.domains);
        saveProfiles(all, home);
        io.err(`profile "${cmd.name}" created (${cmd.domains.join(', ')}) — first use will show a pair code`);
        return EXIT.OK;
      }
      case 'profile-declare': {
        const all = loadProfiles(home);
        const p = all[cmd.name];
        if (!p) return runCliUnknownProfile(cmd.name, home);
        p.cookies = uniqMerge(p.cookies, cmd.cookies);
        p.localStorage = uniqMerge(p.localStorage, cmd.localStorage);
        p.sessionStorage = uniqMerge(p.sessionStorage, cmd.sessionStorage);
        for (const decl of cmd.captureHeaders) {
          if (!p.captureHeaders.some((d) => d.headerName === decl.headerName && d.host === decl.host && d.path === decl.path)) {
            p.captureHeaders.push(decl);
          }
        }
        for (const decl of cmd.domSelectors) {
          const existing = p.domSelectors.find((d) => d.name === decl.name);
          if (existing) Object.assign(existing, decl);
          else p.domSelectors.push(decl);
        }
        if (cmd.download) p.download = true;
        if (cmd.cookieWrite) p.cookieWrite = true;
        saveProfiles(all, home);
        io.err(`profile "${cmd.name}" scope updated — the next connect will ask you to re-pair (scope diff)`);
        return EXIT.OK;
      }
      case 'profile-remove': {
        const all = loadProfiles(home);
        if (!all[cmd.name]) return runCliUnknownProfile(cmd.name, home);
        delete all[cmd.name];
        saveProfiles(all, home);
        rmSync(identityPath(cmd.name, deps.identityDir), { force: true });
        io.err(`profile "${cmd.name}" removed — also revoke fpx-${cmd.name} in the Transporter extension popup`);
        return EXIT.OK;
      }
      case 'fetch':
        return await runFetch(cmd, getProfile(cmd.profile, home), io, deps.makeServer);
      case 'read':
        return await runRead(cmd, getProfile(cmd.profile, home), io, deps.makeServer);
      case 'session':
        return await runSession(cmd, getProfile(cmd.profile, home), io, deps.bootstrapFn);
      case 'dom':
        return await runDom(cmd, getProfile(cmd.profile, home), io, deps.makeServer);
      case 'download':
        return await runDownload(cmd, getProfile(cmd.profile, home), io, deps.makeServer);
      case 'health':
        return await runHealth(cmd, getProfile(cmd.profile, home), io, deps.makeServer);
      case 'trust':
        return await runTrust(cmd, io, deps.identityDir);
      case 'pair':
        return await runPair(cmd, getProfile(cmd.profile, home), io, deps.makeServer);
    }
  } catch (err) {
    if (err instanceof UsageError) {
      io.err(`fpx: ${err.message}`);
      if (err.hint) io.err(`  hint: ${err.hint}`);
      return EXIT.USAGE;
    }
    io.err(`fpx: unexpected error: ${err instanceof Error ? err.message : String(err)}`);
    return EXIT.BRIDGE;
  }
}

function runCliUnknownProfile(name: string, home: string): never {
  getProfile(name, home); // always throws the canonical UsageError
  throw new Error('unreachable');
}
