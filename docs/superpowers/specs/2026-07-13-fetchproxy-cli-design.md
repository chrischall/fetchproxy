# `@fetchproxy/cli` (`fpx`) — design

_2026-07-13. Approved in brainstorming; implementation plan to follow._

## Motivation

Skills (SKILL.md + shell recipes) are becoming the lightweight tier for
web-service integrations that don't earn a full MCP repo. Today only MCPs can
reach the fetchproxy bridge, because `@fetchproxy/server` is a library with no
CLI. `fpx` closes that gap: a one-shot command-line client for the bridge, so
a skill can `fpx -p opentable get https://www.opentable.com/...` through the
user's signed-in tab. It also reaches bootstrap parity (cookie/storage/header
reads), so Pattern-A-style session capture works from a shell too.

## Decisions (made during brainstorming)

1. **Trust model: per-service profiles.** Each profile gets its own identity
   (`fpx-<profile>`) with its own pinned domain list — one pairing approval
   per service, per-service revocation, and the extension popup shows
   `fpx-tripadvisor: tripadvisor.com`, never a grab-bag grant. Rejected: a
   single accumulating `fpx-cli` identity (broad grant, all-or-nothing
   revocation) and ephemeral per-domain identities (pair-prompt spam).
2. **Verb surface: full bootstrap parity, scoped by declarations.** Fetch
   verbs plus cookie/localStorage/sessionStorage/IndexedDB/header-capture
   reads. Parity lives in the *profile declarations*: a fetch-only profile
   declares no read scopes and gets a minimal consent screen; only profiles
   that declare storage scopes pay the broader grant.
3. **Packaging: new monorepo workspace** `packages/cli`, published as
   `@fetchproxy/cli` (bin `fpx`), on the lockstep release-please version train
   and the existing OIDC publish job. Rejected: a bin inside
   `@fetchproxy/bootstrap` (breaks that package's Pattern-A-only boundary) and
   a standalone fleet repo (repo #40, loses lockstep with protocol changes).

## Architecture

Thin command layer over the existing libraries — no new protocol surface, no
extension changes:

- `@fetchproxy/server` for live verbs (`fetch`/`request`, `bridgeHealth`,
  storage reads) and everything it already owns: host/peer election on port
  37149, identity persistence, session crypto, pairing.
- `@fetchproxy/bootstrap` for the `session` command (declare scope → read all
  buckets → emit one `Session` blob).
- `node:util.parseArgs` for argument parsing — zero new runtime deps.

Every invocation is one-shot, exactly like bootstrap: load profile →
`new FetchproxyServer({ serverName: 'fpx-<profile>', version, domains })` →
`listen()` → run one verb → close. Election means fpx coexists with any
running MCPs (joins as peer, or briefly hosts).

## Profiles

`~/.fetchproxy/cli/profiles.json` — dir 0700, file 0600 (same discipline as
identity files). Schema per profile mirrors bootstrap's `Declarations`:

```jsonc
{
  "tripadvisor": {
    "domains": ["tripadvisor.com"],
    "cookies": [],                  // cookie names to allow reading
    "localStorage": [],             // keys
    "sessionStorage": [],           // keys
    "captureHeaders": [],           // CaptureHeaderDecl[]
    "indexedDb": [],                // IndexedDbScopeDecl[]
    "localStoragePointers": [],     // JSON-pointer extractions
    "sessionStoragePointers": []
  }
}
```

**Capability parity (hard rule).** Extension trust is keyed to (identity,
domains, capabilities), so EVERY connect for a profile must send an identical
hello — otherwise alternating `fpx get` and `fpx session` would re-trigger
pairing each time. The CLI derives capabilities + scope keys from the profile
with exactly `bootstrap()`'s algorithm (same push order, same pointer-key
auto-add) for all direct-server verbs; the `session` verb goes through
`bootstrap()` itself and matches by construction. Key-subset *reads* narrow
per-call, never in the hello.

Identity lands at `~/.fetchproxy/identity/fpx-<profile>.json` via existing
server behavior. First use prints the SAS pair code to stderr and waits for
extension approval (bounded by a pair timeout). Editing a profile's domains or
scope triggers the extension's normal re-pair diff on next connect.

`FETCHPROXY_CLI_HOME` overrides the config dir (tests use a temp dir).

### Profile commands

```sh
fpx profile add tripadvisor --domain tripadvisor.com [--domain otherdomain.com]
fpx profile declare tripadvisor --cookie datadome --local-storage authToken \
    --capture-header 'x-csrf-token@https://www.tripadvisor.com/*'
fpx profile list | show <name> | remove <name>
fpx pair -p <profile> [--domain <apex>]   # connect + HEAD / probe through the tab: any HTTP
                                          # status proves pairing + a matching signed-in tab
```

`profile remove` deletes the profile entry and the identity file, and reminds
the user to revoke the trust row in the extension popup (the extension owns
its trust store; the CLI can't reach into it).

## Verbs

```sh
fpx -p <profile> get <url>
fpx -p <profile> post-json <url> @body.json
fpx -p <profile> request <url> -X PUT -H 'k: v' -d @file   # generic
fpx -p <profile> session                                    # bootstrap parity: all declared buckets → Session JSON
fpx -p <profile> cookies [names…]                           # subset reads of declared scope
fpx -p <profile> local-storage | session-storage | indexeddb [keys…]
fpx -p <profile> health                                     # bridgeHealth() diagnostics
```

- Fetch URLs must be on the profile's declared domains — the extension
  enforces this; the CLI pre-checks and gives a friendly error naming the
  profile and its domains.
- Multi-domain profiles: full URLs disambiguate fetch verbs on their own;
  storage reads require `--storage-domain` (mirrors `resolveBaseDomain`).
- Read verbs can only narrow the declared scope, never widen it; asking for
  an undeclared key is a usage error naming the declare command to run.
- Header captures have no standalone verb: capturing requires a matching
  request to fire in the tab, so declared `captureHeaders` are read via
  `session` (which waits the same way bootstrap does).

## Output contract

Data on stdout, everything else on stderr. Logging never touches stdout.

- Fetch verbs: response body → stdout. `--json` wraps `{status, url, body}` —
  the bridge protocol's `FetchResult` carries exactly those fields; response
  headers never cross the protocol, and `body` is always a UTF-8 string (the
  extension decodes it). Non-2xx: status line on stderr, body still on stdout.
- Read verbs / `session`: JSON on stdout.
- Exit codes: `0` = success (2xx for fetch verbs); `1` = usage error;
  `2` = bridge unavailable (extension not running, pairing declined/timed
  out, no matching tab — each mapped from `classifyBridgeError` /
  `FetchproxySessionNotReadyError` to an actionable message); `3` = bot wall
  detected (`classifyBotWall`); `4` = upstream HTTP error status.

## Testing

Vitest next to source in `packages/cli/tests/`, all mocked — `fpx` is exactly
the consumer `@fetchproxy/test-helpers` was built for:

- Pure units tested directly: arg → request mapping, profile schema
  validation/(de)serialization, output formatting, exit-code mapping.
- Verb flows against the mocked `FetchproxyServer` (constructor-opts capture
  asserts `serverName`/`domains` derivation from profiles).
- One spawn test runs the built bin (`--help`, `profile list`) against a temp
  `FETCHPROXY_CLI_HOME`. No live network in CI, per repo rule.

Live verification happens out of band, like the rest of the repo: pair a real
profile and run `fpx -p <profile> get` against a bot-walled site.

## Build & release

- `tsc -b` workspace added after server/bootstrap in the build order.
- release-please: add `packages/cli/package.json` to the lockstep
  `extra-files`; the publish job picks up any non-private package
  automatically. npm Trusted Publisher trust must be configured for
  `@fetchproxy/cli` on npmjs.com before the first release (manual, human
  step — same as the other packages).
- Root README gets a workspace-table row; `packages/cli/README.md` documents
  profiles, verbs, and the output contract.

## Out of scope (v1)

- Daemon / persistent mode (one-shot only; election makes this cheap).
- Response caching, retries beyond what `@fetchproxy/server` already does.
- Writing per-service skills that consume fpx (follow-up work, one SKILL.md
  per service).
- Safari/Firefox extension concerns; extension UI changes of any kind.
