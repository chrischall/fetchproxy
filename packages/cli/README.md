# @fetchproxy/cli

> `fpx` — a one-shot CLI for the [fetchproxy](https://github.com/chrischall/fetchproxy) bridge: authenticated fetches and session reads through the user's signed-in browser tab, straight from a shell prompt or a skill.

`@fetchproxy/server` and `@fetchproxy/bootstrap` are libraries an MCP server embeds. `fpx` is the same bridge wrapped as a standalone binary — no Node process to write, no MCP server to run. Point it at a URL, get the response on stdout; point it at a storage bucket, get JSON back. Useful anywhere a skill or shell script needs one authenticated request and doesn't want to carry a whole MCP.

## Install

```sh
npm install -g @fetchproxy/cli
```

Or run it without installing:

```sh
npx @fetchproxy/cli profile list
```

Either way, the user also needs the fetchproxy browser extension (**Transporter**) installed — see the [top-level README](https://github.com/chrischall/fetchproxy#install).

## The profile model

`fpx` scopes every command to a named **profile** — a small JSON record describing one service: its declared domains, and (optionally) the cookie keys, storage keys, capture-headers, and IndexedDB scopes it's allowed to read. Profiles live at `$FETCHPROXY_CLI_HOME/profiles.json`, or `~/.fetchproxy/cli/profiles.json` if that variable is unset.

```sh
fpx profile add opentable --domain opentable.com
fpx profile list
# opentable    opentable.com
```

### Per-service identity

Each profile gets its own long-term identity, keyed by name: profile `opentable` connects to the bridge as `fpx-opentable`, with its identity keypair persisted at `~/.fetchproxy/identity/fpx-opentable.json`. This mirrors how a real `opentable-mcp` would identify itself — the extension's trust store, pair history, and capability grants are all keyed off that per-service identity, not off `fpx` itself. Running `fpx` against ten services looks, from the extension's point of view, like ten independent MCPs.

### Pair-code flow

The first time any verb connects under a given profile, the extension doesn't auto-trust it. `fpx` prints a 6-digit pair code to stderr:

```
$ fpx health -p opentable
fetchproxy pair code: 482-913 — approve in the Transporter extension popup
```

Open the Transporter popup, confirm the code matches, click Approve. Every subsequent command against that profile — from any verb — reuses the same trust record and skips the prompt.

### Re-pair on scope change

`fpx profile declare` widens a profile's scope (more cookie keys, a new capture-header, etc.). Because the extension's trust is keyed to `(identity, domains, capabilities)`, widening the scope changes the hello the next connection sends, and the extension treats that as a diff worth re-confirming:

```sh
fpx profile declare opentable --cookie oaid --capture-header x-csrf-token@www.opentable.com
# profile "opentable" scope updated — the next connect will ask you to re-pair (scope diff)
```

The next command against `opentable` prints a fresh pair code even though the identity is unchanged.

### Revocation

`fpx profile remove <name>` deletes the local profile entry and its identity file:

```sh
fpx profile remove opentable
# profile "opentable" removed — also revoke fpx-opentable in the Transporter extension popup
```

That only cleans up the CLI's side. The extension still holds a trust row for `fpx-opentable` until the user opens the Transporter popup and revokes it there — removing the profile does not reach into the browser.

## Verbs

Every verb takes `-p`/`--profile <name>` (except the `profile` subcommands themselves, which take the name as a positional).

| Command | What it does | Example |
|---|---|---|
| `fpx profile add <name> --domain <apex>…` | Create a profile with one or more declared domains. | `fpx profile add opentable --domain opentable.com` |
| `fpx profile declare <name> [--cookie k]… [--local-storage k]… [--session-storage k]… [--capture-header name@host[/path]]…` | Widen a profile's scope. Merges with the existing declaration; forces a re-pair. | `fpx profile declare opentable --cookie oaid` |
| `fpx profile list` | List all profiles and their domains (tab-separated, one per line). | `fpx profile list` |
| `fpx profile show <name>` | Print a profile's full JSON record. | `fpx profile show opentable` |
| `fpx profile remove <name>` | Delete the profile and its identity file. | `fpx profile remove opentable` |
| `fpx pair -p <name> [--domain <apex>]` | Force a pairing round-trip against one declared domain (defaults to the only one, if there's exactly one). | `fpx pair -p opentable` |
| `fpx health -p <name>` | Print the bridge's health snapshot (host/peer role, connection state). | `fpx health -p opentable` |
| `fpx get <url> -p <name> [--json] [-H 'K: V']…` | GET a URL through the profile's tab. | `fpx get https://www.opentable.com/ -p opentable` |
| `fpx post-json <url> <body\|@file> -p <name> [--json] [-H 'K: V']…` | POST a JSON body (literal or `@file`); sets `Content-Type: application/json` unless overridden. | `fpx post-json https://www.opentable.com/dapi/fe/gql '{"operationName":"Autocomplete"}' -p opentable` |
| `fpx request <url> -p <name> [-X METHOD] [-H 'K: V']… [-d body\|@file] [--json]` | Arbitrary method/headers/body. | `fpx request https://www.opentable.com/x -p opentable -X DELETE` |
| `fpx cookies [keys…] -p <name>` | Read declared cookies (all declared keys if none given). | `fpx cookies -p opentable` |
| `fpx local-storage [keys…] -p <name>` | Read declared `localStorage` keys. | `fpx local-storage authToken -p opentable` |
| `fpx session-storage [keys…] -p <name>` | Read declared `sessionStorage` keys. | `fpx session-storage csrfToken -p opentable` |
| `fpx indexeddb -p <name>` | Read all declared IndexedDB scopes (no key arguments — scopes come from the profile). | `fpx indexeddb -p opentable` |
| `fpx session -p <name> [--storage-domain d] [--storage-subdomain s]` | Bootstrap-parity one-shot: pair (if needed), read every declared bucket, close, print the combined session JSON. | `fpx session -p opentable` |

`--storage-domain` / `--storage-subdomain` (on the storage-read verbs and `session`) select which declared domain to read from when a profile declares more than one — required only in that case, same as the underlying library.

## Output contract

- **stdout carries data only** — response bodies, `--json` envelopes, storage-read JSON, `profile list`/`profile show` output.
- **Everything else goes to stderr** — pair codes, status lines (`profile "x" created …`, `paired ✓ …`), hints, and error messages.

This split means `fpx get … | jq .` or `fpx cookies -p x > cookies.json` never picks up incidental noise.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Usage error — bad flags, unknown command, unknown profile, undeclared scope, malformed body. |
| `2` | Bridge unavailable — extension not connected, pairing still pending, or an unexpected bridge-level failure. |
| `3` | Bot wall detected in the response (Akamai/Cloudflare-style interstitial). |
| `4` | Upstream HTTP error — the request reached the site but got a non-2xx response. |

Exit codes 3 and 4 are emitted only by the fetch verbs (`get`, `post-json`, `request`); the `pair`, `health`, `session`, and read verbs (`cookies`/`local-storage`/`session-storage`/`indexeddb`) return 0 on a successful bridge round-trip regardless of upstream status.

## `FETCHPROXY_CLI_HOME`

Profiles are stored at `$FETCHPROXY_CLI_HOME/profiles.json` if that environment variable is set, otherwise at `~/.fetchproxy/cli/profiles.json`. Set it to isolate `fpx` state per-shell, per-CI-job, or for a smoke test:

```sh
FETCHPROXY_CLI_HOME=$(mktemp -d) fpx profile add scratch --domain example.com
```

Per-service identity files are unaffected by this variable — they always live at `~/.fetchproxy/identity/fpx-<name>.json`.

## Capability parity

Every verb — `get`, `post-json`, `request`, `cookies`, `local-storage`, `session-storage`, `indexeddb`, `session`, even `health` and `pair` — derives its hello frame from the *full* profile record via the same `serverOptsFor()` helper, not just the fields that particular verb happens to touch. That's deliberate: the extension's trust is keyed to `(identity, domains, capabilities)`, so if `fpx get` sent a narrower hello than `fpx cookies`, alternating between the two verbs on the same profile would look like a capability change and force a re-pair every time. Sending the same hello for every verb means you can freely interleave `fpx get`, `fpx cookies`, `fpx session`, etc. against one profile and only ever pair once — a re-pair only happens when `fpx profile declare` actually changes the stored scope.

## Skills

`fpx` is designed to be the thing a skill shells out to when it needs one authenticated read, without embedding a bridge client. A typical pattern:

```sh
# One-time setup (pairs interactively):
fpx profile add opentable --domain opentable.com
fpx pair -p opentable

# From then on, any skill script can do:
fpx get -p opentable 'https://www.opentable.com/dapi/fe/gql?...' --json | jq .body
```

Or, scoped to a declared cookie for a lightweight auth check:

```sh
fpx cookies oaid -p opentable | jq -r .oaid
```

Because pairing is per-profile and persists across invocations, a skill can call `fpx` repeatedly across a session — once per tool call, even — without re-triggering the pair prompt after the first approval.
