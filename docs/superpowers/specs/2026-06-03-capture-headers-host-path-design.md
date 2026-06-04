# captureHeaders config: `{ host, path?, headerName }`

**Date:** 2026-06-03
**Packages:** `@fetchproxy/protocol`, `@fetchproxy/server`, `@fetchproxy/extension-core` (+ consumer `musescore-mcp`)
**Status:** approved (design), pending implementation
**Supersedes:** fetchproxy PR #102 (construct-time captureHeaders validation against the old `urlPattern` shape) — close unmerged; its intent is absorbed and improved here.

## Problem

`CaptureHeaderDecl` is `{ urlPattern: string; headerName: string }`, where `urlPattern`
must be a full Chrome match pattern (`https://host/path`). This is a footgun: an
MCP author naturally writes the bare host (`'musescore.com'`), which the protocol
validator rejects — `validateFrame` throws on the hello, the bridge host closes
the connection (`"peer WS closed before ready"`), and the bridge silently dies.
musescore-mcp shipped exactly this bug. The MCP already declares its `domains`,
so the host portion of the pattern is redundant *and* unchecked against that list.

## Goal

Replace the free-form match pattern with structured `{ host, path?, headerName }`,
and validate `host` against the MCP's declared `domains` at construction. The
common case (capture a header on any request to a declared host) becomes
`{ host, headerName }`. Misconfiguration fails loud at boot, not silently at runtime.

## Design

### 1. Wire shape (clean break — no working consumers)

`@fetchproxy/protocol` `frames.ts`:

```ts
interface CaptureHeaderDecl {
  host: string;        // a declared domain, or a subdomain of one
  path?: string;       // optional; omitted ⇒ '/*'. Must start with '/'.
  headerName: string;
}
```

The capture-time inner request (`op: 'capture_request_header'` init) and the
server's `captureRequestHeader({ host, path?, headerName, timeoutMs? })` change to
match. `urlPattern` is removed everywhere (no migration — capture has no working
consumers; the lockstep version bump carries the breaking change).

### 2. Validation — one shared validator, two call sites

New protocol export `validateCaptureHeaderDecls(value, domains)`:
- structural: array of `{ host, path?, headerName }`, no extra keys, no dupes
  (dup key = `host\x00normalizedPath\x00headerName`);
- `host` matches `HOSTNAME_RE`;
- `host` equals a declared `domain` **or is a subdomain of one** (reuse the
  host-or-subdomain rule already used for tab/fetch matching);
- `path`, if present, starts with `/` and is charset-clean (path + optional
  trailing `*`); omitted normalizes to `/*`;
- `headerName` matches `HEADER_NAME_RE`.

Call sites:
- **`FetchproxyServer` constructor** — `validateCaptureHeaderDecls(opts.captureHeaders, opts.domains)`,
  wrapped to throw `FetchproxyServer: invalid captureHeaders — <reason>` (same
  fail-loud philosophy as the existing `domains` / `capabilities` guards).
- **`validateFrame` → `validateHello`** — cross-check each `captureHeaders.host`
  against `hello.domains`, so the bridge host also rejects a peer whose capture
  host escapes its declared domains (defense-in-depth).

The old `assertCaptureUrlPattern` (the `https://`-prefix check) is removed.

### 3. Extension (`extension-core`)

- `handleCaptureRequestHeaderRequest`: build the `webRequest` filter as
  `https://${host}${path ?? '/*'}`; match the request against a declared entry by
  `(host, normalizedPath, headerName)`. The existing host∈domains check stays
  (host is now read directly).
- `scope.ts` `normCaptureHeader`: key on `host\x00normalizedPath\x00headerName`
  (omitted path normalized to `/*`, so `{host,header}` ≡ `{host,'/*',header}`).
  `scopeHash` / `intersectScope` / `isScopeSubset` follow.
- `declaredScope` / `handleServerHello`: carry the new shape.
- popup: render `host` + `path` + header instead of the raw pattern.

### 4. Consumer — musescore-mcp

```ts
captureHeaders: [
  { host: 'musescore.com', headerName: 'cookie' },
  { host: 'musescore.com', headerName: 'user-agent' },
]
```
`captureSessionHeaders()` → `captureRequestHeader({ host: 'musescore.com', headerName: 'cookie' })`,
`{ host: 'musescore.com', headerName: 'user-agent' }`. `musescore.com` is already
in `domains`, so it validates. (Done in a follow-up musescore PR once the
fetchproxy bump is published.)

## Non-goals

- Back-compat for the old `urlPattern` shape (clean break; no live consumers).
- Per-method / per-query-param capture scoping (host + path is enough).

## Testing (TDD)

- **protocol** `validate.test.ts`: `validateCaptureHeaderDecls` accepts
  `{host,header}` and `{host,path,header}` with host∈domains (exact + subdomain);
  rejects host∉domains, invalid host, path without leading `/`, bad headerName,
  duplicate entries, unexpected fields. `validateFrame` rejects a hello whose
  captureHeaders host escapes its domains.
- **server** `ws-server.test.ts`: constructor throws on host∉domains / malformed;
  accepts valid `{host,header}` and subdomain host; `captureRequestHeader` forwards
  the `{host,path?,headerName}` init.
- **extension-core**: capture op builds the right filter from host+path (default
  `/*`); declared-match by `(host,path,header)`; `scope.ts` key/hash/intersect on
  the new shape; equivalence of omitted-path and `/*`.
- **musescore** `transport-fetchproxy.test.ts`: declares `{host,header}`; the
  declared scope passes the real `validateFrame`; capture calls match a declared
  entry. (musescore PR.)

All mocked / in-memory per repo convention.
