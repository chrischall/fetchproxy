# Reaching an API through the bridge

Four ways a request can leave the browser, and how to tell which one you need.
Written after `resy-mcp`'s token bootstrap failed three times in a row, each
time for a different reason, each with an error that named a symptom rather
than the cause.

The short version: **the tab that relays a request and the host the request
goes to are two different things, and neither of them is "the API host".**

## The options

| | what it does | when you need it | cost |
| --- | --- | --- | --- |
| plain `fetch` / `request()` | relays through a tab on the request's own host | the app and its API share a host | none |
| `viaTab` | names the relaying tab explicitly | the API host serves no app, so it never has a tab | none — it widens which tab relays, never which origins are reachable |
| `capture_request_header` | reads a header off a request the page already made | the credential is already on the page's own traffic | needs the capability approved; opportunistic — an idle tab yields nothing |
| `fetch_in_page` | issues the request from the page's MAIN world | the isolated world's request is refused where the page's is not | the page can see and alter that request (`docs/SECURITY.md` §T-in-page-fetch) |

## The ladder, by error

Work down. Each error is what you see *after* fixing the one above it, which
is why they are easy to mistake for one problem that keeps coming back.

### `no tab matching https://api.example.com/`

`request()` derives the relaying tab from the **request's** host. `api.` hosts
usually serve JSON and no HTML, so no tab ever exists there and no amount of
signing in creates one.

```ts
server.postJson('/v1/thing', body, { subdomain: 'api', viaTab: 'https://example.com/' })
```

`viaTab` must be inside the declared `domains`. The request URL is untouched.

### `fetch threw: Failed to fetch`

The tab was found and the request was attempted. This is the isolated world
being refused, and it is **not** a fetchproxy bug — it is the origin Chrome
attaches to content-script requests.

Confirm it in one step, because the distinction decides the fix:

```ts
await server.request('GET', 'https://example.com/',       { viaTab: 'https://example.com/' }); // 200?
await server.request('GET', 'https://api.example.com/x',  { viaTab: 'https://example.com/' }); // Failed to fetch?
```

Same-origin passing while cross-origin fails is the signature. If both fail,
the bridge is the problem, not the origin.

Two ways out, and prefer the first:

- **Read instead of ask.** If the page already sends the credential you need,
  `capture_request_header` snapshots it off traffic the page makes anyway.
  Nothing of yours crosses an origin, so the block does not apply.
- **`fetch_in_page`.** Issue the request from the page's own world. Necessary
  when there is no header to read, or when the response itself is what you
  need. It gives up the isolated world's tamper resistance — read
  §T-in-page-fetch before declaring it.

### `capability "…" not granted (declared: [fetch])`

The capability is not in the approved pairing. Declaring one is not granting
it: **widening the capability set changes the requested scope, so the pairing
must be approved again** in the extension popup. A server whose declaration
changed shows `declared: []` until that happens — not a bug, an unapproved
scope.

Note the shape of the set, not just its contents: **`capabilities` REPLACES
the server's default, it does not extend it.** Declaring anything therefore
un-declares `fetch` unless you say so, which reads at runtime as a capability
you never touched going missing:

```
capability "fetch" not granted (declared: [capture_request_header])
```

Derive capabilities from the declaration rather than listing them by hand;
`@chrischall/mcp-utils`' `createBootstrapOpts` does this, so a declared capture
cannot ship with its verb locked (it kept `fetch` from
`@chrischall/mcp-utils` 0.19.4 — before that, spread its output and add
`capabilities: ['fetch', …]` yourself):

```ts
createFetchproxyTransport({
  ...createBootstrapOpts({
    domains: 'example.com',
    bootstrap: { captureHeaders: [{ host: 'api.example.com', path: '/*', headerName: 'authorization' }] },
  }),
  serverName: pkg.name,
  version: pkg.version,
});
```

## Prefer capture over a request, where the choice exists

An MCP that needs a bearer token usually does not need to *perform* an
authenticated call — it needs the token that the page's own calls already
carry. Capturing it is strictly narrower than routing a credentialed request
through the page:

- nothing of yours crosses into the MAIN world, so nothing is exposed to a
  patched `window.fetch`;
- no cross-origin request is attempted, so the block above never applies;
- it works with what ships today.

The trade is that capture is **opportunistic**: it resolves when the page next
makes a matching request, so an idle tab yields nothing and a reload is
sometimes the trigger. Pair it with a persistent `$HOME` so the captured
credential is cached rather than re-captured on every cold start, and keep a
request-based path as the fallback for the case where no traffic arrives.

## Worked example

`resy-mcp` bootstraps a token by reading `x-resy-auth-token`. Its route through
this document, in order:

1. `POST https://api.resy.com/3/auth/refresh` → `no tab matching https://api.resy.com/`.
   api.resy.com serves no app.
2. Add `viaTab: 'https://resy.com/'` → `fetch threw: Failed to fetch`.
   The probe above showed `GET https://resy.com/` returning 200 from the same
   tab, so the tab was fine and the origin was not.
3. Declare `captureHeaders` for `x-resy-auth-token` on `api.resy.com` →
   `capability "capture_request_header" not granted`, then `declared: []`
   after the widened scope invalidated the old approval. Re-approve the
   pairing.
4. → `capability "fetch" not granted (declared: [capture_request_header])`.
   The derived set had replaced the default and dropped the verb the fallback
   needed.

Then it captured a real token off the page's own traffic, first try.

Four errors, four causes, one working path — and the token was on the page's
traffic the whole time. Each error named a symptom of the layer it stopped at,
which is why the ladder above is written by error string rather than by
concept: that is the order you meet them in.
