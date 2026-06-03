# Peer re-host on host loss

**Date:** 2026-06-03
**Package:** `@fetchproxy/server`
**Status:** approved (design), pending implementation

## Problem

The concentrator role (`host` vs `peer`) is decided exactly once, in
`FetchproxyServer.doConnect()` via `electRole()` — a `127.0.0.1:37149`
bind race. After the first connection, `ensureConnected()` short-circuits
forever:

```ts
if (this.hostHandle || this.peerHandle) return;
```

A **peer** dials the host's WebSocket. If that host process dies, the
peer's WS closes — but nothing clears `peerHandle`, so the server is
stranded as a peer permanently. `peer.ts` only wires `ws.once('close')`
to reject the first-ready gate; it never tells `ws-server` the host
vanished. Every subsequent verb call reuses the dead `peerHandle` and
fails with `peer WS closed before ready`, even though the port is now
free and the peer could trivially become the new host.

Observed in the field: a Claude Desktop app held the bridge host
(fetch-only). A second MCP (byte-delivery capable, declaring
`capture_request_header`) came up as a peer. When the desktop host was
killed, the port freed but the peer stayed stuck — no tool call could
recover without a full MCP process restart.

## Goal

When a peer's host disappears, the peer should re-elect on its next verb
call and (with the port now free) become the new **host** — which
re-pairs the extension declaring *this* server's own capabilities. If
another peer grabbed the port first, it cleanly becomes that one's peer
instead. This is exactly `electRole()` semantics; we just need to run it
again.

## Approach (lazy teardown + re-election)

Chosen over eager/background self-heal and capped-retry variants:
lazy matches the existing lazy-connect philosophy (`listen()` binds
nothing; the first verb call elects) and needs the least code. The next
tool call after host loss pays the (cheap) re-election cost; an idle peer
does no background work.

### 1. `peer.ts` — expose an `onClose` callback

Mirror the existing `onRenegotiate` / `onPendingPair` callback pattern.

- Add `onClose(cb: () => void)` to the `PeerHandle` interface.
- Maintain a `closeListeners: (() => void)[]`.
- Fire them inside the existing `ws.once('close', …)` handler, alongside
  the current `rejectFirstReady(...)`. No change for existing subscribers.

`peer.ts` stays intent-agnostic: it fires `onClose` on *any* WS close
(host died, or our own `close()`). The caller decides what that means.

### 2. `ws-server.ts` — tear down on host loss, guard intentional close

- Add `private closing = false`. Set it `true` at the top of `close()`.
  Reset it `false` at the top of `doConnect()` (NOT in `close()`'s tail —
  the WS `close` event fires asynchronously, possibly after `close()`
  returns, so resetting there would race the guard. Keeping `closing`
  true from `close()` until the next real connection means any stray
  `close` events from the torn-down socket are correctly ignored, and a
  fresh `doConnect()` re-arms the guard before wiring the new handle).
- In `doConnect()`'s peer branch, after the existing
  `onInner`/`onRenegotiate`/`onPendingPair` wiring:

  ```ts
  this.peerHandle.onClose(() => {
    if (this.closing || this.peerHandle === null) return;  // our own close(), not host death
    this.stopKeepalive();
    this.rejectAllPending();         // fail in-flight calls fast
    this.peerHandle = null;
    this.role = null;                // next verb → ensureConnected → re-elect
  });
  ```

### 3. Behavior

host dies → peer WS closes → `onClose` fires → (not closing) → handle
torn down, `role` back to `null` → next verb call's `ensureConnected()`
sees no handle → `doConnect()` → `electRole()`:
- free port → **host** (`startHost` re-declares this server's
  capabilities; a `capture_request_header`-capable server gets it back);
- port taken by another ex-peer → **peer** of the new host.

## Non-goals (tracked as future work)

- **Eager/background self-heal** — re-electing without waiting for a verb
  call. Deferred; lazy is sufficient for the observed cases.
- **Capped-retry / backoff storm control** — bounding reconnect attempts
  when a host flaps. Not needed for lazy (one re-election per verb call,
  driven by real demand).
- **Initial-dial retry** — a peer whose very first dial hits a host that's
  mid-restart (`ECONNREFUSED`) still fails that call. Separate gap.
- **Self-healing the *same* failing call** (auto-retry across the
  re-election within one verb invocation). The lazy choice means the
  *next* call recovers, not the one that observed the close.

## Testing (TDD)

Unit (`tests/peer.test.ts`):
- `onClose` fires when the host WS closes (host accepts hello, then
  closes). Asserts the callback runs.

Integration (`tests/integration/reconnect.test.ts`, new describe):
- Start host A + peer B on one port; assert `B.role === 'peer'`.
- `await A.close()`; wait for B to observe the WS close.
- Assert `B.role === null` (handle torn down, lazy).
- `await B.connect()` → assert `B.role === 'host'` (re-elected on the
  freed port).
- Guard: an intentional `B.close()` must NOT leave a torn-down handle
  mid-flight or throw (the `closing` flag suppresses the teardown path).

All mocked / in-memory per repo convention. `npm test --workspace=@fetchproxy/server`.
