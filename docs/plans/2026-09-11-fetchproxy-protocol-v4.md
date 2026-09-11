# fetchproxy protocol v4 — forward secrecy, AAD over the frame's identity, and the cohort choreography

> **For the executing session.** Self-contained: every task names its files,
> the test it adds first, and the commit it ends in. Read
> `/Users/chris/git/mcp-host/docs/beta-review-2026-09-10/fetchproxy-bridge.md`
> findings **H1** and **M2** once — they are the source for this plan and carry
> the `file:line` evidence — then only the files a task points at. Execution per
> `~/.claude/CLAUDE.md`: Workflow orchestration, one fresh agent per task with
> the full task text, sequential (nothing here is parallel-safe — every task
> after Task 1 compiles against Task 1's types), reviewer-gated, then
> `superpowers:finishing-a-development-branch` per PR.
>
> Line numbers were true on 2026-09-11 at fetchproxy `ad6b673` (2.11.3,
> PROTOCOL_VERSION 3) and mcp-host `main` at 0.62.0; re-locate by symbol if
> they have moved.
>
> This is **PR H2** of
> `/Users/chris/git/mcp-host/docs/plans/2026-09-11-single-tier-autoscale-and-backlog.md`,
> which defers to this document precisely because a wire break is not one PR —
> it is one PR plus a fleet operation plus a hand on the extension. Group 4
> below is the part that is easy to get wrong.
>
> **Filed in `docs/plans/`, not `docs/superpowers/plans/`**, because the seven
> documents there are superpowers plans with `- [ ]` checkbox tracking and a
> REQUIRED SUB-SKILL header; this one is executed by the Workflow
> orchestration `~/.claude/CLAUDE.md` mandates instead, and the mcp-host plan
> that calls for it names this path.

---

## What v4 is, in one paragraph

Two things are wrong with the v3 wire and one of them is the reason to break
it. **Forward secrecy:** the per-session AES key is
`HKDF(X25519(mcpIdentityPriv, extEphemeralPub), salt = mcpHelloNonce)` —
the MCP contributes its **long-term** X25519 key and only the browser
contributes an ephemeral (`host.ts:501`, `peer.ts:385`, `hello.ts:303`,
`approval.ts:135`), so anyone who holds an MCP's identity plus a recording of
its frames decrypts them afterwards, passively, retroactively, with nothing to
notice. **AAD:** `sealInnerFrame` (`seal.ts:140`) calls `aesGcmSeal` with no
`additionalData`, so `mcpId` and `seq` ride outside the authenticated envelope
and a party in the path can replay a recorded frame under a bumped counter, or
reflect one back. v4 gives the MCP a per-session ephemeral X25519 covered by
its hello signature, derives the session key ephemeral×ephemeral with
identities authenticating only, and puts `mcpId ‖ seq ‖ direction` in the AAD.
`PROTOCOL_VERSION` 3 → 4; v3 is refused at the hello, with no negotiated
downgrade, for the reason #222 already wrote down.

**What this does NOT buy, and must not be described as buying.** mcp-host's
PR F2 seals the provisioned `bridge_identities` row to the account's runner
key, so the gateway holds the identity plaintext for one request instead of at
rest. That narrows **who** holds the identity. It does nothing about **what an
identity holder can do with a transcript**, which is the whole of H1. The two
changes are independent and both are wanted: F2 shrinks the set, v4 empties
the capability. Neither is a substitute for the other, and the doc rewrites in
F2 must not claim otherwise.

---

## Prior art: how the 2.0.0 break was choreographed — found, and it is the template

**Yes, the repo records it.** `git show c13aeed`
(`feat(protocol)!: bind the ephemeral key into the ready signature (#222)`,
2026-08-05, released as 2.0.0 on 2026-08-06) carries the choreography in the
commit body, and `packages/protocol/src/frames.ts:28-38` carries the standing
paragraph. `CLAUDE.md` §Security model summary item 3b carries the one-sentence
version. The relevant parts, verbatim in substance:

- **The advisory came first, the fix second.** GHSA-j6jv-w774-77m6 was filed
  privately, the fix merged, and the advisory published only after merge. Same
  order here: the hole v4 closes is written down in an mcp-host review document
  that is not public, and H1's disclosure obligation (fix step 1: state the
  true residual in `docs/SECURITY.md` and tell beta tenants) belongs to
  mcp-host and precedes this work rather than waiting on it.
- **No negotiated version, and the reason.** "A version-gated variant avoids
  the break, and hands the attacker the choice: a relay that can rewrite frames
  can rewrite the field advertising v3 support, and both ends would then agree
  on the weaker payload." That argument is unchanged and applies verbatim to
  v4. It also forbids the transitional dual-stack extension that looks like the
  obvious way to shrink the outage window in Group 4 — a v4 extension that
  still accepts v3 IS the downgrade path.
- **"All packages together, old version refused at the hello."** 19 files,
  6 workspaces, one release, and the 0.4.0 precedent cited for the same shape.
- **What it said to the human.** "Reload the unpacked extension when this
  ships, or the bridge stops working — loudly, at the handshake, not silently."
- **The test discipline.** 128 tests failed on the first run because fixtures
  hand-built v2 hellos; each was moved onto the single shared payload function
  rather than patched, and `validate.test.ts` gained an assertion that v2 is
  *refused* rather than downgraded. One test (`KNOWN RESIDUAL: a relay can
  still swap the ephemeral key…`) changed sides and kept its name's meaning.

**What is different this time, and it is the whole of Group 4.** In August
2026 the only consumers were the operator's own laptop MCPs and a sideloaded
extension he reloaded himself; "loudly, at the handshake" was a message he read
in his own terminal. Today the failure lands on a hosted relay, on ~20 bridged
registrations whose npm pins move on mcp-host's nightly `follow` cron, and the
message has to survive a Durable Object that currently **drops it**
(`mcp-host/packages/core/src/bridge-frames.ts:32-38` — `readEnvelope` knows
five frame kinds and `hello-rejected` is not one of them; bridge report L10).
So v4 needs a refusal path, not only a refusal.

---

## Decisions required before Task 1

Each has a default; take the default unless Chris says otherwise.

1. **Package major.** v4 ships as `@fetchproxy/*` **3.0.0**. The off-by-one
   between package major and protocol version (package 2.x ↔ protocol 3;
   package 3.x ↔ protocol 4) persists and is a real footgun for anyone reading
   a version string as a protocol number. **Default: accept it and say so in
   `frames.ts`'s header paragraph and `CLAUDE.md`** rather than renumbering
   either; the alternative (jump the package to 4.0.0) desynchronises the
   changelog from release-please's own arithmetic for one cosmetic gain.
2. **Does the pair code change in the same break?** Bridge report **L5** —
   6 digits, `SHA256(mcpPub‖extPub)`, both inputs public and long-term, so a
   MITM grinds a target code in ~10⁶ keygens. v4 introduces a transcript hash
   that already contains both fresh nonces and both ephemerals; deriving the
   pair code from it and lengthening to 8 digits is a dozen lines and removes
   the grind entirely. It is a wire-visible change and this is the only break
   scheduled. **Default: YES, fold it in** (Task 1 mints the transcript hash;
   Task 8 re-derives the code from it), because a second break to fix L5 later
   costs the whole of Group 4 again. If Chris says no, cut Task 8 and move L5
   to "what this does not fix".
3. **Does mcp-host raise a protocol floor for bridged spawns?** Today
   `assertSandboxableConcentrator`
   (`mcp-host/packages/runner-node/src/browser-bridge/concentrator-version.ts`,
   `SANDBOX_CONCENTRATOR_MIN = '2.2.0'`) reads the installed
   `@fetchproxy/server` version off the tree **before** the spawn and refuses,
   naming both numbers — but only on the sandboxed path, and only for the
   `FETCHPROXY_WS_HOST` reason. **Default: YES** — Group 4 step 6 raises a
   separate `BRIDGE_PROTOCOL_MIN` floor applied to **every** bridged spawn, so
   a straggler registration is refused at spawn with an actionable message
   rather than discovered by a hanging tool call. This is a guard for the
   stragglers, not for the window.
4. **Beta timing.** See Group 4 §"The one-installed-copy property", below. The
   short version: **ship v4 before the extension has an install base outside
   the operator's machines.** If the beta has already handed Transporter to
   strangers on a sideloaded zip with no auto-update, this plan's Group 4 needs
   a Chrome Web Store submission in front of it. That is Chris's call and it
   gates the whole plan, not a task in it.

---

## The v4 wire, precisely

Everything below lives in `@fetchproxy/protocol` as **one exported function
per fact**, which is `readySignaturePayload`'s own rule
(`frames.ts:50-57`: "in one place so the extension that produces it and the two
server paths that verify it cannot drift apart"). Three producers and four
verifiers is exactly the population that drifted before.

### 1. The server hello gains a per-session ephemeral

```
HelloFrameFromServer {
  ...
  identityX25519Pub   // unchanged — long-term, and still the TRUST KEY
  identityEd25519Pub  // unchanged — long-term, authenticates
  sessionNonce        // unchanged shape; now minted per CONNECTION (below)
  sessionPub          // NEW: base64 raw 32B, ephemeral X25519 public key
  sessionSig          // WIDENED: see 2
}
```

`identityX25519Pub` stays the trust key. The extension pins
`sha256(identityX25519Pub)` (`hello.ts:238`) and the pair code commits to both
identities; nothing about pinning, trust records or re-pair prompts changes.
`sessionPub` is a new field beside the identity, not a replacement for it —
which is what keeps v4 from re-pairing the fleet the way L11 describes.

**Per CONNECTION, not per process.** Today `ownHello` and its nonce are built
once in `listen()` (`host.ts:197`, `peer.ts:153`) and the same bytes are sent
to every extension connection for the life of the process (bridge report I1:
"the MCP hello nonce is per PROCESS … so freshness rests on the extension's
ephemeral"). A per-process MCP ephemeral would bound forward secrecy at the
process lifetime, which on mcp-host is up to ten idle minutes of real traffic —
worth having, not worth claiming as forward secrecy. **Mint a fresh
`{sessionNonce, sessionPub, sessionPriv}` each time an extension hello arrives,
then build and send the server hello from it.** The host already sends
`ownHello` on extension connect (`host.ts:371`), so the structural change is
that the hello is *built* there rather than at `listen()`, and the private half
is held beside `ownSession` and discarded with it.

**The private half must die with the session.** Forward secrecy is the property
that an identity holder cannot open a *past* session; it is false if the
process keeps every ephemeral private key it ever minted. The session-teardown
path (`host.ts:511-528`, the close handler that nulls `ownSession`) zeroes and
drops `sessionPriv` in the same statement. Assert it.

### 2. Both signatures cover both ephemerals

```
helloSignaturePayload(mcpId, sessionNonce, sessionPub)
  = utf8(mcpId) ‖ sessionNonce ‖ sessionPub
  signed with the MCP's long-term Ed25519 key      (v3: mcpId ‖ sessionNonce)

readySignaturePayload(mcpNonce, extNonce, extSessionPub, mcpSessionPub)
  = mcpNonce ‖ extNonce ‖ extSessionPub ‖ mcpSessionPub
  signed with the extension's long-term Ed25519 key (v3: without mcpSessionPub)
```

The hello payload is the exact mirror of what #222 did for the ready: without
it a relay substitutes `sessionPub` for one it holds the private half of, the
extension derives against the relay's key, and forward secrecy is fiction. The
extension already verifies the hello signature over `mcpId ‖ sessionNonce`
(`hello.ts:226-234`, `{kind:'reject', reason:'sessionSig invalid'}`), so
widening the payload is a change of argument at one call site on each side —
which is exactly why it must be a shared function and not two concatenations.

The ready payload gains `mcpSessionPub` so the transcript is bound
symmetrically: after v4 neither side's contribution to the ECDH can be
substituted without a signature from a long-term key the relay does not hold.

### 3. The session key is derived from a transcript, ephemeral × ephemeral

```
shared   = X25519(ownEphemeralPriv, peerEphemeralPub)
transcript = SHA256(mcpNonce ‖ extNonce ‖ mcpSessionPub ‖ extSessionPub)
sessionKey = HKDF-SHA256(ikm = shared, salt = transcript,
                         info = 'fetchproxy/4.0.0/session', 32)
```

`HKDF_SESSION_INFO` moves from `'fetchproxy/1.0.0/session'` (`frames.ts:47`) to
`'fetchproxy/4.0.0/session'`, so even a hypothetical key-confusion between
versions yields different bytes. The transcript salt also closes **I1**: under
v3 a replayed old `ready` re-establishes an old key with a reset counter
(harmless only by the `id` matching downstream); with the salt covering both
nonces and both ephemerals, a replayed `ready` derives a key nothing else
holds.

`transcriptHash()` is exported because decision 2 wants it for the pair code.

### 4. AAD over the frame's identity

```
frameAad(mcpId, seq, direction)
  = utf8('fetchproxy/4/frame' ‖ NUL ‖ mcpId ‖ NUL ‖ decimal(seq) ‖ NUL ‖ direction)

type Direction = 's2e' | 'e2s'   // server→extension, extension→server
```

NUL-separated because `mcpId`'s charset (`MCP_ID_RE`) excludes NUL and `seq` is
decimal, so the encoding is unambiguous — the `scope\0accountId\0name`
convention mcp-host's `seal.ts` already uses for the same reason. The domain
label in front means an AAD can never be mistaken for any other signed or
authenticated string in this protocol.

`sealInnerFrame` and both `openEncryptedFrame*` take `direction` as a
**required** parameter, so no call site can omit it and no default can be wrong.
The direction byte is what makes reflection structural rather than incidental
(**I2**: today a reflected frame is harmless only because the two dispatchers
ignore each other's inner types).

**The wire size does not change.** GCM's additional data is authenticated, not
transmitted. `sealedFrameWireBytes` (`seal.ts`) and the 42 MiB
`MAX_FRAME_BYTES` derivation are untouched, and Task 2 asserts that so nobody
"fixes" the constant later.

### 5. v3 is refused at the hello — and the refusal is heard

`validateHello` (`validate.ts:517-519`) throws
`hello.protocolVersion: must be 3` on anything else, which is correct and is
also, today, the end of the story: the extension's `onMessage` catches that
throw and **drops the frame with a `console.warn` in a service worker nobody
has open** (`socket.ts:246-248`). The MCP then waits out
`SESSION_READY_TIMEOUT_MS` = 30 s (`session-ready.ts:9`) and reports `not-ready`
with a hint that blames being signed out or a changed scope. That is precisely
the silent hang v4 must not ship.

**Both directions can be made clean by changing only the v4 side.** That is the
load-bearing insight of this plan, and it is what makes the outage window a
matter of minutes rather than of upgrade ordering:

| Pair | What happens | Whose code must change |
|---|---|---|
| **v3 MCP ↔ v4 extension** | The v4 extension recovers `protocolVersion`, `mcpId` and `accepts` from the refused hello and answers `hello-rejected` with a reason naming both versions. The v3 MCP at ≥ 2.6.0 already parses that frame (`host.ts:569`, `peer.ts:417`) and fails its pending session immediately. | extension only |
| **v4 MCP ↔ v3 extension** | The extension sends its hello **first** on every connection (`socket.ts:197-208`, in the socket's `open` handler), before the server sends its own. So the v4 host reads `protocolVersion: 3` off the extension's hello, fails the pending session immediately, and closes with a reason naming both versions. | server only |

The second row is a *refinement* of what the host does today, not a reversal:
`host.ts:277-286` already closes `1002 'protocol error'` when `validateFrame`
throws, so the socket does not linger. What it does not do is say **why** — the
close reason is the same three words for a version mismatch as for a mangled
field — and, the part that actually costs thirty seconds, it does not reject
`ownSessionReady`. So the MCP's next `request()` waits out
`SESSION_READY_TIMEOUT_MS` while the extension reconnects on its backoff and
is closed again, forever. The v4 change is the reason text and the immediate
rejection; the close itself is already there.

The `hello-rejected` frame is the right vehicle for the first case because it
**predates the break**: it landed in 2.6.0, the whole cohort declares
`accepts: ['hello-rejected']` (`host.ts:180`, `peer.ts:200`), the extension
already gates on that declaration (`server-hello.ts:81`), and the frame's own
doc records that it "carries no authority and grants nothing. A forged one can
make a session fail, which a silent peer could do anyway by never answering."

**The narrow reader.** Reading fields out of a frame you have just refused is
the kind of thing that goes wrong, so it gets its own function with its own
contract: `peekHelloVersion(raw: unknown)` returns
`{ protocolVersion, mcpId, accepts } | null`, rebuilt member by member (never a
cast of the parsed object), `mcpId` regex-validated or null, `accepts` filtered
to strings, and **it grants nothing** — no caller may start a session, bind an
`mcpId` slot, write a trust record or move a counter from its output. Its only
two consumers are the two refusal paths. The `readEnvelope` / rebuild-member-by-
member pattern, and Task 6's test asserts the "grants nothing" half by
construction.

---

## File map

| Action | Path | Why |
|---|---|---|
| Modify | `packages/protocol/src/frames.ts` | `PROTOCOL_VERSION` 4, `HKDF_SESSION_INFO`, `sessionPub` on the server hello, `helloSignaturePayload`, widened `readySignaturePayload`, `transcriptHash`, `frameAad`, `Direction`, the standing v4 paragraph in the header |
| Modify | `packages/protocol/src/validate.ts` | require `sessionPub`; `peekHelloVersion` |
| Modify | `packages/protocol/src/crypto.ts` | `aesGcmSeal`/`aesGcmOpen` take `aad` |
| Modify | `packages/protocol/src/seal.ts` | `direction` required on seal/open; AAD threaded; `sealedFrameWireBytes` unchanged |
| Modify | `packages/protocol/src/pair-code.ts` | decision 2 only — derive from the transcript hash, 8 digits |
| Modify | `packages/server/src/build-server-hello.ts` | mint/accept the ephemeral, sign `helloSignaturePayload` |
| Modify | `packages/server/src/host.ts` | per-connection hello, ephemeral derivation, widened ready verify, AAD, v3 extension refusal, zeroing on teardown |
| Modify | `packages/server/src/peer.ts` | the same on the peer path |
| Modify | `packages/server/src/frame-size.ts` | seal/measure signature follow-through |
| Modify | `packages/extension-core/src/background/hello.ts` | verify the widened hello signature; derive against `sessionPub` |
| Modify | `packages/extension-core/src/background/approval.ts` | the same on the approval path |
| Modify | `packages/extension-core/src/background/server-hello.ts` | sign the widened ready payload |
| Modify | `packages/extension-core/src/background/socket.ts` | AAD on open; the v3-server refusal path |
| Modify | `packages/extension-core/src/background/send-inner.ts` | AAD on seal |
| Modify | `packages/extension-core/src/popup/popup.ts` | a protocol-mismatch line on the link |
| Modify | `packages/cli/src/bridge-errors.ts` | map the mismatch reason to a remedy |
| Modify | `packages/test-helpers/src/index.ts` | mock signature follow-through |
| Create | `packages/server/tests/cross-version/` | frozen v3 fixtures + the refusal suite (Task 7) |
| Modify | `docs/PROTOCOL.md`, `docs/SECURITY.md`, `CLAUDE.md`, `README.md` | the v4 record |

`packages/bootstrap` has no protocol surface of its own (it composes
`FetchproxyServer`); it needs a release and a smoke test, not an edit. Confirm
with `grep -rn "@fetchproxy/protocol" packages/bootstrap/src` before assuming.

---

## Group 1 — the protocol

> One PR: branch `feat/protocol-v4`, title
> `feat(protocol)!: per-session ephemerals on both sides, AAD over the frame's identity, and v3 refused at the hello`.
> The `!` is correct here and is the only place in this plan it is: this
> genuinely is the breaking change. **Beware the single-commit squash rule** —
> if this PR ends up as one commit, GitHub squashes on the *commit* subject, so
> the commit subject must carry the `!` and the same text as the title.

**Task 1.1 — the transcript.** Where: `packages/protocol/src/frames.ts:40`
(`PROTOCOL_VERSION`), `:47` (`HKDF_SESSION_INFO`), `:58` (`readySignaturePayload`),
the `HelloFrameFromServer` interface, `validate.ts:517`.
Test (`packages/protocol/tests/frames.test.ts`, first): `PROTOCOL_VERSION === 4`;
`helloSignaturePayload` is the exact concatenation and changes with each of its
three inputs; `readySignaturePayload` takes four arguments and changes with each;
`transcriptHash` changes with each of its four; `HKDF_SESSION_INFO` is
`'fetchproxy/4.0.0/session'`. In `validate.test.ts`: a hello with
`protocolVersion: 3` is **refused**, not downgraded (the #222 assertion, moved
one version along); a server hello missing `sessionPub` is refused; a
`sessionPub` that is not 32 raw base64 bytes is refused.
Do: implement. Keep each payload function a single concatenation with a doc
comment saying which version widened it, in the style `frames.ts:50-57` already
uses.

**Task 1.2 — the AAD.** Where: `packages/protocol/src/crypto.ts` (`aesGcmSeal`,
`aesGcmOpen`), `seal.ts:140` (`sealInnerFrame`) and both `openEncryptedFrame*`.
Test (`packages/protocol/tests/seal.test.ts`, first): a frame sealed at
`(mcpId, seq, 's2e')` opens under the same triple and **fails to open** under
`seq + 1`, under another `mcpId`, and under `'e2s'` — three separate
assertions, each failing at the `decrypt-failed` stage (not
`validation-failed`, which would mean the tag passed); `frameAad` is the exact
NUL-separated encoding; `sealedFrameWireBytes` returns the same number it
returned before this task for the same inner frame, and a sealed frame's
`JSON.stringify` length still equals it.
Do: `aad` is a required parameter on the crypto wrappers and `direction` a
required parameter on seal/open — no defaults anywhere, so every call site is a
compile error until it answers.

**Task 1.3 — `peekHelloVersion`.** Where: `packages/protocol/src/validate.ts`.
Test (`validate.test.ts`, first): a v3 server hello yields
`{protocolVersion: 3, mcpId, accepts}`; a hello with a malformed `mcpId` yields
`mcpId: null` rather than the string; `accepts` holding a non-string drops that
entry; a non-object, a non-`hello` type and a missing `protocolVersion` all
yield `null`; the returned object has no other keys (assert
`Object.keys(...)`, so a field added to the hello later is not echoed out of a
refused frame).
Do: implement by rebuilding member by member. Doc comment states the contract:
it grants nothing, and its only callers are the two refusal paths.

Commit: `feat(protocol)!: protocol v4 — per-session ephemerals, a transcript-salted session key, and mcpId‖seq‖direction in the AAD`.

---

## Group 2 — the server

**Task 2.1 — the host.** Where: `packages/server/src/host.ts` (hello built at
`:197` moves to the extension-connect path at `:371`; derivation `:501`; ready
verify `:458`; teardown `:511-528`), `build-server-hello.ts:79`.
Test (`packages/server/tests/host.test.ts`, first): two successive extension
connections to one host receive hellos with **different** `sessionPub` and
`sessionNonce`; the session key derived by a mock extension against the hello's
`sessionPub` matches the host's; a `ready` whose `sessionSig` omits
`mcpSessionPub` from its payload is refused; after the extension socket closes,
the host holds no readable copy of the previous `sessionPriv` (assert through
the exported surface or an injected zeroing hook — do **not** add an accessor
that exists only for the test).
Do: mint `{nonce, pub, priv}` per extension connection; build and send the
hello from it; derive `X25519(sessionPriv, extSessionPub)`; salt with
`transcriptHash`; pass `direction: 's2e'` on seal and `'e2s'` on open; zero and
drop `sessionPriv` in the same statement that nulls `ownSession`.

**Task 2.2 — the peer.** Where: `packages/server/src/peer.ts:153`, `:275`,
`:385`, `frame-size.ts`.
Test (`packages/server/tests/peer-hello-auth.test.ts` and the integration
suites under `tests/integration/`, first): the peer path derives the same key
the host path does against the same mock extension; a peer whose hello omits
`sessionPub` is refused by the host at registration.
Do: the same five changes. The peer's `requireExtensionIdentity` /
`warnedUnverifiable` branch (`peer.ts:240-271`) is about a pre-1.12.0 *host*
and is orthogonal — leave it, and check its wording still reads right beside a
v4 refusal.

Commit: `feat(server)!: mint a session ephemeral per extension connection and authenticate every frame against its own identity`.

---

## Group 3 — the extension

**Task 3.1 — derivation and signature.** Where:
`packages/extension-core/src/background/hello.ts:226-234` (verify) and `:303`
(ephemeral), `approval.ts:135`, `server-hello.ts:136`.
Test (`packages/extension-core/tests/hello.test.ts`, first): a server hello
whose `sessionSig` does not cover `sessionPub` is rejected with a reason naming
the signature; the auto-trust and the approval paths derive the **same** key
for the same hello (they are two code paths deriving one thing and have drifted
before); the `ready` the extension emits signs all four fields.
Do: verify `helloSignaturePayload`; derive against `hello.sessionPub` rather
than `identityX25519Pub`; salt with `transcriptHash`; sign the widened ready
payload. **Trust matching is untouched** — the record is still keyed on
`sha256(identityX25519Pub)` (`hello.ts:238`), so no registration re-pairs
because of v4. Assert that: a trust record written under v3 still auto-trusts
under v4 for the same identity, serverName and domain set.

**Task 3.2 — AAD on both directions.** Where: `send-inner.ts`, `socket.ts`
(`onEncryptedFrame`, around `:258-300`).
Test (`packages/extension-core/tests/socket.test.ts`, first): a frame the
extension sealed opens on the server side and not under a bumped `seq`; a
server→extension frame replayed under `seq + 1` fails at `decrypt-failed` and
— this is the part that matters — **releases** the claimed seq rather than
committing it, so the next genuine frame is still accepted (the `claimInboundSeq`
/ `releaseInboundSeq` contract `socket.ts` already documents).
Do: `'e2s'` on seal, `'s2e'` on open.

Commit: `feat(extension)!: derive the session key against the MCP's ephemeral and bind every frame to its id, ordinal and direction`.

---

## Group 4 — the refusal (both directions), and the surfaces that say so

This is the group that makes the release choreography survivable. Do not let it
be cut for time.

**Task 4.1 — a v4 extension refuses a v3 MCP, out loud.** Where:
`packages/extension-core/src/background/socket.ts:246-248` (the drop),
`server-hello.ts:81-85` (the existing `hello-rejected` sender).
Test (`packages/extension-core/tests/socket.test.ts`, first): a server hello
with `protocolVersion: 3` and `accepts: ['hello-rejected']` produces exactly one
`hello-rejected` on that link, addressed to that `mcpId`, whose `reason`
contains both numbers and the package version to upgrade to; **no** session is
created, no trust record is read or written, no `mcpId` slot is bound; a v3
hello **without** `accepts` produces no frame at all (and a warn); a hello that
is malformed for any other reason still takes the existing silent-drop path —
the version mismatch is the only case that answers.
Do: on the `validateFrame` catch, call `peekHelloVersion`; answer only when the
version differs from `PROTOCOL_VERSION`, `mcpId` is non-null and `accepts`
includes `hello-rejected`. Reason text, fixed and asserted:
`protocol version mismatch: this browser extension speaks fetchproxy protocol 4, this MCP speaks 3 — upgrade @fetchproxy/server to >= 3.0.0`.

**Task 4.2 — a v4 MCP refuses a v3 extension, out loud.** Where:
`packages/server/src/host.ts:277-286` (the `validateFrame` catch that closes
`1002 'protocol error'` today), the extension-hello branch below it, and the
same two places in `peer.ts`.
Test (`packages/server/tests/host.test.ts`, first): a socket that sends an
extension hello with `protocolVersion: 3` is closed within one tick **with a
reason naming both versions** (assert the reason string, not only the code);
the pending `ownSessionReady` rejects immediately with an error whose message
names both versions and the extension version to install — **not** after
`SESSION_READY_TIMEOUT_MS` (assert against a fake clock); a `request()` issued
afterwards fails fast with the same message; a frame that is malformed for any
*other* reason still closes with today's generic `1002 'protocol error'` and
leaves the pending session alone, so the mismatch is the only case that gets
the new treatment.
Do: `peekHelloVersion` in that catch, the same shape as 4.1. Message text,
fixed and asserted:
`protocol version mismatch: this MCP speaks fetchproxy protocol 4, the attached browser extension speaks 3 — update Transporter (the fetchproxy extension) to 3.0.0 or later`.
Name the *extension* by its user-facing name, because the person reading this
in a claude.ai tool error has a browser, not a package.

**Task 4.3 — the popup says it.** Where:
`packages/extension-core/src/popup/popup.ts` (the per-link status rendering).
Test (`packages/extension-core/tests/popup.test.ts`, first): a link whose last
event was a version-mismatch refusal renders a line naming the MCP's
`serverName` and both versions; the line clears when a v4 hello succeeds on
that link.
Do: the popup's per-link dot is the only signal today (bridge report **I22**),
and the popup is the one surface the *browser* user has. Keep the text to one
line and do not invent a remediation the user cannot perform — the remedy for
this case is on the MCP side.

**Task 4.4 — the CLI maps it.** Where: `packages/cli/src/bridge-errors.ts`.
Test (`packages/cli/tests/bridge-errors.test.ts`, first): the mismatch reason
maps to a remedy sentence rather than to the generic bridge-unavailable hint.
Do: one entry. `fpx` is how the operator will debug a straggler.

Commit: `feat(server,extension)!: a version mismatch fails at the hello, naming both versions, instead of hanging for thirty seconds`.

---

## Group 5 — cross-version proof

**Task 5.1 — the frozen v3 fixtures.** Create
`packages/server/tests/cross-version/v3-fixtures.ts`: byte-literal v3 hello,
ready and frame objects, captured once from 2.11.3 and **hard-coded**, with a
comment saying they are frozen bytes and must never be regenerated from the
current source. This is the whole point: a fixture built from today's
`PROTOCOL_VERSION` is not a v3 fixture, it is a tautology, and #222's own
report records that 128 tests failed precisely because fixtures hand-built the
old version. Freezing them means a future break has a v3 corpus to test
against too.

**Task 5.2 — the cross-version suite.** Create
`packages/server/tests/cross-version/refusal.test.ts`. Four cases, all
asserting a *clean* outcome within a bounded time and never a timeout:

1. **v3 mock extension → v4 host.** Host closes 1008, reason names both
   versions, `ownSessionReady` rejects immediately, elapsed time is far below
   `SESSION_READY_TIMEOUT_MS` (assert against a fake clock, not a wall-clock
   threshold).
2. **v3 mock server → v4 extension** (`extension-core` test harness). Exactly
   one `hello-rejected`, correct `mcpId`, reason names both versions, no
   session, no trust write.
3. **v4 host ↔ v4 extension.** The control: the same rig completes a handshake,
   derives matching keys, and round-trips a sealed frame. Without the control
   the first two prove only that nothing works.
4. **v3 frame replayed at a v4 session.** A v3-shaped frame (no AAD) offered to
   a v4 session fails at `decrypt-failed`, and a v4 frame replayed under
   `seq + 1` does too — the M2 regression pinned where a future refactor of
   `seal.ts` would trip it.

**Task 5.3 — the mutation check.** Per
`~/.claude/projects/.../mutation-testing-needs-a-rebuild.md`: cross-package
tests run the built `dist/`, so a mutation without `npm run build` always
survives. Build first, then mutate each of the four v4 facts in turn — drop
`sessionPub` from the hello payload, drop `mcpSessionPub` from the ready
payload, drop `direction` from the AAD, leave `HKDF_SESSION_INFO` at
`1.0.0` — and confirm a test fails for each. Record the four results in the PR
body. A fact with no failing test is a fact the next refactor removes.

Commit: `test(server,extension): prove a v3 peer meets a v4 host with a clean refusal, against frozen v3 bytes`.

---

## Group 6 — the record

**Task 6.1 — `packages/protocol/src/frames.ts` header.** Add the v4 paragraph
in the exact style of the 0.4.0 and 2.0.0 ones already at `:1-38`: what moved,
why it is a hard break, why there is no negotiated downgrade, and — new for
this one — that the AAD does not change the wire size so `MAX_FRAME_BYTES` is
unmoved. State the package-major off-by-one from decision 1 here, once.

**Task 6.2 — `docs/PROTOCOL.md`.** The four wire facts above with their exact
encodings, the two refusal paths and their message texts, and a table of
`PROTOCOL_VERSION` → package major → what changed, so the off-by-one is
readable rather than inferred.

**Task 6.3 — `docs/SECURITY.md`.** Retract what v3 could not support and state
the new residual precisely. Retract: `:236` "Hosting an MCP does not give the
host the user's cookies, requests or responses" was **true only of a host that
does not also hold the identity** — under v4 it is true of an identity holder
too, and say what changed and when. `:197`/`:326` on replay: v4's AAD closes
it; say so and stop overstating it as already closed. Add the new residuals
(Group 7's list) rather than letting them be discovered.

**Task 6.4 — `CLAUDE.md`.** §Security model summary items 2 and 3b get the v4
sentences; the "Current line" paragraph moves to 3.x. Two or three sentences,
in the voice of the existing 2.0.0 note. Do not restate the release
choreography here — it lives in this plan and in the PR body, and a third copy
drifts.

**Task 6.5 — `README.md` and `packages/extension-chrome/README.md`.** The
install line says which extension version pairs with which package major, and
the "reload after pulling" note is upgraded from advice to a requirement with
the failure it prevents named.

Commit: `docs(protocol,server): record the v4 break, retract the confidentiality claim v3 could not support, and name what v4 still does not fix`.

---

## Group 7 — the release choreography

The hard part, and the reason this plan exists. Nothing below is a code task;
all of it is a sequence with a hand on it.

### What must move together

| Population | Count (measured 2026-09-11) | How it moves | Latency |
|---|---|---|---|
| `@fetchproxy/*` packages | 6 (4 published, 2 private) | release-please, one combined PR, one `v3.0.0` tag, one publish job | minutes after the release PR merges |
| Cohort npm consumers | **31 `*-mcp` repos** pinned at `^2.10.0` (moving to `^2.11.3` in PR H1), plus `@chrischall/mcp-utils`, whose declaration is a `*` **peer** and needs no range edit | 31 PRs, each `fix(deps):`, each its own release-please cycle, each its own npm publish | hours, and unattended it is days |
| Bridged registrations on mcp-host | **~20** on the shared tier | a source PUT (or `mcp-host update-all`) per registration → new `configHash` → new install slot → builder artifact → restart | minutes if driven; **a night** if left to the `follow` cron |
| The browser extension | effectively **one installed copy** today (see below) | rebuild `dist/`, reload at `chrome://extensions`, or install the GitHub-release `.zip` | seconds |

The exact cohort, so the executing session does not have to rediscover it:
`alltrails angi artsonia booli canvas-parent compass creditkarma easytable etix
eventbrite evite groupon hemnet homes honeybook infinitecampus jobber musescore
myatriumhealth onehome opentable redfin remind resy setlist signupgenius tock
tripadvisor workday zillow zola` (each `-mcp`), plus `mcp-utils`. Re-derive with
`grep -l '"@fetchproxy/server"' ~/git/*/package.json` before starting; the list
was 32 files on 2026-09-11 and it grows.

### The ordering, and why

**Cohort first, extension last.** Both orderings have a broken window — that is
what a hard break means — and the question is only which window the operator
controls.

- *Extension first* breaks every bridged registration at once and keeps them
  broken until 31 npm releases and 20 re-pins have landed. Days.
- *Cohort first* breaks every bridged registration only for as long as it takes
  to reload one extension on one machine. Seconds, if the build is already
  sitting in `dist/`.

There is no third option. A transitional extension that accepts both v3 and v4
is **the downgrade path #222 refused**: a rewriting relay rewrites
`protocolVersion` to 3 and strips `sessionPub`, and the extension does static
DH with a smile. Do not build it, and do not let a reviewer ask for it without
this paragraph in the answer.

### The sequence

1. **Gate.** Decisions 1–4 answered. mcp-host PR H1 (the cohort bump to 2.11.3)
   is *merged and landed on the fleet*, so this operation moves one range, not
   two. mcp-host's `readEnvelope` change (Group 7 §prerequisite, below) is
   **live in the gateway**, not merely merged.
2. **fetchproxy 3.0.0.** Groups 1–6 merge; the release PR merges; the `v3.0.0`
   tag cuts; the publish job runs. Then, per the fleet rule that a green tag is
   not a green publish: `npm view @fetchproxy/protocol version` and the same
   for `server`, `bootstrap`, `test-helpers` — all four must read `3.0.0`. If
   any does not, re-run `release-please.yml` by `workflow_dispatch` with
   `republish_tag: v3.0.0`; the publish step is idempotent.
3. **Build the extension now, before touching the cohort.** `npm run build
   --workspace=@fetchproxy/extension-chrome`, confirm
   `packages/extension-chrome/dist/manifest.json` reads `3.0.0`, and leave it
   there. Per
   `~/.claude/projects/.../fetchproxy-extension-needs-rebuild.md`: merged
   extension code is not running code until `dist/` is rebuilt and Chrome has
   reloaded it. Doing this in step 3 rather than step 6 is what makes step 6 a
   single keystroke.
4. **The cohort: 31 PRs.** For each repo, bump `@fetchproxy/server` to
   `^3.0.0`, update the lockfile, and open a PR titled
   `fix(deps): @fetchproxy/server 3.0.0 — protocol v4 (forward secrecy, AAD over the frame)`.
   Four fleet rules bite here and each has drawn blood before:
   - **`fix(deps):`, label `bug`** — a first-party bump is not a chore.
     `chore:`/`build(deps):`/`dependencies` ships nothing.
   - **These are one-commit PRs, so GitHub squashes on the COMMIT subject, not
     the PR title.** Make the commit subject identical to the title. This is
     the encore-ios #39 shape exactly.
   - **No `!`** on any cohort PR. The break is in fetchproxy; a consumer
     picking up a new dependency is a `fix`, and an `!` here cuts 31 unwanted
     majors.
   - **Never add the arming label and never merge.** Each repo's auto-review
     pipeline arms its own merge; watch the verdicts and the
     `auto-review-followup` issues.
   Then confirm publication per repo (`npm view <pkg> version`), because 31
   publish jobs is 31 chances for the ofw-mcp silent-publish-failure shape.
5. **The fleet, in one window.** Do **not** wait for the nightly `follow` cron:
   it re-pins each registration independently, so the fleet would spend a night
   half on v3 and half on v4, with every bridged registration broken the whole
   time regardless. Drive it: for each of the ~20 bridged registrations, a
   scoped `mcp-host update-all` or a per-registration source PUT, then confirm
   the installed version on each — the runner logs it, and
   `GET /api/v1/registrations/{id}/status` reports `lastInstallOutcome`
   (`'artifact'` means the builder's tree, which is what you want to see).
   Budget for the builder: each new pin is a new `(pin, lock hash, build)`
   triple and therefore a new artifact.
6. **Reload the extension.** `chrome://extensions` → Transporter → reload (or
   install the release `.zip`). The outage window closes here.
7. **Verify end to end, not by inspection.** Pick three bridged registrations
   that have round-tripped real traffic before — `alltrails`, `tock`, `etix`
   are the three mcp-host's CLAUDE.md records as having done it on
   2026-09-09 — and make a real tool call on each. `session_state: linked` and
   `extension_connected: true` are necessary, not sufficient: make the call.
8. **Raise the floor** (decision 3). Land mcp-host's `BRIDGE_PROTOCOL_MIN` so a
   straggler registration is refused at spawn naming both versions. Do this
   *after* step 7, never before: a floor raised while the fleet is mid-move
   refuses exactly the registrations you are in the middle of moving.

### The prerequisite in mcp-host, which is not optional

`packages/core/src/bridge-frames.ts:32-38` lists the five frame kinds
`readEnvelope` will forward, and `hello-rejected` is not among them
(bridge report **L10**). Over the hosted relay, therefore, Task 4.1's clean
refusal is **discarded by the Durable Object** and the child hangs for
`SESSION_READY_TIMEOUT_MS` exactly as it does today — which means every
mid-window straggler in step 5 looks like a dead connector rather than a
version mismatch, and the message this whole plan exists to deliver never
reaches anyone.

mcp-host's PR A1 already carries this change (`fix(bridge): forward the
extension's rejection and disconnect frames to the child instead of dropping
them`). **It must be merged and deployed before step 2**, and step 1 checks it
against the live gateway rather than against `main`. If A1 has slipped, this
plan waits.

### The one-installed-copy property, and the window it is closing

The extension is distributed today as an unpacked sideload and a GitHub-release
`.zip`. The Chrome Web Store listing is *prepared* — `docs/store-assets/`,
`docs/PRIVACY.md`, the Transporter rebrand, the whole of
`docs/superpowers/plans/2026-05-26-transporter-cws-launch.md` — but not
submitted: `README.md:62` still links
`chromewebstore.google.com/detail/transporter/EXTENSION_ID_PLACEHOLDER`. So
there is no auto-update channel, and step 6 above is a single reload because
there is essentially a single install.

**That is a property with an expiry date, and it is the argument for shipping
v4 now rather than after the beta.** The moment mcp-host's beta hands
Transporter to people who are not Chris, a wire break stops being one reload
and becomes a support operation against an install base that cannot be pushed
to: every one of those users' bridged MCPs breaks when their registration
re-pins on the nightly cron, and the only thing that tells them why is Task
4.2's tool error — which is exactly why Group 4 is not optional, and exactly
why it is still a worse outcome than shipping first.

Concretely: **either v4 lands before the beta distributes the extension, or the
CWS submission lands before v4 does.** There is no third arrangement in which
the next wire break is cheap. Chris's call (decision 4); this plan assumes the
first.

### Rollback

There isn't one that preserves the fleet — a wire break is symmetric, so
reverting the extension to v3 while the cohort is on v4 is the same outage in
the other direction. What there is:

- **Keep the v3 extension build.** Before step 3, copy
  `packages/extension-chrome/dist/` aside (or keep the v2.11.3 release `.zip`
  to hand). Restoring it is a reload — seconds — and it is the only fast half of
  a rollback.
- **Keep the previous pin per registration.** Note each bridged registration's
  pre-step-5 source pin. Rolling one back is one source PUT each, and the pin
  is exact, so nothing has to be resolved again.
- **The cohort is not rolled back.** A published npm version is published; the
  way back is a registration pinned to the older one, which the point above
  already gives you.

State in the PR body that a rollback is a *fleet* operation of about the same
size as the rollout, so that nobody plans the rollout on the assumption that
backing out is cheap.

---

## What this does NOT fix, stated plainly

v4 closes H1 and M2. Everything below stays true the day it ships, and the
`docs/SECURITY.md` rewrite in Task 6.3 must say so rather than let a reader
infer that a version bump fixed the bridge.

1. **The pair code an MCP shows its user is still the relay's number**
   (bridge report **M1**). `ws-server.ts`'s `pairingErrorMessage` (`:1728`,
   reached from `:1665`, `:1703`, `:1760`, `:3649`) builds the tool-error text
   from the `pair-pending` frame's `pairCode` — a plaintext, unauthenticated
   field — while the self-derived code (`host.ts:358`,
   `derivePairCodeFromIds`) reaches only the optional `onPairCode` hook, and on
   the peer path even that is wired to `onPendingPair`
   (`ws-server.ts:1708-1710`). On mcp-host that displayed code **is** the
   comparison channel, since a hosted MCP has no terminal, so the SAS compares
   the relay's number against the relay's number. This is a server-side display
   change (surface only the self-derived code; treat a disagreeing
   `pair-pending` as an alarm) and needs **no wire break** — it can and should
   ship separately, before or after v4.
2. **The pair code's own strength**, if decision 2 goes the other way. 6 digits,
   `SHA256(mcpPub‖extPub)`, both inputs public and long-term, so a MITM grinds
   a target in ~10⁶ keygens (**L5**). If it is not folded into this break it
   needs its own.
3. **The hosted relay still sees the metadata** (**I19**): serverName, version,
   declared domains, capabilities, cookie and storage key *names*, capture
   header names, GraphQL operation names, `mcpId`s, frame timing, frame sizes
   and per-registration byte counts. v4 protects the contents of frames. It
   protects nothing about the shape of the conversation, and the server hello
   is plaintext by construction because the extension must render it in a pair
   prompt.
4. **A compromised endpoint reads everything.** Forward secrecy is a statement
   about *past* sessions and about a party holding an identity. A gateway that
   is compromised *while a session is live* and can reach the child's memory —
   or an operator who runs the runner — reads the plaintext. mcp-host's
   `docs/SECURITY.md` says this about the operator already; v4 does not change
   it and must not be read as changing it.
5. **The extension is still trusted on first use over the relay** (**H2**).
   `FETCHPROXY_TRUST_DIR` (#352, shipped in 2.11.3) gives the pin a writable
   home, but whether a given hosted registration *has* one is an mcp-host
   deployment question, not a protocol one.
6. **`Origin: null` and `http://localhost:*` are still admitted** at the
   concentrator (**L3**, `host.ts:41` `PUBLIC_ORIGIN_RE`, applied at `:165`
   only when an `Origin` is present), and declared domains still have no
   public-suffix check (**L7**). Both are in mcp-host's PR F4, not here.
7. **Cloudflare's 1 MiB WebSocket message limit is still below fetchproxy's
   5 MiB body cap** (**L9**), so a large bridged response still tears down the
   browser link. That is a chunking change at the protocol layer and would be a
   *second* wire change — deliberately not folded in, because it is additive
   work with a real design of its own and bundling it would put this break's
   schedule behind it.
8. **`Ed25519` key confusion in the extension's trust match** (**L6**):
   `hello.ts:261-272` matches on the X25519 hash, serverName, domains and the
   extension's own identity, never `record.identityEd25519Pub ===
   hello.identityEd25519Pub`. No confidentiality loss, and it is a one-line
   comparison — but it is not in this plan, so it is not in this release.
9. **mcp-host's F2 is still wanted.** v4 makes an identity holder unable to
   decrypt a transcript; F2 makes fewer parties identity holders. Landing v4 is
   not a reason to drop F2, and the two doc rewrites must not each claim the
   other's ground.

---

## After every PR

`superpowers:finishing-a-development-branch`; watch the auto-review verdict and
its `auto-review-followup` issue; address findings **on the open PR**; never add
the arming label. When a PR merges, verify with `git diff main..<branch>` what
actually landed, not what it intended to. After the release, `npm view` all four
published packages before believing the tag.
