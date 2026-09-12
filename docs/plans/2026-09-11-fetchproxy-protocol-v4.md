# fetchproxy protocol v4 — forward secrecy, AAD over the frame's identity, and the cohort choreography

> **For the executing session.** Self-contained: every task names its files,
> the test it adds first, and the commit it ends in. Read
> `/Users/chris/git/mcp-host/docs/beta-review-2026-09-10/fetchproxy-bridge.md`
> findings **H1** and **M2** once — they are the source for this plan and carry
> the `file:line` evidence — then only the files a task points at. Execution per
> `~/.claude/CLAUDE.md`: Workflow orchestration, one fresh agent per task with
> the full task text, sequential (nothing here is parallel-safe — every task
> after Group 1 compiles against Group 1's types), reviewer-gated, then
> `superpowers:finishing-a-development-branch` per PR.
>
> Line numbers were true on 2026-09-11 at fetchproxy `ad6b673` (2.11.3,
> PROTOCOL_VERSION 3) and mcp-host `main` at 0.62.0; re-locate by symbol if
> they have moved.
>
> This is **PR H2** of
> `/Users/chris/git/mcp-host/docs/plans/2026-09-11-single-tier-autoscale-and-backlog.md`,
> which defers to this document precisely because a wire break is not one PR —
> it is one PR plus a fleet operation plus a hand on the extension. Group 7
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
And because the identities then authenticate *only* — nothing else proves
possession of them any more — v4 has to close the extension's half-pinned trust
match in the same break (**L6**): the hello signature is verified against an
Ed25519 key the trust record must now agree with, where under v3 it need not,
because under v3 the ECDH itself was the proof. Skipping that half would make
v4 an upgrade in confidentiality and a downgrade in authentication.
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
  obvious way to shrink the outage window in Group 7 — a v4 extension that
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

**What is different this time, and it is the whole of Group 7.** In August
2026 the only consumers were the operator's own laptop MCPs and a sideloaded
extension he reloaded himself; "loudly, at the handshake" was a message he read
in his own terminal. Today the failure lands on a hosted relay, on ~20 bridged
registrations whose npm pins move on mcp-host's nightly `follow` cron, and the
message has to survive a Durable Object that dropped it until three days ago
(bridge report L10; `readEnvelope` knew five frame kinds and `hello-rejected`
was not one of them — `mcp-host/packages/core/src/bridge-frames.ts:32-38` at the
0.62.0 release commit). The relay code now carries it
(`bridge-frames.ts:63-70`, routed at `:127-136`), which moves the prerequisite
from "write it" to "deploy it" and no further: see §prerequisite in Group 7.
So v4 needs a refusal path, not only a refusal.

---

## Decisions required before Task 1.1

The first three have a default; take the default unless Chris says otherwise.
The fourth is **answered** and is recorded here as settled rather than offered.

1. **Package major.** v4 ships as `@fetchproxy/*` **3.0.0**. The off-by-one
   between package major and protocol version (package 2.x ↔ protocol 3;
   package 3.x ↔ protocol 4) persists and is a real footgun for anyone reading
   a version string as a protocol number. **Default: accept it and say so in
   `frames.ts`'s header paragraph and `CLAUDE.md`** rather than renumbering
   either; the alternative (jump the package to 4.0.0) desynchronises the
   changelog from release-please's own arithmetic for one cosmetic gain.
2. **Does the pair code change in the same break?** Bridge report **L5** —
   6 digits, `SHA256(mcpPub‖extPub)`, both inputs public and long-term, so one
   OFFLINE grind of ~10⁶ keygens produces a code that stays usable against that
   MCP identity forever. v4 mints fresh per-session values on both sides, so the
   code can commit to a transcript instead: that makes each grind online and
   per-pairing, and 8 digits raises it to ~10⁸. It does not abolish the grind —
   a party posing as the extension chooses its own side of the inputs — and
   Task 1.4 says so rather than claiming otherwise. It is a wire-visible change
   and this is the only break scheduled. **Default: YES, fold it in** —
   **Task 1.4**, which is a SECOND transcript over the values both ends hold at
   the pair prompt and not `transcriptHash` itself (that one contains the
   extension's ephemeral, which does not exist yet when the code is shown; the
   task sets out why) — because a second break to fix L5 later costs the whole
   of Group 7 again. If Chris says no, cut Task 1.4, drop the `pair-code.ts` row
   from the file map and its entry from Task 5.3's mutation list, and leave L5
   where §"What this does NOT fix" item 2 already has it.
3. **Does mcp-host raise a protocol floor for bridged spawns?** Today
   `assertSandboxableConcentrator`
   (`mcp-host/packages/runner-node/src/browser-bridge/concentrator-version.ts`,
   `SANDBOX_CONCENTRATOR_MIN = '2.2.0'`) reads the installed
   `@fetchproxy/server` version off the tree **before** the spawn and refuses,
   naming both numbers — but only on the sandboxed path, and only for the
   `FETCHPROXY_WS_HOST` reason. **Default: YES** — Group 7 step 8 raises a
   separate `BRIDGE_PROTOCOL_MIN` floor applied to **every** bridged spawn, so
   a straggler registration is refused at spawn with an actionable message
   rather than discovered by a hanging tool call. This is a guard for the
   stragglers, not for the window.
4. **Beta timing — SETTLED, 2026-09-12: ship v4 now.** The operator's answer
   is that **nothing has left his walls** — Transporter has no install base
   outside his own machines. Three things follow and the rest of this plan is
   written on them rather than around them: Group 7 needs **no** Chrome Web
   Store submission in front of it; step 6 is a single reload; and
   §"The one-installed-copy property" is a measured fact today, not an
   assumption the executing session has to re-check. What does **not** change
   is the deadline logic, which is the reason this is settled rather than
   merely convenient: every day the listing stays unsubmitted is a day this
   break stays cheap, and the answer expires the moment the beta hands the
   extension to somebody who is not Chris. So this is a gate that is now open,
   with the *other* arrangement (CWS submission first) still the only one
   available if v4 slips past that moment.

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
  answersExtNonce     // NEW: base64 raw 32B — the `sessionNonce` of the
                      //      EXTENSION hello this hello was minted against,
                      //      or 32 zero bytes for a hello that answers none
                      //      (a peer's registration hello). §1a Rule B.
  sessionSig          // WIDENED: see 2
}
```

`identityX25519Pub` stays the trust key. The extension pins
`sha256(identityX25519Pub)` (`hello.ts:238`) and the pair code commits to both
identities; nothing about pinning, trust records or re-pair prompts changes.
`sessionPub` is a new field beside the identity, not a replacement for it —
which is what keeps v4 from re-pairing the fleet the way L11 describes.

**Per EXTENSION SESSION, not per process.** Today `ownHello` and its nonce are
built once at startup (`host.ts:177-197`, `peer.ts:181-203`) and the same bytes
are sent to every extension connection for the life of the process (bridge
report I1: "the MCP hello nonce is per PROCESS … so freshness rests on the
extension's ephemeral"). A per-process MCP ephemeral would bound forward
secrecy at the process lifetime, which on mcp-host is up to ten idle minutes of
real traffic — worth having, not worth claiming as forward secrecy. **Mint a
fresh `{sessionNonce, sessionPub, sessionPriv}` each time an extension hello
arrives, then build and send the server hello from it.** The host already sends
`ownHello` on extension connect (`host.ts:372`), so the structural change is
that the hello is *built* in that handler rather than at startup, and the
private half is held beside `ownSession` and discarded with it.

**The private half must die with the session.** Forward secrecy is the property
that an identity holder cannot open a *past* session; it is false if the
process keeps every ephemeral private key it ever minted. On the host the
teardown is the extension socket's close handler (`host.ts:612-641`, which
nulls `ownSession` at `:622`); it zeroes and drops `sessionPriv` in the same
statement. Assert it. The peer's teardown is three places rather than one and
is set out in Task 2.2 — `session` there is deliberately never returned to null
(`peer.ts:236-238`, the 2.5.0 `extensionGone` comment: "`session` itself is left
in place — `sendInner` relies on it never returning to null once set"), so "the
same statement that clears `session`" is not available on that path and the
zeroing hangs off the events instead. That is a different comment from
`peer.ts:209-215`, which says `sendInner` reads `session` at call time rather
than at handshake time; Task 2.2 quotes that one for the replay repair, and the
two must not be cited at one range.

### 1a. The ephemeral's lifetime, as one invariant over every hello

The per-connection rule above is correct for the host's own hello and says
nothing about the other two ways a server hello reaches the extension — the
host's replay of a cached peer hello (`host.ts:374-376`) and its live forward of
a peer's dial hello (`:425`) — both of which break under a naive reading of it.
Two further paths are not hellos at all but `ready` frames that arrive after
the hello they answer has been superseded: one minutes later, when the user
answers a pair prompt (`approval.ts:111-165`), and one milliseconds later, when
an MV3 reconnect lands an extension hello while a peer's re-hello is still in
flight. The first needs the invariant to hold for longer; the second needs the
invariant to say what happens when it cannot. So the rule this plan holds both
ends to is stated once, over every path, and it is meant to be checked against
the code rather than believed:

> **Invariant.** Every server hello the extension can act on carries a
> `sessionPub` whose private half is held, by exactly one MCP process, from the
> moment that hello was **committed** until the extension session it was minted
> for ends — which is also the moment after which that `sessionPub` can no
> longer produce a usable `ready`. While it is held it is displaced only by a
> mint for a **later** extension session, never by one for an earlier session
> whose crypto resolved late. A hello that would not satisfy it is never
> forwarded to the extension in the first place — and, when the process learns
> before the send that it minted for a session that has since ended, never
> sent; and a `ready` that names a `sessionPub` this process no longer holds is
> **discarded**, never refused, because the hello that superseded it is already
> on its way.
>
> **And it has a LIVENESS half, which is the trigger side of the same rule:**
> one extension session draws exactly **one** SESSION-EPHEMERAL mint per MCP
> process, and every session-ephemeral mint is drawn by an extension session.
> *Session-ephemeral* is what makes the second clause true rather than nearly
> true, and the exception is named here rather than left to a later paragraph:
> a peer also mints a **bootstrap** keypair, once, in `startPeer`
> (`peer.ts:181-203`), drawn by a dial and by no extension session at all —
> the host will not map a slot for a hello whose signature it cannot verify,
> and Task 1.1 makes `sessionPub` a required field. That mint is bounded where
> it is introduced below: no key is ever derived from it, the frame carrying it
> says on the wire that it answers nothing so Rule B will not forward it, and
> the first Rule A mint that commits zeroes it. Without the liveness half the
> safety half above is satisfied by a process that mints forever: every hello
> it sends names the live session, every mint it commits is the current one,
> nothing is ever stale — and no session ever opens.

Four rules produce it, and each is a change to existing code rather than a
restatement. **Committed**, rather than *minted*, is the load-bearing word, and
Rule D is where it is cashed: the v4 mint is an interval and not a step, so
what a process does across that interval is the difference between this
invariant and a plausible-sounding claim about it.

- **Rule A — mint on an extension hello, never otherwise.** The host mints in
  the extension-hello handler (`host.ts:289`) and sends at `:372`. The peer
  mints when the *relayed* extension hello arrives (`peer.ts:349-351`) and
  sends a fresh server hello in the same handler. Nothing else mints a session
  ephemeral, and nothing reuses one across two extension sessions.

  **Which frames are TRIGGERS is as load-bearing as what a mint does, because
  the peer's trigger arrives from the host and the peer's answer goes straight
  back to it** — so a trigger the host re-sends in answer to that answer is a
  loop, and Rule B's mirror (below) is what forbids it. The host relays an
  extension hello to a peer in exactly two places. This is the trigger side of
  the table further down, and a path added later owes a row here too:

  | Frame reaching a peer | A mint trigger? | Why |
  |---|---|---|
  | the extension hello fanned out on extension connect (`host.ts:370`) | **yes** | one per extension session, to every peer in the map at that moment |
  | the cached extension hello at the tail of the peer-hello branch (`host.ts:428`) | **yes — and only in answer to a REGISTRATION hello**, per Rule B's mirror | it is how a peer that registered *after* that fan-out learns an extension is attached at all; un-gated it also answers the peer's own re-hello, which is the livelock |
  | `extension-disconnected` (`peer.ts:356-363`) | no | it ends a session: it zeroes, it does not mint |
  | a `ready` on either path | no | Rule C's subject — it names an ephemeral rather than asking for one |
- **Rule B — the host forwards a server hello to the extension only when the
  hello NAMES the current extension session.** The gate is
  `extensionHello !== null && frame.answersExtNonce === extensionHello.sessionNonce`
  — a fixed 32-byte comparison, with no branch for an absent field: a hello
  that answers no extension session carries 32 zero bytes, and a nonce minted
  from a CSPRNG is not that value. Two sends fail it and both are wrong under
  v4 for the same reason: `host.ts:374-376` replays each peer's *cached* hello to
  a newly connected extension, and `:425` forwards a peer's *registration* hello
  straight to an already-connected extension. In both cases the `sessionPub` on
  the wire is one Rule A is about to supersede.

  **The gate is on the FRAME, never on the slot, and that is the whole of it.**
  An earlier draft of this section gated `:425` on a mark recorded per peer —
  `slot.toldOfExtension === extensionHello` — and that is unsound twice over,
  both times because the mark is the slot's *latest* state rather than the
  frame's provenance:

  1. **It is read after the await it would have to survive.** The peer-hello
     branch awaits `ed25519Verify` at `host.ts:395` before it reaches
     `peers.set` at `:424` and the forward at `:425`; the extension-hello
     branch awaits `extensionTrust.read()` at `:308`, installs the new
     `extensionWs`/`extensionHello` at `:350-351`, and then at `:370`
     re-points the mark for **every** peer already in the map. So: peer P is
     told of extension session E1 and re-hellos; the host's handler for that
     hello suspends at `:395`; E1's socket closes (`:618` nulls
     `extensionHello`, `:635-639` sends `extension-disconnected`, which zeroes
     P's ephemeral at `peer.ts:356-363`); E2 connects and its handler runs to
     completion, so `host.ts:370` sets P's mark to E2's hello; the suspended handler
     resumes, `:424` writes the slot, and the mark now matches at `:425` — so
     the hello minted for E1 is forwarded to E2. All four steps are ordinary — the code treats MV3
     reconnects as routine — and the frame gate cannot be fooled by the
     interleaving because it compares the frame's own echo, not a mark
     something else moved.
  2. **A captured mark is only a proxy, and the proxy leaks.** Capturing the
     mark synchronously at frame arrival (the `host.ts:294-300` pattern) fixes
     case 1 but still stands in for "which extension session this hello was
     minted against". That proxy holds only while a peer never has two mints
     in flight, and it can: `peer.ts`'s `onMessage` is `async` and
     unserialised, and the v4 mint awaits `generateX25519` and `ed25519Sign`,
     so E1's relayed hello can suspend mid-mint, E2's arrive and complete, and
     E1's hello be sent *after* E2's. Both then arrive at a host whose mark is
     E2, and the stale one passes a captured gate too.

  That second fact is spent twice in this section, and the halves are not the
  same repair. Here it says the gate must read the frame. It also says the late
  mint **overwrites the minting process's own current ephemeral** — which no
  gate at the host can touch, because by then the damage is a variable in
  another process rather than a frame on a wire. Rule D below is that half.

  So the echo goes on the wire (§1 and §2): each server hello carries the
  `sessionNonce` of the extension hello it was minted against, inside the
  signed payload. The gate needs no per-slot state, nothing to clear on a
  reconnect, and nothing to carry across a slot overwrite — a reconnecting
  extension has a new nonce, so every hello minted against the old one stops
  matching by arithmetic.

  **The same FIELD gates the other direction, with the test inverted, and
  without it every peer session establishment livelocks.** `host.ts:428` —
  `if (extensionHello) ws.send(JSON.stringify(extensionHello));` — sends the
  cached extension hello at the tail of the peer-hello branch
  UNCONDITIONALLY: on every peer hello, on the same socket, with no first-time
  gate (the squat guard at `:411-420` fires only when `existing.ws !== ws`, and
  `:424` simply overwrites the slot). It is a Rule A trigger, so a peer's Rule
  A re-hello draws another one:

  > registration hello → `:425` withholds it (Rule B) → `:428` sends E's hello
  > → peer mints and re-hellos → `:425` now forwards it (the re-hello echoes
  > E's live nonce, so Rule B passes) → `:428` sends E's hello **again** → peer
  > mints and re-hellos → unbounded.

  Nothing already written stops it. Rule B passes every iteration, because each
  re-hello legitimately answers the live extension session. Rule D commits
  every iteration, because `extensionHello === frame` compares against the
  freshly parsed frame the handler was entered with. Rule C is downstream of a
  session that never settles. And this is not an exotic path — the same loop
  runs off `:370` on an ordinary MV3 reconnect, so under the rules as first
  drafted **every** peer session establishment on **both** trigger paths spins,
  and whether a session opens at all depends on the loop pausing long enough
  for a `ready` to reach the pub the peer last committed. Each turn costs an
  X25519 keygen and an Ed25519 sign on the peer, a verify on the host, and a
  full `onServerHello` — bind, ECDH, HKDF, ready — on the extension. It also
  makes two things this document already asserts unsatisfiable rather than
  merely unproven: Task 2.2's dial-path test asserting the extension "then
  receives **exactly one** server hello for it", and the `:425` row of the
  table below, which describes one mint per extension session.

  **The fix taken is Rule B mirrored onto `:428`: hand a peer the cached
  extension hello only in answer to a hello that answers NO extension session**
  — `answersExtNonce` all zero, i.e. a registration hello, tested through
  `answersNoExtSession`, the one predicate Task 1.1 exports for the fact,
  rather than a literal spelled out here and again where the peer writes it.
  Those two are the fact's whole population in shipped code — this gate reads
  it and the bootstrap hello writes it — and Task 1.1 says why the two places
  that look like further readers are not: Rule B's own gate at `:425` compares
  against the live nonce and takes no branch on this value, and Rule C's
  refusal is a comparison against the extension's own nonce that the zero value
  fails anyway. `:370` already
  covers every new extension session for every peer in the map, so nothing else
  needs the re-send. The predicate is the complement of the one above rather
  than a copy of it, which is the point: a hello that answers the current
  session goes ON to the extension and draws nothing back, and a hello that
  answers nothing goes nowhere and draws the extension hello back. And this
  half is one degree cleaner than its mirror: it reads the frame and **no
  authoritative variable at all**, so there is no await window of the kind case
  1 is about and nothing is recorded per peer. Termination and liveness both
  follow from the two relays being mutually exclusive per (peer, extension
  session):

  - a peer already in the map when an extension connects is triggered once by
    `:370`, and its re-hello answers that session's nonce, so `:428` is silent
    for it;
  - a peer that registers *after* that fan-out is not in the map for `:370` —
    its handler may be suspended at the `await ed25519Verify` on `:395` — and is
    triggered once by `:428`, which reads the CURRENT `extensionHello`. That is
    the job this send still has to do, and the reason the answer is a gate
    rather than a deletion;
  - a peer that registers with no extension attached is triggered by neither,
    and by `:370` when one connects.

  **The alternative, and why it is not taken.** The loop can also be cut at the
  peer: mint only when the arriving relayed hello's `sessionNonce` differs from
  the `answersExtNonce` of the ephemeral this peer has currently **committed**
  (committed, so it composes with Rule D rather than reading an in-flight mint
  whose own commit may lose). That terminates too, and it is robust to a relay
  that duplicates a frame, which the host-side gate is not — under the gate, a
  duplicated extension hello costs a redundant mint and a redundant server
  hello, the extension binding the last and Rule C discarding the `ready` for
  the first: a degradation, never a loop, because the chain is cut where the
  frames are produced. It is declined because it asks the peer to carry, across
  Rule D's interval, a second fact about which session its ephemeral answers,
  and that interval is where this design has already been wrong twice. If a
  duplicating relay ever becomes real it is the repair to reach for, and it
  composes with this gate rather than replacing it.
- **Rule C — the extension refuses a hello that answers a nonce it did not
  send, and the MCP discards a `ready` for an ephemeral it no longer holds.**
  Rule B is the host's gate, and a gate that fails open must not be the only
  thing standing. So the rule is enforced at both ends, by the party each
  failure lands on:

  - **Extension side.** `onServerHello` holds the link and its nonce already
    (`server-hello.ts:89-90`, which returns early on `!link.sessionNonce`), so
    it refuses a hello whose `answersExtNonce` is not `link.sessionNonce`
    **before** `bindMcpToLink` at `:94` — no binding, no trust read, no pair
    prompt, and the existing `tellServerWhy` path carries the reason. A hello
    that answers 32 zero bytes is refused here too, and by that same
    comparison rather than by a second check: on the wire that is a
    registration hello, `link.sessionNonce` comes from a CSPRNG and is never
    the zero value, so "answers nothing" fails the equality like any other
    wrong answer — which is why Task 1.1 counts this as no reader of
    `answersNoExtSession`.
  - **MCP side.** The `ready` now carries `mcpSessionPub` explicitly (§2
    already signs it), and both server paths compare it to the ephemeral they
    currently hold **before** verifying the signature. Equal → verify as
    today, and an invalid signature keeps today's refusal (`host.ts:470-476`
    closes 1008; `peer.ts:374-381` closes 1008 and calls `rejectFirstReady`).
    Not equal → **discard**: log it, change nothing, close nothing, reject
    nothing. That distinction is the point — today a stale `ready` and a
    forged one are the same 1008, so an ordinary extension reconnect that
    raced a re-hello would strand a bridged MCP on `rejectFirstReady`. The
    mismatch branch is reached before any signature has been checked, so
    anything that can put a frame on the socket can reach it; it must
    therefore cost nothing and change nothing. A relay that rewrites a genuine
    echo turns that `ready` into a discarded one, which is a capability it
    already has by dropping the frame.
- **Rule D — a mint is installed only if it is still the current one.** Rules A
  to C all say "the ephemeral this process currently holds" as though minting
  and installing were one step. They are not. The v4 mint awaits
  `generateX25519` and `ed25519Sign`, which is the interleaving case 2 above
  already proves — seen now from inside the process that mints rather than from
  the host that forwards. So a mint does all of its crypto into **locals** and
  then **commits** — installs `{nonce, pub, priv}` and sends the hello — at one
  **synchronous** point, which first re-reads the single authoritative variable
  naming the extension session the mint was for:

  - **Host** (the extension-hello handler, `host.ts:289`): `extensionWs === ws`.
    The idiom is already in this file for this exact window — `host.ts:508`,
    `if (extensionWs !== ws) return;`, placed after the ECDH and HKDF awaits so
    a close during derivation cannot resolve the session promise with a stale
    key. Rule D is that guard moved one handshake earlier, to the mint.
  - **Peer** (the relayed-extension-hello handler, `peer.ts:349-351`):
    `extensionHello === frame`, the triggering frame the handler is already
    holding. Free — nothing to record, nothing to look up, and nothing to clear.

  A mint that fails its own check **zeroes the private half it just minted,
  installs nothing and sends nothing.** It loses to the newer mint rather than
  displacing it; without the check the two are ordered by whichever crypto call
  returned first, and each path then fails as follows.

  - **Host.** E1's handler suspends inside the mint. E1's socket closes, and its
    close handler runs to completion (`host.ts:612-641`: `:615` releases
    `extensionClaim`, `:617` nulls `extensionWs`, `:618` nulls `extensionHello`,
    `:620` rejects the pending promise, `:622` nulls `ownSession` and `:630`
    resets the promise — and Task 2.1's zeroing takes whatever was installed
    **before** mint 1, which on a first connection is nothing at all, because
    mint 1 has not landed). The `:290-291` "extension
    already connected" guard is now open, so E2 connects and its own mint
    commits. Mint 1 then resumes, overwrites `{nonce, pub, priv}` with E1's and
    sends a hello down a closed socket. The extension derived against pub2 and
    its `ready` names pub2; Rule C compares against pub1 and **discards** it.
    The `ownSessionReady` that `:630` just created (`host.ts:213`, reset at
    `:215-222`) stays pending, nothing closes 1008, and nothing re-mints:
    the only trigger is an extension hello and E2 has already sent its. Also,
    E1's private half is never zeroed again for the life of the process — the
    forward secrecy this group exists to buy, lost on the ordinary path.
  - **Peer.** The same shape, one relay further out. Handler 1 (E1's relayed
    hello) suspends in the mint; `extension-disconnected` arrives and zeroes the
    previous half (`peer.ts:356-363`); E2's relayed hello arrives, handler 2
    commits kp2 and sends the hello Rule B forwards; handler 1 resumes and
    installs kp1 over kp2. Rule C then discards the extension's legitimate
    `ready` for pub2, and nothing re-triggers a mint — this peer's only triggers
    are a relayed extension hello (`peer.ts:349`) and none is coming, since the
    extension is attached and has already answered. Today `peer.ts:374-381` at
    least closes 1008 and rejects `rejectFirstReady`; without Rule D, v4 is
    **silence** until the next extension flap. Two handlers can be in flight at
    all because `onMessage` is `async` (`peer.ts:342`) and is registered as
    `ws.on('message', onMessage)` (`:501`), whose returned promise nothing
    awaits.

  Rule D is therefore what lets Rule C be a discard without being a trap: a
  discard is right exactly when a superseding hello is already on its way, and
  Rule D is what makes "superseding" mean *the mint that committed last* rather
  than *the crypto call that returned last*. Deleting Rule D does not reopen a
  1008; it converts a loud failure into a hang, which is why Task 5.3 mutates
  it and why both server task test lists carry the interleaving as a case of
  their own.

**The bootstrap mint, which Rule A does not cover and the wire requires.** A
peer cannot wait for an extension hello before it hellos: the host's
`hello/server` dispatch is what *registers* the peer
(`peers.set(frame.mcpId, …)`, `host.ts:424`), and the host relays the extension
hello only to peers already in that map (`:370`) — so a peer that sends no
hello at dial is never told an extension exists and never gets a Rule A
trigger. That registration hello must therefore carry a `sessionPub`, because
Task 1.1 makes the field required and because the host verifies the hello's
signature over
`helloSignaturePayload(mcpId, sessionNonce, sessionPub, answersExtNonce)`
before it will map the slot (`host.ts:387-404`). So `startPeer` mints a
**bootstrap** keypair for it, and sets `answersExtNonce` to 32 zero bytes: at
dial the peer has been told of no extension session, and saying so is what
makes the frame self-describing rather than merely un-forwarded by convention.
The bootstrap keypair is a registration credential and never a session
ephemeral: no key is ever derived from it, and what makes that a fact rather
than an intention is Rule B — the frame says it answers nothing, so the host's
gate refuses to forward it and the extension's own check would refuse it if the
gate ever failed open, and therefore no `ready` can ever name it. Its private
half is zeroed at the first Rule A mint **that commits**, or at the peer
socket's close if none ever does — a mint that loses Rule D's check zeroes only
its own half, so the bootstrap survives it and dies to the mint that won.

**Every hello the extension can receive, and which ephemeral the `ready` it
sends back corresponds to.** This table is the reviewable form of the
invariant; a path added later owes a row.

| Hello the extension acts on | Minted | `ready` sent from | Corresponds to | Live at that moment because |
|---|---|---|---|---|
| the host's own hello (`host.ts:372`) | the extension-hello handler (Rule A), committed under Rule D while `extensionWs === ws` — **not** same-tick: the mint awaits | `server-hello.ts:148`, immediately (auto-trust) | that mint | the commit is what makes it current, and from there it is zeroed only by the extension socket's close handler (`host.ts:612-641`), which *is* the end of this extension session. A mint for an EARLIER session resolving late cannot displace it: Rule D makes it zero its own half instead |
| the host's own hello, needs-pair → the user clicks approve minutes later | as above | `approval.ts:163` | that same mint | the approval path skips an mcpId with no live link (`approval.ts:127-130`), and for the HOST's own mcpId that link IS the extension's socket to this host — so the thing the guard reads dies exactly when the mint is zeroed. Not true of a peer's mcpId; see the residual below |
| a peer's Rule A hello, forwarded by the host (`host.ts:425`, the hello answering the current extension nonce) | the relayed-extension-hello handler (`peer.ts:349-351`), ONCE per extension session — Rule B's mirror on `host.ts:428` is what makes it once — committed under Rule D while `extensionHello` is still that frame | `server-hello.ts:148` or `approval.ts:163` | that mint | it is zeroed on `extension-disconnected` (`peer.ts:356-363`), or displaced by a LATER session mint at its commit point — never by an earlier one resolving late, which Rule D makes zero its own half. Those are the events that end this extension session; a `ready` arriving after one of them names a superseded `sessionPub` and is discarded by Rule C, not refused |
| a peer's **registration** hello | `startPeer` (bootstrap) | — | nothing | it says so on the wire (`answersExtNonce` = 32 zero bytes), so Rule B will not forward it and Rule C's extension-side check would refuse it anyway; no `ready` can name it |
| a peer's cached hello, replayed to a newly connected extension (`host.ts:374-376`) | — | — | — | **path removed** by Task 2.2 |

Zeroing at the peer's own socket close (`peer.ts:507-513`) is on that list in
Task 2.2 and deliberately **not** in this table's last column. It is a teardown
obligation — this process is leaving and must not keep a private half it can no
longer use — and not one of the moments that ends an extension session: the
socket it closes is the peer's link to the *host*, and the extension's link to
the concentrator is untouched by it. Saying otherwise was the table's own
justification being wrong on a path the table exists to make checkable.

**The one residual, stated because the guard the approval row leans on cannot
see it.** `approval.ts:127-130` reads `linkForMcp(mcpId)`, which is
`mcpLink.get(mcpId)` (`links.ts:98-99`) — the link the mcpId hello'd on, i.e.
the concentrator socket, shared by the host's own mcpId and every peer's. For a
peer's mcpId that guard therefore **passes while the peer is gone**: the user
approves minutes later, the extension derives against an ephemeral whose
private half died with the peer, sends a `ready`, and the host drops it at
`host.ts:516-517` (`peers.get(mcpId)` is empty). The extension is left holding
a session key in `state.sessions` for a dead MCP — unusable, since nobody holds
the other half, and overwritten by that mcpId's next successful handshake
(`approval.ts:143`). Accepted, with the reason: the peer that would have to
repair it does not exist any more. What Rule C repairs is the neighbouring case
— the peer is alive but has re-minted since the prompt — which was the same
1008 as a forgery and is now a discard.

The cost is one round trip before a peer's session opens — the peer hellos
again once it hears about the extension — which it already pays waiting for
`ready`. What it buys is that the sequence has exactly one shape on every path:
extension hello → server hello → `ready`, with no cached frame and no
superseded key anywhere in it.

### 2. Both signatures cover both ephemerals

```
helloSignaturePayload(mcpId, sessionNonce, sessionPub, answersExtNonce)
  = utf8(mcpId) ‖ sessionNonce ‖ sessionPub ‖ answersExtNonce
  signed with the MCP's long-term Ed25519 key      (v3: mcpId ‖ sessionNonce)

readySignaturePayload(mcpNonce, extNonce, extSessionPub, mcpSessionPub)
  = mcpNonce ‖ extNonce ‖ extSessionPub ‖ mcpSessionPub
  signed with the extension's long-term Ed25519 key (v3: without mcpSessionPub)
```

`answersExtNonce` is **always 32 bytes** — the extension hello's nonce, or 32
zero bytes when the hello answers no extension session. Fixed-shape rather than
optional, so "answers nothing" is a *value* in the signed payload and not an
absence of bytes: with `sessionNonce` and `sessionPub` fixed at 32 each and
`mcpId` variable at the front, an omitted trailing field would make two
different (mcpId, answers) pairs concatenate to the same message. It is signed
because Rule B's gate reads it: an unsigned echo is one a relay re-points at
whichever extension session it wants the hello delivered to.

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

**But a signature is worth only what its verifier pins, and today the extension
pins the wrong half.** Under v3 the extension derives against
`identityX25519Pub` — the very key its trust record is keyed on
(`sha256(identityX25519Pub)`, `hello.ts:237-238`) — so *completing* a session is
itself a proof that the far end holds the pinned private key. The hello
signature is belt-and-braces on top of that, which is why `hello.ts:261-272`
can get away
with never comparing `record.identityEd25519Pub` against
`hello.identityEd25519Pub`: a party that swapped the signing key still could
not compute the session key. That is **L6**, and under v3 it is the harmless
finding an earlier draft of this plan filed it as.

**v4 inverts it.** The session key now comes from `sessionPub`, and the only
thing binding `sessionPub` to a trusted identity is a signature under
`identityEd25519Pub` — the half nothing checks. So under v4, with L6 still
open, an attacker holding nothing but **public** values impersonates any
trusted MCP:

1. copy `identityX25519Pub` out of any recorded hello — it is plaintext on the
   wire by construction, and on mcp-host the hosted relay sees every one;
2. present it alongside an `identityEd25519Pub` and a `sessionPub` of their own;
3. sign `helloSignaturePayload(mcpId, sessionNonce, sessionPub, answersExtNonce)`
   with their own
   Ed25519 key — the extension verifies the signature against the key carried
   in the *same frame*, so it is self-consistent and passes (and it can echo
   the extension's own nonce, which is on the wire in front of it, so Rule C's
   extension-side check does not stand in the way either — that check is about
   staleness, never about identity);
4. the trust lookup on `sha256(identityX25519Pub)` hits the genuine record and
   **auto-trusts**, with no pair prompt and no re-pair diff;
5. the extension derives the session key against the attacker's ephemeral.

The implicit proof of possession that v3 got for free from the ECDH has to be
bought back explicitly, or **v4 is an upgrade in confidentiality and a
downgrade in authentication** — a strictly worse trade than not shipping it. So
L6 is not deferred to a later release: it is **Task 3.3**, and it ships inside
this break because this break is what makes it exploitable.

The other direction needs nothing, and the asymmetry is worth stating so no
reviewer asks for a symmetric change that already exists. The MCP has never had
implicit proof of possession of the *extension's* identity — the extension's
contribution has been an ephemeral since 0.4.0 — so it already buys the proof
explicitly, and `decideExtensionTrust` (`server/src/extension-trust.ts`)
already compares **both** pinned keys, with the reason in its own comment:
"Both keys, not either: a rotation of one is a different extension, and
accepting a half-match would let an attacker keep the ECDH key it needs while
swapping the signing key it doesn't hold, or the reverse." That is exactly the
sentence the extension's trust match is missing. v4 makes the MCP's rule true
of both ends.

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

`transcriptHash()` is exported because the host, the peer and both extension
derivation paths compute it — four call sites for one fact, which is this
section's opening rule. It is **not** what the pair code is derived from: that
needs values both ends hold before any `ready` exists, and Task 1.4 defines a
separate `pairTranscript` for it.

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
`MAX_FRAME_BYTES` derivation are untouched, and Task 1.2 asserts that so nobody
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
two consumers are the two refusal paths. It is the `readEnvelope`
rebuild-member-by-member pattern, and Task 1.3's test asserts the "grants
nothing" half by construction.

---

## File map

| Action | Path | Why |
|---|---|---|
| Modify | `packages/protocol/src/frames.ts` | `PROTOCOL_VERSION` 4, `HKDF_SESSION_INFO`, `sessionPub` + `answersExtNonce` on the server hello, `ANSWERS_NO_EXT_SESSION` + `answersNoExtSession`, `mcpSessionPub` on the ready, `helloSignaturePayload`, widened `readySignaturePayload`, `transcriptHash`, `frameAad`, `Direction`, the standing v4 paragraph in the header |
| Modify | `packages/protocol/src/validate.ts` | require `sessionPub`, `answersExtNonce` and the ready's `mcpSessionPub`; `peekHelloVersion` |
| Modify | `packages/protocol/src/crypto.ts` | `aesGcmSeal`/`aesGcmOpen` take `aad` |
| Modify | `packages/protocol/src/seal.ts` | `direction` required on seal/open; AAD threaded; `sealedFrameWireBytes` unchanged |
| Modify | `packages/protocol/src/pair-code.ts` | decision 2 / Task 1.4 only — one exported `pairTranscript`-based derivation, 8 digits, `derivePairCodeFromIds` deleted |
| Modify | `packages/server/src/build-server-hello.ts` | mint/accept the ephemeral, sign `helloSignaturePayload` |
| Modify | `packages/server/src/host.ts` | per-connection hello, ephemeral derivation, widened ready verify, AAD, v3 extension refusal, zeroing on teardown |
| Modify | `packages/server/src/peer.ts` | the same on the peer path |
| Modify | `packages/server/src/frame-size.ts` | seal/measure signature follow-through |
| Modify | `packages/extension-core/src/background/hello.ts` | verify the widened hello signature; derive against `sessionPub`; match the pinned `identityEd25519Pub` too (L6, Task 3.3) |
| Modify | `packages/extension-core/src/background/approval.ts` | the same on the approval path, from the stored `sessionPubs` (Task 3.1) |
| Modify | `packages/extension-core/src/background/pending-records.ts` | `sessionPubs` on `PendingPairRecord`, refreshed per `mcpId` like `sessionNonces` |
| Modify | `packages/extension-core/src/background/server-hello.ts` | sign the widened ready payload; carry `mcpSessionPub` on it; refuse a hello whose `answersExtNonce` is not this link's nonce, before the mcpId binding (§1a Rule C) |
| Modify | `packages/extension-core/src/background/socket.ts` | AAD on open; the v3-server refusal path |
| Modify | `packages/extension-core/src/background/send-inner.ts` | AAD on seal |
| Modify | `packages/extension-core/src/popup/popup.ts` | a protocol-mismatch line on the link |
| Modify | `packages/cli/src/bridge-errors.ts` | map the mismatch reason to a remedy |
| Modify | `packages/test-helpers/src/index.ts` | mock signature follow-through |
| Create | `packages/server/tests/cross-version/` | frozen v3 fixtures + the refusal suite (Tasks 5.1 and 5.2) |
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
Test — `packages/protocol/tests/frames.test.ts`, a NEW file and deliberately so:
the protocol package has no home for payload-function facts today (`grep -rln
readySignaturePayload packages/protocol/tests` finds none), and the existing
suites are named for what they cover (`seal`, `validate`, `crypto`,
`pair-code`). Write it first: `PROTOCOL_VERSION === 4`;
`helloSignaturePayload` is the exact concatenation and changes with each of its
**four** inputs; `readySignaturePayload` takes four arguments and changes with
each; `transcriptHash` changes with each of its four; `HKDF_SESSION_INFO` is
`'fetchproxy/4.0.0/session'`. In `validate.test.ts`: a hello with
`protocolVersion: 3` is **refused**, not downgraded (the #222 assertion, moved
one version along); a server hello missing `sessionPub` or `answersExtNonce` is
refused; either field not 32 raw base64 bytes is refused; a ready missing
`mcpSessionPub` is refused, and so is one whose `mcpSessionPub` is not 32 raw
base64 bytes.
Do: implement. Keep each payload function a single concatenation with a doc
comment saying which version widened it, in the style `frames.ts:50-57` already
uses. `answersExtNonce` and `mcpSessionPub` are both required, fixed-length
fields — §2 says why the first is 32 zero bytes rather than absent when a hello
answers no extension session, and that reason belongs in its doc comment.
Export the "answers nothing" value and its test **once**, as
`ANSWERS_NO_EXT_SESSION` plus `answersNoExtSession(b64)`, per the wire
section's one-function-per-fact rule. The shipped population is small enough to
state exactly, and worth stating because two of the places that look like
readers are not: **one place writes the value** — the peer's bootstrap hello
(§1a) — and **one place reads it**, Rule B's mirror on `host.ts:428`
(Task 2.2). Rule B's own gate at `host.ts:425` is
`frame.answersExtNonce === extensionHello.sessionNonce`, a fixed comparison
against the live nonce that takes no branch on this value and which §1a
forbids taking one; and Rule C's extension-side refusal (Task 3.1) is
`answersExtNonce !== link.sessionNonce`, which the zero value fails without a
second call, because `link.sessionNonce` comes from a CSPRNG and is never that
value. So the export exists for the writer, that one reader, and the vectors
below — a value that crosses a wire and is asserted in two suites is exactly
what this rule says to name once, and a literal spelled at both ends of it is
the drift the rule exists to prevent. Its assertions go in `frames.test.ts` beside the payload
facts: the constant is 32 zero bytes, the predicate is true of exactly that
value and false of a hundred CSPRNG nonces, and (in `validate.test.ts`) a hello
carrying the zero value VALIDATES — it is a registration hello, not a malformed
one.

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

**Task 1.4 — the pair code (decision 2; cut this task if the answer is no).**
Where: `packages/protocol/src/pair-code.ts`, `frames.ts:472` (the `pairCode`
field's `// formatted "XXX-XXX"` comment), `packages/server/src/host.ts:358`
(the `onPairCode` derivation) and
`packages/extension-core/src/background/hello.ts:369-373` (the needs-pair
derivation). Those last two are the only producers — the peer path self-derives
nothing and reads the relay's number instead, which is M1 and stays out of this
break.

**It cannot be `transcriptHash` itself, and that is the part decision 2 got
wrong.** The session transcript (§3) contains `extSessionPub`, which arrives in
the `ready`; the pair code has to be shown at the pair *prompt*, before any
`ready` exists. The extension has no ephemeral of its own yet at
`hello.ts:369-373` (the auto-trust path mints one at `hello.ts:303`, the
approval path at `approval.ts:135` — both after this point), and the host
derives at `host.ts:358` the moment
the extension hello lands, with no `ready` in hand either. So this is a SECOND,
separate function over the values both ends do hold at the prompt:

```
pairTranscript(mcpIdentityX25519Pub, extIdentityX25519Pub,
               mcpNonce, extNonce, mcpSessionPub)
  = SHA256(utf8('fetchproxy/4/pair') ‖ NUL ‖ mcpIdentityX25519Pub
           ‖ extIdentityX25519Pub ‖ mcpNonce ‖ extNonce ‖ mcpSessionPub)

code = first 8 bytes as a big-endian integer, mod 100_000_000 → "XXXX-XXXX"
```

Eight bytes read as a BigInt rather than the existing `uint32` (`pair-code.ts`
reads `h[0..3]`): `2**32 % 10**8` leaves a 2.4% skew across the digit space,
which is sloppy in a SAS and free to avoid; from 64 bits the bias is ~5e-12.
The domain label and the NUL are the `frameAad` convention, for the same
reason.

**What it buys, stated honestly, because decision 2 overclaims it.** It does
**not** "remove the grind entirely". A MITM posing as the extension chooses its
own identity, its own nonce and its own ephemeral, so it can always grind its
side against a target code; what the two changes do is (a) make that grind
ONLINE and per-session — under v3 both inputs are long-term and public, so one
offline grind against a given MCP identity is reusable against that MCP
forever, while a transcript containing both fresh nonces and the MCP's
ephemeral makes each pairing attempt its own puzzle inside the pairing
window — and (b) raise the online cost from ~10⁶ to ~10⁸ hashes. Say exactly
that in the doc comment and in Task 6.2; "removes the grind" is the sentence a
future reader would rely on.

Test (`packages/protocol/tests/pair-code.test.ts`, first): the code is
`/^\d{4}-\d{4}$/`; it changes when **each** of the five inputs changes, one
assertion apiece; the byte encoding is exact against a hard-coded vector; both
orders are fixed (MCP's identity before the extension's, MCP's nonce before the
extension's) and swapping either pair yields a different code — the
`derivePairCodeFromIds` doc comment already warns that both sides must agree on
the order, and five inputs is four more chances to disagree.

**That file is rewritten, not extended, and every one of its eleven `it`
blocks needs an answer** (counted with `grep -c "^\s*it(" \
packages/protocol/tests/pair-code.test.ts`, which is eleven, one `expect`
apiece) — leaving them to an executing agent's judgement is how a
"format assertion moved" turns into three known-answer vectors quietly
regenerated against the new reduction, which is the one thing a known-answer
vector must never be. Row by row, plus the comment that pins the reduction:

| `pair-code.test.ts` today | What happens to it |
|---|---|
| `:5-9` `produces XXX-XXX format` (`^\d{3}-\d{3}$`, `:8`) | becomes the `^\d{4}-\d{4}$` assertion over `pairTranscript`'s output |
| `:11-16` deterministic for the same input | kept, restated over the five inputs |
| `:18-22` different inputs → different codes | subsumed by the five one-input-apiece assertions |
| `:24-29` comment pinning "first 4 bytes of SHA-256(pub) → big-endian uint32 → mod 1_000_000 → XXX-XXX" | rewritten to pin the 8-byte BigInt reduction, keeping the *reason* (a refactor that moves the hash, the endianness or the width must fail here, not at pair time) |
| `:30-33` known answer `123-181` (all-zero pub) | **deleted.** Its input is a single pub, which `pairTranscript` has no argument for, and a new vector is hard-coded in its place from the five-input encoding |
| `:35-42` known answer `848-182`, the `>>> 0` high-bit regression | **deleted, and this one is a deliberate loss of coverage.** Its whole subject is the signed/unsigned slip in a 32-bit read, and reading 8 bytes as a `BigInt` removes the read that could slip. Say so in the replacement file's comment, so the next reader does not restore a test for a hazard the code no longer has |
| `:44-49` known answer `425-966` (1..32 pub) | **deleted**, same reason as `:30-33` |
| `:51-92` `describe('derivePairCodeFromIds (mutual auth)')` — 5 assertions, including `:60-66`'s `^\d{3}-\d{3}$` and `:85-91`'s "differs from single-arg `derivePairCode`" | **deleted whole.** Both functions it exercises are gone; `:85-91` in particular compares two exports that no longer exist. Its order-sensitivity and MITM-detection intent carry over into the five-input assertions above |

Do: export ONE function, per this section's opening rule. **Delete both v3
entry points**, not just the wrapper: `derivePairCodeFromIds`
(`pair-code.ts:42-47`) is a two-line wrapper over `derivePairCode`
(`:17-29`), and `derivePairCode` **is** the v3 derivation — SHA-256 →
`h[0..3]` → uint32 → mod 1e6 → `XXX-XXX` — exported and reaching the published
package's public API through `export * from './pair-code.js'`
(`protocol/src/index.ts:12`). Deleting only the wrapper would leave the thing
"nothing may keep the v3 derivation reachable" is about. So: `pairTranscript`
is the only export, and the digit reduction becomes a module-private helper
rather than a second entry point.
Thread the extension's own nonce into `handleServerHello` as a new `deps`
member — it is `link.sessionNonce` in `server-hello.ts` and the pure function
does not receive it today, which is why this is a signature change rather than
a body change. (Rule C's extension-side check needs the same value and does
**not** depend on this task: it lives in `onServerHello`, which holds `link`
already, so cutting Task 1.4 does not cut Rule C.)

Then the surfaces outside the protocol source, all of which state the old
format and none of which the earlier draft of this task named. Format
assertions: `packages/extension-core/tests/multi-link.test.ts:432`, `:470` and
`:608` (that last one is `^[A-Z0-9]{3}-[A-Z0-9]{3}$`, a wider charset than the
other two — widen the *count*, not the charset). The popup's `.pair-code`
element must still fit nine characters (`popup.ts:880`) — the string is
rendered verbatim, so that is a CSS check, not a code one. Prose and comments,
each with the task that owns it:

| Surface | States | Owner |
|---|---|---|
| `packages/protocol/README.md:26` | names `derivePairCode`, `derivePairCodeFromIds`, "6-digit", `SHA256[0..3] mod 1_000_000`, `XXX-XXX` — i.e. two functions this task deletes | **this task** |
| `packages/protocol/src/frames.ts:455-457` | "the same 6-digit joint pair code", the joint derivation spelled out, and "formatted `XXX-XXX`" | **this task** (the earlier draft named only the inline `:472` comment) |
| `packages/protocol/src/frames.ts:472` | `// formatted "XXX-XXX"` | **this task** |
| `packages/extension-core/src/background/server-hello.ts:300`, `packages/server/src/ws-server.ts:1663`, `packages/extension-core/tests/multi-link.test.ts:414` | comments reading "the same XXX-XXX the popup is displaying" | **this task** — comments, so one sed, but they are the sentences a reader trusts |
| `CLAUDE.md:78-80` (§Security model summary item **3**) | the derivation (`:78`) and `XXX-XXX` (`:79`) | **Task 6.4**, which named only "items 2 and 3b" and is corrected below |
| `docs/SECURITY.md:65` | "The 6-digit pair code (SAS …) is `SHA256(identityX25519Pub)[0..3] mod 1_000_000` formatted as `XXX-XXX`" — and note it states the *single-pub* v3 derivation, which has not been the shipped one since 0.4.0 | **Task 6.3** |
| `docs/PROTOCOL.md:418-419` | `mod 1_000_000` / `formatted "XXX-XXX"` | **Task 6.2** |
| `README.md:44`, `packages/cli/README.md:37`, `packages/extension-chrome/README.md:79` | "6-digit" in the pair-flow walkthrough | **Task 6.5**, extended below to cover them |
| `docs/PRIVACY.md:63` | "the 6-digit code dialog" | **Task 6.5** |
| `docs/store-assets/listing-description.md:32`, `:68` | "6-digit code (e.g. `482-931`)" and "6-digit pair code … derived from a SHA-256 hash of both parties'" — the prepared CWS listing, which Group 7 already treats as live | **Task 6.5** |

`docs/superpowers/**` also says 6 digits in several places; leave every one of
them. Those are historical plans and specs, and editing them would rewrite
what was decided in May.

Finally, say in the Group 1 commit BODY that the code the user
compares is now eight digits: it is the one v4 change a person sees with their
own eyes, and a release note silent about it turns "the numbers don't match"
into a support call.

Commit: `feat(protocol)!: protocol v4 — per-session ephemerals, a transcript-salted session key, and mcpId‖seq‖direction in the AAD`.

---

## Group 2 — the server

**Task 2.1 — the host.** Where: `packages/server/src/host.ts` (hello built at
`:177-197` moves into the extension-hello handler at `:289`, whose send is
already at `:372`; derivation `:501`; ready verify `:458`; teardown `:612-641`,
the extension socket's close handler, which nulls `ownSession` at `:622`),
`build-server-hello.ts:79`. Read §1a first: this task is Rules A and D on the
host. "Per connection" is the right shape here — the host does get one socket
per extension — but it is not the whole rule even on this path, because the
mint awaits and the socket can close inside it; Rule D is that half.
Test (`packages/server/tests/host.test.ts`, first): two successive extension
connections to one host receive hellos with **different** `sessionPub` and
`sessionNonce`; the hello's `answersExtNonce` equals the `sessionNonce` of the
extension hello that triggered it, on both connections; the session key derived
by a mock extension against the hello's `sessionPub` matches the host's; a
`ready` whose `sessionSig` omits `mcpSessionPub` from its payload is refused;
after the extension socket closes, the host holds no readable copy of the
previous `sessionPriv` (assert through the exported surface or an injected
zeroing hook — do **not** add an accessor that exists only for the test).
Then Rule C on this path, and note that the two outcomes must be asserted
apart: a `ready` whose `mcpSessionPub` is the host's CURRENT ephemeral but
whose `sessionSig` does not verify closes 1008 (`host.ts:470-476`, unchanged)
and rejects the pending session, while a `ready` whose `mcpSessionPub` is a
SUPERSEDED one is **discarded** — the socket stays open, `ownSession` and the
pending promise are untouched (assert the promise is still pending against a
fake clock), and a genuine `ready` arriving afterwards still establishes the
session. A test that only asserts "the stale one does not establish a session"
passes against today's 1008 and so proves nothing.
Then Rule D, which needs its own case because the two above cannot reach it:
they drive one mint at a time, and this is two **inside one process**. Drive it
by injecting a keypair generator whose first call is held (the same shape as
the injected zeroing hook, and for the same reason — it is the only way to be
inside the interval): E1 connects and its mint is held → E1's socket closes →
E2 connects and its mint completes → release E1's. Assert that E2's mock
extension receives **exactly one** server hello, that the `ready` it sends for
that hello's `sessionPub` **establishes the session** (which is the assertion
that fails on the bug — mint 1 having landed last, Rule C discards that `ready`
and the session never opens), that **no** frame reaches E2 from the released
mint, and that the private half mint 1 produced is zeroed. A test asserting
only "E1 gets nothing after its close" passes without Rule D, because a closed
socket swallows the send; the load-bearing assertion is about E2's session
opening.
Do: mint `{nonce, pub, priv}` per extension connection — after the liveness
re-check at `host.ts:337-345` and immediately before the send, so a hello the
trust decision refuses mints nothing; set `answersExtNonce` from the triggering
extension hello's `sessionNonce` (it is `frame.sessionNonce`, in scope in that
handler) and sign it. Do **all** of that into locals — `generateX25519` and the
`ed25519Sign` over the widened payload both await — and then commit under
Rule D: **re-read `extensionWs === ws` synchronously; if it has moved, zero the
private half just minted, install nothing, send nothing and return.** Only past
that check assign `{nonce, pub, priv}` and send the hello. The idiom is
`host.ts:508`'s `if (extensionWs !== ws) return;`, which guards the v3
derivation against the same close; Rule D is the same guard one handshake
earlier, and skipping it lets a mint for a dead session overwrite the live one
(§1a Rule D, host bullet). The liveness re-check at `:337-345` does **not**
serve as that check and must not be mistaken for it: it asks a different
question (`closed || ws.readyState !== WebSocket.OPEN` — this socket's own
health, before the slot is taken and before `extensionWs` has been assigned at
`:350`), and it runs on the wrong side of the mint's awaits. Rule D reads the
authoritative variable, after them. Then derive
`X25519(sessionPriv, extSessionPub)`; salt with `transcriptHash`; pass
`direction: 's2e'` on seal and `'e2s'` on open; zero and drop `sessionPriv` in
the same statement that nulls `ownSession`. In the ready branch, put the
`mcpSessionPub` comparison **before** the `ed25519Verify` at `:466` — the
discard must not depend on a signature check, and putting it after would mean a
stale `ready` is refused for the wrong reason whenever the extension's
signature happens to be over the stale pub (which it always is).

**Task 2.2 — the peer, whose "connection" is not a socket.** Where:
`packages/server/src/peer.ts:181` (the hello), `:202` (the nonce), `:275`,
`:349-351` (the relayed extension hello), `:356-363` (`extension-disconnected`),
`:374-381` (the ready's identity refusal, which Rule C narrows), `:385`
(derivation), `:392` (the renegotiation it already names), `:507-513`
(the socket's close handler), `frame-size.ts`; and `host.ts:370`, `:374-376`,
`:411-420`, `:424`, `:425`, `:428`.

**Do not copy Task 2.1 literally — on this path "per extension connection" has
no socket to hang on.** The host gets one WebSocket per extension and can mint
on its `open`. The peer's single socket goes to the *host*, and it outlives
every extension session: the extension's MV3 evictions arrive as fresh `ready`
frames on that same socket, which `peer.ts:392` already calls a renegotiation.
A peer that mints ONLY in `startPeer` therefore holds a per-PROCESS ephemeral
reused across every extension connection for the life of the MCP — on mcp-host
up to ten idle minutes of real traffic per boot, on a laptop days. That is not
an ephemeral, and it is the same "worth having, not worth claiming as forward
secrecy" the hello section refuses for the host.

**But it still mints in `startPeer`, and §1a says why.** The peer needs TWO
keypairs and they have different jobs, because the peer's hello does two jobs:
it registers the peer with the host *and* it offers a session. An earlier draft
of this plan said to mint "per connection rather than on `startPeer`", which
denies the registration hello the `sessionPub` Task 1.1 makes required and
`host.ts:387-404` verifies the signature over — and a peer that cannot register
is never told an extension exists, so it never reaches the other mint at all.

| | Bootstrap | Session ephemeral |
|---|---|---|
| Minted | `startPeer`, before the registration hello (`peer.ts:181-203`) | when a relayed extension hello arrives (`peer.ts:349-351`), followed by a **fresh server hello** to the host in the same handler — both at Rule D's commit point, which is `extensionHello === frame` |
| Job | satisfies the required field and signs the registration hello | derives the session key |
| `answersExtNonce` on the hello it signs | 32 zero bytes — at dial this peer has been told of no extension session, and the frame says so | the `sessionNonce` of the relayed extension hello that triggered this mint (`frame.sessionNonce`, in scope in that handler) |
| Derives a key | **never** — the frame carrying it answers nothing, so Rule B below refuses to forward it and no `ready` can name it | yes: `X25519(sessionPriv, extSessionPub)`, salted with `transcriptHash` |
| Zeroed | at the first session mint that COMMITS, or at `:507-513` if none does | at `extension-disconnected` (`:356-363`), at the next session mint's COMMIT POINT, or at `:507-513` — and, if this mint is the one that loses Rule D's check, by itself, before it has installed anything |

**"The next session mint" means the next one that commits, and the difference is
not pedantry.** Mints do not necessarily land in the order they started:
`onMessage` is `async` (`peer.ts:342`) and registered as
`ws.on('message', onMessage)` (`:501`), so E1's mint can still be inside
`generateX25519` when E2's relayed hello arrives, completes and installs. A mint
that resolves after a later one has committed must therefore zero **its own**
half and install nothing (§1a Rule D); phrased as "superseded at the next mint",
this row would license exactly the overwrite that leaves the peer holding pub1
while the extension holds pub2, with Rule C then discarding the one legitimate
`ready` and nothing left to re-trigger a mint.

Zeroing is by EVENT on this path, not by a statement that clears `session`:
`session` is deliberately never returned to null (`peer.ts:236-238`, the 2.5.0
`extensionGone` comment — **not** `:209-215`, which is the call-time-read
comment this task repairs below), so each of the three events above zeroes and
drops `sessionPriv` where it already handles the extension going away. (The
fourth entry in that row is not an event: a mint that loses Rule D's check
zeroes the half it just produced at its own commit point, which is the one
zeroing that happens before anything was ever installed.) Two of
the three events end the extension session; the third (`:507-513`, the peer's own
socket to the host) does not — it ends this process's part in it, and zeroing
there is a teardown obligation rather than part of §1a's invariant. §1a's table
says which, and why the difference matters for the approval path.

**Six consequences, all required for that to work.** The first four are in the
host: the first three are one rule — Rule B of §1a, gating BOTH directions —
and the fourth is a guard that becomes load-bearing. The last two are back in
the peer, and they are Rules C and D. Rule D is listed last and is not optional
garnish on Rule C: it is what stops Rule C's discard from being the only thing
that happens. (Reading key for these six bullets: a bare `:NNN` is in `host.ts`
unless the sentence names the file it is in.)

- The host caches each peer's hello (`peers.set(mcpId, {ws, helloFrame})`,
  `host.ts:424`) and **replays it to every newly connected extension**
  (`host.ts:374-376`).
  Under v4 the cached frame is stale by construction — the private half it
  names is gone or about to be — so the extension would derive against a key
  nobody holds. Drop the replay: the relay the host already performs at `:370`
  (extension hello → every peer) is what prompts each peer to hello afresh, and
  the host forwards those as they arrive.
- **The dial path has the same bug and is not fixed by dropping the replay.**
  `:425` forwards a peer's hello to an already-connected extension the instant
  it arrives, and `:428` then hands that peer the cached extension hello —
  which is its Rule A trigger. So a peer joining a live extension would send
  its registration hello, have it forwarded, be told about the extension, mint,
  re-hello, and leave the extension holding a `ready` for a `sessionPub` whose
  private half the peer has just zeroed. Gate `:425` on §1a's Rule B — forward
  only when
  `extensionHello !== null && frame.answersExtNonce === extensionHello.sessionNonce`
  — so a registration hello (which answers 32 zero bytes) never reaches the
  extension and the re-hello that follows always does. **Both operands are read
  at the forward, one off the frame and one off the single authoritative
  variable; nothing is recorded on `PeerSlot` and nothing is carried across a
  slot overwrite.** §1a sets out why a per-peer mark cannot work here, and it
  is worth restating in one line because the mark is the obvious fix and it is
  wrong: `:425` runs **after** the `await ed25519Verify` at `:395`, and `:370`
  re-points every peer's mark inside that window, so a mark says which
  extension is attached now rather than which one this frame was minted for. An
  echo the peer signed says the second thing, which is the question the gate is
  asking.
- **`:428` is itself a mint trigger, so it needs the MIRROR of that gate or the
  dial fix loops.** `if (extensionHello) ws.send(JSON.stringify(extensionHello));`
  runs at the tail of this branch unconditionally, on every peer hello —
  including the Rule A re-hello the bullet above exists to let through. So
  gating `:425` alone converts the dial from one stale hello into an unbounded
  exchange: re-hello → forwarded → cached extension hello sent back → mint →
  re-hello. Send it only when the arriving hello answers NO extension session
  (`answersNoExtSession(frame.answersExtNonce)`, Task 1.1): a REGISTRATION hello
  is the one case
  where this peer has not been told about the extension and needs to be, and
  `:370` covers every other peer for every extension session already. Read off
  the frame alone — this gate touches no authoritative variable, which is one
  fewer moving part than its mirror at `:425`. §1a Rule B traces the loop, the
  two trigger paths it runs on, why the two relays are mutually exclusive per
  (peer, extension session) once gated, and why the peer-side alternative was
  declined.
- A same-socket, same-identity re-hello must REPLACE the slot rather than be
  refused, because that re-hello is now the *only* way a peer's session hello
  reaches the extension. It already does — the squat guard at `:411-420` fires
  only when `existing.ws !== ws`, and `:424` overwrites the slot — but under v4
  that is load-bearing rather than incidental, so assert it. Nothing else has
  to survive the overwrite: `PeerSlot` keeps exactly the two fields it has
  today (`{ws, helloFrame}`), which is the second reason the gate belongs on
  the frame.
- **Rule C on this path, which is where it earns its keep.** After the replay
  at `:374-376` is gone, a peer's re-hello is the only route its session hello
  takes to the extension — so an extension reconnect that races a re-hello is
  the ORDINARY case, not an exotic one, and today it ends in
  `peer.ts:374-381`: a 1008 close plus `rejectFirstReady`, which strands the
  bridged MCP on a failure an MV3 eviction caused. Compare
  `frame.mcpSessionPub` against the ephemeral this peer currently holds before
  `authenticateExtension` at `peer.ts:374`; a mismatch logs and returns, touching
  neither `session` nor `extensionGone` nor the promise, and the socket to the
  host stays up because the host is not the party at fault. The 1008 stays for
  the case it was written for — a `ready` naming the current ephemeral whose
  signature does not verify.
- **Rule D on this path, which is what keeps "currently holds" meaningful.**
  Rule C compares a `ready` against "the ephemeral this peer currently holds",
  and after the bootstrap this handler is the only thing that ever assigns that
  value — so if it can assign the wrong one, Rule C reads the wrong one and its
  discard becomes a hang. It can:
  `onMessage` is `async` (`:342`) and nothing awaits the promise
  `ws.on('message', onMessage)` returns (`:501`), so E1's mint can be inside
  `generateX25519` while E2's relayed hello arrives and completes, and the two
  install in the order their crypto resolved. Do the mint and the hello
  signature into **locals**, then commit synchronously and only if
  `extensionHello === frame` — the frame that triggered this handler, already in
  hand, which is why this costs nothing here. On a mismatch: **zero the private
  half just minted, assign nothing, send no hello, return.** The hello it would
  have sent is one Rule B refuses to forward anyway, so the send is merely
  pointless; the **assignment** is the bug, and it is the one that leaves this
  peer holding a superseded pub while the extension holds the live one, with
  Rule C discarding the only `ready` there will be and no trigger left to mint
  again (§1a Rule D, peer bullet). Note what the mismatch means on this path
  and not on the host's: `extensionHello` may be `null` (an
  `extension-disconnected` landed inside the mint) as well as a newer frame, and
  both are the same refusal to commit.

**What this changes about renegotiation, which a comment currently gets wrong.**
`peer.ts:209-215` says a renegotiation most commonly happens "after MV3
service-worker eviction reconnects the browser side and **the host replays our
hello**". After this task there is no replay: the trigger is the host relaying
the new extension hello at `host.ts:370` and the peer hellos again. Update that
comment in the same task — a comment naming a path this task deletes is how the
next reader concludes the replay is still there.

**The `warnedUnverifiable` branch dies, and must not be left looking alive.**
`peer.ts:240-271` lets a peer proceed with a warning when the host never
relayed an extension hello (a pre-1.12.0 host). Under v4 it *cannot*: the
transcript salt is `SHA256(mcpNonce ‖ extNonce ‖ …)` and `extNonce` comes only
from that hello, so a peer without it has nothing to derive from. Make the
branch a hard refusal naming the reason, and retire
`requireExtensionIdentity`'s "unless" — a v4 peer behind a v3 host is already
refused at the hello by Task 4.2. (An earlier draft of this plan said to leave
that branch alone and check its wording; that was written before the transcript
salt made it uncomputable.)

Test (`packages/server/tests/peer-hello-auth.test.ts` and the integration
suites under `tests/integration/`, first): two successive extension hellos
relayed to one peer produce two hellos to the host with **different**
`sessionPub` and `sessionNonce`, each echoing the `sessionNonce` of the
extension hello that triggered it, while the registration hello sent at dial
echoes 32 zero bytes; the peer derives the same key the host path
does against the same mock extension; after `extension-disconnected` the peer
holds no readable copy of the previous `sessionPriv`, and the same after the
socket to the host closes (through the exported surface or an injected zeroing
hook, not an accessor that exists only for the test); a newly connected
extension is **not** sent a cached peer hello; a peer whose hello omits
`sessionPub` is refused by the host at registration; a peer that never receives
an extension hello refuses rather than warning.
Then the dial path, which is the half an earlier round missed and which the
invariant in §1a is checkable against — **a peer that dials into a host with an
extension already attached**: the extension receives **no** frame for that
`mcpId` until after the peer has been sent the extension hello; it then
receives **exactly one** server hello for it; that hello's `sessionPub` is
**not** the one on the registration hello; the `ready` the mock extension sends
for it opens a frame the peer seals (i.e. the key the extension derived is the
key the peer still holds); and the peer's bootstrap `sessionPriv` is zeroed by
then. Plus the ordering control: with **no** extension attached at dial, the
extension that connects afterwards receives one server hello for that peer and
it is the post-relay one.

Then `host.ts:428`'s gate, which is what makes that "exactly one" reachable at
all — un-gated, the dial never settles, so the assertion above is not merely
unproven but unsatisfiable. Two assertions on one gate, one per direction, so a gate
deleted either way fails: a peer's **registration** hello (echoing 32 zero
bytes) is not forwarded to the extension and **does** draw the cached extension
hello back; a peer's **re-hello** (echoing the live extension nonce) **is**
forwarded and draws **nothing** back. Then the property itself, end to end, on
**both** trigger paths — a dial into a live extension AND an extension
reconnect — asserted over a rig run to QUIESCENCE rather than for a fixed
number of turns, because the bug's signature is an exchange that never settles:
the extension receives exactly one server hello per peer per extension session,
and the injected keypair generator was called exactly once per peer per
extension session. A rig that takes its counts after N turns records a clean
number on the looping code.

Then the RACE, which the un-interleaved sequence above does not reach and which
is what a per-peer mark passed: **a peer hello minted for the previous
extension session, arriving at the host after `host.ts:370` has fanned the next
extension's hello out, is not forwarded.** Drive it at the host with two mock
extensions and a peer whose hello is held: peer told of E1 → its hello for E1 is
withheld → E1's socket closes → E2 connects (so `host.ts:370` has run for this peer
and `extensionHello` is E2's) → release the peer's hello for E1. Assert that E2
receives **no** frame for that `mcpId` from it, that the peer then hellos again
off E2's relay, and that **that** hello is forwarded. Two controls keep it
honest: with E1 still attached the same withheld hello **is** forwarded, so the
test is about the supersession and not about withholding; and the assertion is
on what the extension RECEIVES, not on an internal flag, so an implementation
that gates by some other sound means still passes.
Then Rule C's discard, which is the same race seen from the other end: a
`ready` naming the peer's superseded `sessionPub` leaves `session` in place,
leaves the socket open and does not reject the first-ready promise, while a
`ready` naming the current one with a bad signature still closes 1008 and
rejects. Assert both in the same file — they are one branch and a test of
either alone passes on the pre-Rule-C code.
Then Rule D, and note first why the race test above cannot reach it: that one
is driven **at the host**, withholds a frame on the wire and asserts what the
extension RECEIVES, so it never has two of one peer's mints in flight — the
whole of Rule D is inside the peer process. Drive this one **at the peer**, with
an injected keypair generator whose first call is held (same shape as the
injected zeroing hook): relay E1's extension hello → its mint is held → relay
`extension-disconnected` → relay E2's extension hello, whose mint completes and
whose hello the host receives → release E1's mint. Assert that the peer sends
**no** further hello to the host, that its `sessionPriv` for E1 is zeroed, and —
the assertion that actually fails on the bug — that the `ready` naming **E2's**
`sessionPub` still establishes the session and seals a frame the mock extension
can open. Without Rule D that last one fails as a *hang*, not an error: mint 1
landed last, so Rule C discards a legitimate `ready` and the first-ready promise
stays pending, which is why asserting it must be positive ("the session opens")
rather than negative ("nothing bad is sent"). Run the same case with a newer
extension hello in place of the `extension-disconnected`, so both mismatch
shapes — `extensionHello` newer and `extensionHello` null — are covered.
Do: the derivation, salt, direction and zeroing changes of Task 2.1, mounted
on the two mint points above, each with the `answersExtNonce` the table gives
it, and each committing under Rule D (`extensionHello === frame`, zero-and-drop
on a mismatch); the host changes (drop the replay, gate `host.ts:425` on Rule B,
gate `host.ts:428` on Rule B's mirror — send the cached extension hello only in
answer to a hello whose `answersExtNonce` is 32 zero bytes, without which the
gate on `:425` turns the dial into a livelock — assert the same-socket re-hello
overwrite, Rule C's discard on the ready branch); and the comment repair.

Commit: `feat(server)!: mint a session ephemeral per extension connection and authenticate every frame against its own identity`.

---

## Group 3 — the extension

**Where the tests go, checked rather than assumed.** `extension-core/tests`
has no `hello.test.ts`, no `socket.test.ts` and no `approval.test.ts`; its
suites are named for the BEHAVIOUR they pin, not for the module. Every target
below was resolved with `grep -rln <symbol> packages/extension-core/tests` and
each task names the file it found, because a new file beside an existing home
splits one function's coverage in two — the thing Task 3.1's approval note
already says in the one place an earlier draft got right. The resolutions:
`handleServerHello` → `background.test.ts`, `multi-link.test.ts`,
`background-module-surface.test.ts`; `onServerHello` and `onApproval` →
`background.test.ts`; `onEncryptedFrame` and the `claimInboundSeq` /
`releaseInboundSeq` contract → `session-keys.test.ts` and
`replay-counter-after-auth.test.ts`; `hello-rejected` → `multi-link.test.ts`
(extension side) and `server/tests/host.test.ts` (server side). No task in this
plan creates a file under `extension-core/tests`; the one new test file
anywhere is `protocol/tests/frames.test.ts` (Task 1.1, which says why) plus
`server/tests/cross-version/` (Tasks 5.1 and 5.2).

**Task 3.1 — derivation and signature.** Where:
`packages/extension-core/src/background/hello.ts:226-234` (verify) and `:303`
(ephemeral), `approval.ts:135`, `server-hello.ts:136`.
Test (`packages/extension-core/tests/background.test.ts`, where
`handleServerHello` and `onServerHello` are both exercised today, first): a
server hello whose `sessionSig` does not cover `sessionPub` is rejected with a
reason naming the signature; the auto-trust and the approval paths derive the
**same** key for the same hello (they are two code paths deriving one thing and
have drifted before); the `ready` the extension emits signs all four fields and
carries `mcpSessionPub` on the wire (Rule C's other end depends on it being
there, not merely signed over). Then Rule C's extension-side half: a hello
whose `answersExtNonce` is not `link.sessionNonce` is refused **before** any
binding — `bindMcpToLink` was not called for that `mcpId` (so a later, correct
hello for the same id is not blocked behind it), no trust record is read or
written, no session key exists, and the reason goes out through the existing
`tellServerWhy`; and a hello whose `answersExtNonce` is 32 zero bytes is
refused the same way, since on the wire that is a registration hello.
Do: verify `helloSignaturePayload`; add the `answersExtNonce` check in
`onServerHello` (`server-hello.ts:89-94`, which already returns early on
`!link.sessionNonce`, so the value is in hand and the check goes above
`bindMcpToLink`); derive against `hello.sessionPub` rather
than `identityX25519Pub`; salt with `transcriptHash`; sign the widened ready
payload. **Trust matching is untouched** — the record is still keyed on
`sha256(identityX25519Pub)` (`hello.ts:237-238`), so no registration re-pairs
because of v4. Assert that: a trust record written under v3 still auto-trusts
under v4 for the same identity, serverName and domain set.

**The approval path answers a hello it read back out of storage, so it needs
the `sessionPub` stored beside the nonce.** `approval.ts:111-165` derives from
`approved.sessionNonces[mcpId]` plus `approved.identityX25519Pub` — a long-term
key, which is why a stored record sufficed under v3 and does not under v4. So
`PendingPairRecord` gains `sessionPubs: Record<string, string>` beside
`sessionNonces` (`pending-records.ts:51`, written at `server-hello.ts:270`),
refreshed per `mcpId` on every hello exactly as the nonce is
(`applyNeedsPairRecord` case 1, `pending-records.ts:147-151` — that function
lives in that file, not in the `server-hello.ts` cited in front of it) — the
refresh is what keeps a record from naming a superseded ephemeral after a
reconnect. Then derive
against `sessionPubs[mcpId]`, salt with `transcriptHash(storedNonce,
link.sessionNonce, storedSessionPub, ephemeral.publicKey)`, and sign the ready
over all four. An entry with **no** `sessionPubs` value — every pending record
already in `chrome.storage.local` when the extension is reloaded — is skipped
with the same warn as a missing nonce (`approval.ts:119-122`), and the MCP hellos
again; do not fall back to `identityX25519Pub`, which is the v3 derivation
reinstated under a v4 signature.
Test (`packages/extension-core/tests/background.test.ts`, which is where
`onApproval` is exercised today — there is no `approval.test.ts` and this task
should not invent one; check with `grep -rln onApproval
packages/extension-core/tests` before writing, first): approving a
record refreshed by a second hello uses the **second** hello's `sessionPub`, not
the first; a record carrying no `sessionPubs` entry is skipped rather than
derived from the identity key; and the key the approval path derives opens a
frame sealed by the MCP that sent that hello.
Pin the `approval.ts:127-130` guard with a test that a dead link produces no
`ready` — but do **not** write down that the guard proves the MCP's ephemeral
is still live, because for a PEER's mcpId it does not: `linkForMcp` is `mcpLink.get(mcpId)`
(`links.ts:98-99`), the concentrator socket, which the host's own mcpId and
every peer's share, so it survives the peer that hello'd on it. §1a states that
residual and its consequence (the `ready` is dropped at `host.ts:516-517` and
the extension banks an unusable key). What the approval path owes here is Rule
C's other end: assert that the `ready` it sends carries the **stored**
`sessionPubs[mcpId]` as its `mcpSessionPub`, so an MCP that has re-minted since
the prompt can discard it instead of reading it as a forgery.

**Task 3.2 — AAD on both directions.** Where: `send-inner.ts`, `socket.ts`
(`onEncryptedFrame`, around `:258-300`).
Test (`packages/extension-core/tests/session-keys.test.ts` for the
`onEncryptedFrame` half and `replay-counter-after-auth.test.ts` for the
claim/release half — the two files where those already live; first): a frame the
extension sealed opens on the server side and not under a bumped `seq`; a
server→extension frame replayed under `seq + 1` fails at `decrypt-failed` and
— this is the part that matters — **releases** the claimed seq rather than
committing it, so the next genuine frame is still accepted (the `claimInboundSeq`
/ `releaseInboundSeq` contract `socket.ts` already documents).
Do: `'e2s'` on seal, `'s2e'` on open.

**Task 3.3 — the identity that signs is the identity that is pinned (L6, which
v4 makes load-bearing).** Where:
`packages/extension-core/src/background/hello.ts:261-272`.
Test (`packages/extension-core/tests/background.test.ts`, beside Task 3.1's —
the same `handleServerHello` decision, and splitting one function's trust
branch across two files is how the two halves drift; first): a hello carrying a
trusted record's `identityX25519Pub` but a **different** `identityEd25519Pub`,
with a `sessionSig` that verifies under that different key, does **not**
auto-trust — it falls through to needs-pair, returns no session key and writes
no trust record. That is the impersonation set out in §2 above, and without
this test nothing in the suite fails when the comparison is deleted, which is
how it stayed absent for two majors. Also: the matching pair still auto-trusts,
so no existing registration re-pairs because of this task (the same assertion
Task 3.1 makes, for the same reason); and a legacy record whose
`identityEd25519Pub` is absent or empty falls through to needs-pair rather than
being read as a match.
Do: add `record.identityEd25519Pub !== hello.identityEd25519Pub` to the
`scopeIdentityChanged` disjunction at `hello.ts:261-272` — one clause in the
branch that is already there, so a mismatch takes the needs-pair path the user can
answer rather than a `reject` the popup cannot show. Do **not** normalise an
absent stored value with `?? hello.identityEd25519Pub`, which turns the check
into a tautology; an absent one must mismatch. Nothing has to be migrated —
`TrustRecord.identityEd25519Pub` is required
(`packages/extension-core/src/trust-store.ts:115` — one directory up from this
task's `background/`, not beside `hello.ts`) and written unconditionally
(`trust-store.ts:214`), and a record old enough to lack it is a 0.3.0
leftover that `extensionIdentityX25519Pub ?? ''` already forces to re-pair, so
its outcome is unchanged. Comment it with the `decideExtensionTrust` sentence
quoted in §2 and a pointer to that function, because after this task the two
halves of one rule live in two packages and only a comment says so.

Commit: `feat(extension)!: derive the session key against the MCP's ephemeral, pin both halves of its identity, and bind every frame to its id, ordinal and direction`.

---

## Group 4 — the refusal (both directions), and the surfaces that say so

This is the group that makes the release choreography survivable. Do not let it
be cut for time.

**Task 4.1 — a v4 extension refuses a v3 MCP, out loud.** Where:
`packages/extension-core/src/background/socket.ts:246-248` (the drop),
`server-hello.ts:81-85` (the existing `hello-rejected` sender).
Test (`packages/extension-core/tests/multi-link.test.ts`, which is where the
`hello-rejected` path is exercised today, first): a server hello
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
extension hello with `protocolVersion: 3` is closed within one tick with close
code **1002** and **a reason naming both versions** (assert the reason string as
well as the code);
the pending `ownSessionReady` rejects immediately with an error whose message
names both versions and the extension version to install — **not** after
`SESSION_READY_TIMEOUT_MS` (assert against a fake clock); a `request()` issued
afterwards fails fast with the same message; a frame that is malformed for any
*other* reason still closes with today's generic `1002 'protocol error'` and
leaves the pending session alone, so the mismatch is the only case that gets
the new treatment.
Do: `peekHelloVersion` in that catch, the same shape as 4.1. **The close code
stays `1002`** — the one already there (`host.ts:284`), and the right one:
RFC 6455's 1002 is a protocol error, which a version mismatch exactly is, while
this file spends 1008 on identity and authorization refusals (`:291`, `:314`,
`:327`, `:403`, `:418`, `:474`). What changes is the reason and the immediate
rejection, never the code — which is the same thing this task's paragraph above
says when it calls the close "already there". Task 5.2 case 1 asserts the same
`1002`. Message text, fixed and asserted:
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

1. **v3 mock extension → v4 host.** Host closes **1002**, reason names both
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
survives. Build first, then mutate each of the **eleven** v4 facts in turn — drop
`sessionPub` from the hello payload, drop `answersExtNonce` from it (§1a Rule
B's echo is only as good as the signature over it), drop `mcpSessionPub` from
the ready payload, drop `direction` from the AAD, leave `HKDF_SESSION_INFO` at
`1.0.0`, delete the `identityEd25519Pub` comparison Task 3.3 adds, restore the
cached-peer-hello replay and un-gate the `host.ts:425` forward Task 2.2 removes
(one mutation: put both sends back), turn Rule C's `mcpSessionPub` comparison into
an unconditional pass on both server paths (the mutation that must fail the
interleaving test AND the "stale is discarded, forged is refused" pair — if
only one of the two fails, the other assertion is not pinning what it claims),
delete Rule D's commit-point re-check on both server paths (one mutation: the
host's `extensionWs === ws` and the peer's `extensionHello === frame` come out
together, and a test must fail for EACH path — a suite covering only one leaves
the other's overwrite unpinned), un-gate the host's `host.ts:428` re-send of the
cached extension hello so it answers every peer hello rather than a
registration one (§1a Rule B's mirror, Task 2.2), and — if decision 2 said
yes — drop `mcpSessionPub` from `pairTranscript`
(Task 1.4) — and confirm a test fails for each. Record the eleven results in
the PR body (ten if Task 1.4 was cut). A fact
with no failing test is a fact the next refactor removes, which is the whole
history of the sixth one; the seventh is there because the two sends it restores
are what the invariant in §1a exists to forbid, and a plan that only *says*
"drop the replay" is exactly the shape that leaves one of the two behind; the
eighth is there because Rule C's two outcomes are one branch, and a suite that
pins only the refusal passes on the code that 1008s a stale `ready`; the ninth
is, with the tenth, the likeliest to survive a careless suite, because deleting
Rule D
produces no error and no closed socket — a session that silently never opens —
so the test it must fail has to assert positively that the LIVE session opens,
and a suite whose only Rule D assertion is "the stale hello is not sent"
survives the mutation on a closed socket's swallowed write. The tenth is the
ninth's hazard one turn further out: un-gated, `host.ts:428` raises no error,
closes no socket and rejects nothing — only an exchange that never settles, and
on the ordinary path rather than an interleaved one — so
the test it must fail is the one that counts server hellos and keygens after
QUIESCENCE, and a rig that takes its counts after a fixed number of turns
records a clean number on the looping code. Anything that bounds turns rather
than asserting settlement leaves this fact unpinned.

Commit: `test(server,extension): prove a v3 peer meets a v4 host with a clean refusal, against frozen v3 bytes`.

---

## Group 6 — the record

**Task 6.1 — `packages/protocol/src/frames.ts` header.** Add the v4 paragraph
in the exact style of the 0.4.0 and 2.0.0 ones already at `:1-38`: what moved,
why it is a hard break, why there is no negotiated downgrade, and — new for
this one — that the AAD does not change the wire size so `MAX_FRAME_BYTES` is
unmoved. State the package-major off-by-one from decision 1 here, once.

**Task 6.2 — `docs/PROTOCOL.md`.** The wire facts of §§1-5 above with their exact
encodings, the verification rule that goes with them (a hello is trusted only
when **both** long-term keys match the pinned record — Task 3.3 — stated beside
the signature it makes meaningful, not in a footnote), the two refusal paths and
their message texts, the ephemeral-lifetime invariant of §1a — **both halves**,
the safety one and the liveness one — with its two tables (the hellos the
extension can act on, and which frames reaching a peer are mint TRIGGERS) and
its four rules, including which `ready` is discarded and which is refused, the
residual on the approval path the table names, Rule B's SECOND half (the gate
on the host's re-send of the cached extension hello, whose absence is not a
stale key but an exchange that never settles), and **Rule D**, which is the one
rule with no wire footprint at all and is therefore stated as what it is: an
implementation obligation on both ends, without which the invariant above it is
unprovable and the discard of Rule C becomes a hang. Those are the
facts a reader of the wire spec alone cannot reconstruct. Then the `mod
1_000_000` / `XXX-XXX` lines at `:418-419`, the pair code's
new derivation and the honest version of what it buys if Task 1.4 shipped, and a
table of `PROTOCOL_VERSION` → package major → what changed, so the off-by-one is
readable rather than inferred.

**Task 6.3 — `docs/SECURITY.md`.** Retract what v3 could not support and state
the new residual precisely. Retract: `:239` "Hosting an MCP does not give the
host the user's cookies, requests or responses" was **true only of a host that
does not also hold the identity** — under v4 it is true of an identity holder
too, and say what changed and when. `:198`/`:327` on replay: v4's AAD closes
it; say so and stop overstating it as already closed. Record Task 3.3: under v3
the extension's trust match could omit the Ed25519 half because the ECDH proved
possession of the pinned key, and under v4 it cannot — so the doc must not carry
the old sentence into the new derivation. `:65` states the pair code as
`SHA256(identityX25519Pub)[0..3] mod 1_000_000` / `XXX-XXX`, which has not been
the shipped derivation since 0.4.0 made it joint; fix the staleness and the v4
change in one edit if Task 1.4 ships, and the staleness alone if it is cut. Add
the new residuals
(§"What this does NOT fix, stated plainly", below) rather than letting them be
discovered.

**Task 6.4 — `CLAUDE.md`.** §Security model summary items 2, **3** and 3b get
the v4 sentences; the "Current line" paragraph moves to 3.x. Item 3 is the pair
code (`:78-80`, `SHA256(mcpPub || extPub)[0..3] mod 1_000_000` formatted
`XXX-XXX`) and an earlier draft of this task named only "2 and 3b", which would
have left the derivation Task 1.4 replaces stated as current in the file every
future agent reads first; `:17`'s "6-digit pair code" in the TL;DR moves with
it. If Task 1.4 is cut, items 2 and 3b are the whole of this task, as before. Two or three sentences,
in the voice of the existing 2.0.0 note. Do not restate the release
choreography here — it lives in this plan and in the PR body, and a third copy
drifts.

**Task 6.5 — the user-facing walkthroughs.** `README.md` and
`packages/extension-chrome/README.md`: the install line says which extension
version pairs with which package major, and the "reload after pulling" note is
upgraded from advice to a requirement with the failure it prevents named.
Then, **if Task 1.4 shipped**, the digit count everywhere a person reading a
walkthrough meets it — `README.md:44`, `packages/cli/README.md:37`,
`packages/extension-chrome/README.md:79`, `docs/PRIVACY.md:63`, and
`docs/store-assets/listing-description.md:32` (which prints an example code,
`482-931`, that has to become an eight-digit one) and `:68` (which states the
derivation). The store listing is prepared copy Group 7 already treats as live,
so a stale "6-digit" there ships to the Chrome Web Store rather than to a repo.
Task 1.4's surface table lists these with their owners; this is the task that
holds them.

Commit: `docs(protocol,server): record the v4 break, retract the confidentiality claim v3 could not support, and name what v4 still does not fix`.

---

## Group 7 — the release choreography

The hard part, and the reason this plan exists. Nothing below is a code task;
all of it is a sequence with a hand on it.

### What must move together

| Population | Count (measured 2026-09-11) | How it moves | Latency |
|---|---|---|---|
| `@fetchproxy/*` packages | **7 (5 published, 2 private)** | release-please, one combined PR, one `v3.0.0` tag, one publish job | minutes after the release PR merges |
| Cohort npm consumers | **31 `*-mcp` repos** pinned at `^2.10.0` (moving to `^2.11.3` in PR H1), plus `@chrischall/mcp-utils`, whose declaration is a `*` **peer** and needs no range edit | 31 PRs, each `fix(deps):`, each its own release-please cycle, each its own npm publish | hours, and unattended it is days |
| Bridged registrations on mcp-host | **~20** on the shared tier | a source PUT (or `mcp-host update-all`) per registration → new `configHash` → new install slot → builder artifact → restart | minutes if driven; **a night** if left to the `follow` cron |
| The browser extension | effectively **one installed copy** today (see below) | rebuild `dist/`, reload at `chrome://extensions`, or install the GitHub-release `.zip` | seconds |

The seven, counted from `packages/` on 2026-09-11 rather than from a doc:
**published** — `@fetchproxy/protocol`, `@fetchproxy/server`,
`@fetchproxy/bootstrap`, `@fetchproxy/test-helpers`, `@fetchproxy/cli`;
**private** — `@fetchproxy/extension-core`, `@fetchproxy/extension-chrome`.
`cli` is the one that gets missed: `CLAUDE.md`'s workspace table predates it
and still lists six packages and "the other four publish to npm", which is
where an earlier draft of this table got its numbers. It is not a spare part —
Task 4.4 edits `packages/cli/src/bridge-errors.ts`, so `cli` ships a v4 change
and `fpx` is how the operator debugs a straggler in step 5. Correct that table
in Task 6.4 while you are in the file, and verify the count with
`ls packages` before trusting either document.

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

1. **Gate.** Decisions 1–3 answered (4 already is, and its answer is what
   makes step 6 one reload). mcp-host PR H1 (the cohort bump to 2.11.3)
   is *merged and landed on the fleet*, so this operation moves one range, not
   two. mcp-host's `readEnvelope` change (Group 7 §prerequisite, below) is
   **live in the gateway**, not merely merged.
2. **fetchproxy 3.0.0.** Groups 1–6 merge; the release PR merges; the `v3.0.0`
   tag cuts; the publish job runs. Then, per the fleet rule that a green tag is
   not a green publish: `npm view @fetchproxy/protocol version` and the same
   for `server`, `bootstrap`, `test-helpers` and `cli` — all **five** must read
   `3.0.0`. If
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

### The prerequisite in mcp-host, which is merged and not yet deployed

`readEnvelope` forwards the frame kinds listed in
`packages/core/src/bridge-frames.ts`, and until 2026-09-11 there were five of
them with `hello-rejected` not among them (bridge report **L10**). Over the
hosted relay, that made Task 4.1's clean refusal **discarded by the Durable
Object**, with the child hanging for `SESSION_READY_TIMEOUT_MS` instead — which
would mean every mid-window straggler in step 5 looks like a dead connector
rather than a version mismatch, and the message this whole plan exists to
deliver never reaches anyone.

That change is **on mcp-host `main`**: it landed as **#756**, commit
`a2133a5` — whose squash subject is
`fix(gateway): delete a row whose secret is gone, bound the login reaper's IN clause, stop echoing the runner's tools error`
and mentions none of this. The bridge repair is one of the three commits inside
that squash (`fix(bridge): forward the extension's rejection and disconnect
frames to the child instead of dropping them`, in the squash BODY, not its
subject), which is exactly why the citation is the hash and the PR number and
why a reader grepping mcp-host's one-line log for the bridge sentence finds
nothing. So `BridgeFrameType` now
carries `hello-rejected` and `extension-disconnected`
(`bridge-frames.ts:63-70`) and `readEnvelope` routes both (`:127-136`). It is
**not** an ancestor of the `0.62.0` release commit this plan's other mcp-host
citations are read at, which is exactly the gap that matters: **merged is not
deployed.** So what is left of this prerequisite is one check, and it is
already step 1 — `readEnvelope`'s change must be **live in the gateway**, not
merely on `main`. If it is not live in the gateway, this plan waits.

### The one-installed-copy property, and the window it is closing

The extension is distributed today as an unpacked sideload and a GitHub-release
`.zip`. The Chrome Web Store listing is *prepared* — `docs/store-assets/`,
`docs/PRIVACY.md`, the Transporter rebrand, the whole of
`docs/superpowers/plans/2026-05-26-transporter-cws-launch.md` — but not
submitted: `README.md:62` still links
`chromewebstore.google.com/detail/transporter/EXTENSION_ID_PLACEHOLDER`. So
there is no auto-update channel, and step 6 above is a single reload because
there is a single install: **nothing has left the operator's walls** (decision
4, answered 2026-09-12), which is the operator's own statement rather than an
inference from the absence of a listing.

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
the next wire break is cheap. Decision 4 has taken the first, so this section
describes the fleet as it is today and step 6 costs one keystroke. It describes
a fact with an expiry date and not a standing one: on the day Transporter
reaches somebody who is not Chris, the second arrangement is the only one left
and Group 7 is no longer the operation written above — which is the argument
for not letting this plan sit.

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

v4 closes H1, M2 and — because this break is precisely what would have made it
exploitable — **L6**, which an earlier draft of this document deferred to the
list below and which is now Task 3.3. Everything that remains stays true the day v4
ships, and the `docs/SECURITY.md` rewrite in Task 6.3 must say so rather than
let a reader infer that a version bump fixed the bridge.

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
2. **The pair code's own strength** (**L5**). If decision 2 goes the other way:
   6 digits over `SHA256(mcpPub‖extPub)`, both inputs public and long-term, so
   one offline grind of ~10⁶ keygens is reusable against that MCP forever, and
   fixing it needs its own break. If decision 2 goes the default way and Task
   1.4 ships, a residual remains and belongs in `docs/SECURITY.md` rather than
   being dropped from this list: a party posing as the extension still chooses
   its own side of the transcript, so it can grind ~10⁸ hashes *online, inside
   one pairing window*, against a user who will compare only the digits.
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
8. **mcp-host's F2 is still wanted.** v4 makes an identity holder unable to
   decrypt a transcript; F2 makes fewer parties identity holders. Landing v4 is
   not a reason to drop F2, and the two doc rewrites must not each claim the
   other's ground.

---

## After every PR

`superpowers:finishing-a-development-branch`; watch the auto-review verdict and
its `auto-review-followup` issue; address findings **on the open PR**; never add
the arming label. When a PR merges, verify with `git diff main..<branch>` what
actually landed, not what it intended to. After the release, `npm view` all five
published packages before believing the tag — `cli` included, which is the one a
four-package habit drops.
