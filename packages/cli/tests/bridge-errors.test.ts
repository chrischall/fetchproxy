import { describe, it, expect } from 'vitest';
import {
  FetchproxyProtocolError,
  FetchproxyProtocolVersionError,
  protocolErrorFrom,
} from '@fetchproxy/server';
import { mapBridgeError } from '../src/bridge-errors.js';
import { EXIT, type Io } from '../src/output.js';

function memIo(): Io & { outs: string[]; errs: string[] } {
  const outs: string[] = [];
  const errs: string[] = [];
  return { outs, errs, out: (l) => outs.push(l), err: (l) => errs.push(l) };
}

describe('mapBridgeError — scope-diff errors are not version mismatches', () => {
  // A widened declared scope (e.g. an MCP adding a cookie key) is rejected by
  // the extension's gate #2 until the user re-approves. That surfaces as a
  // `protocol` error, which used to inherit the blanket
  // "extension/server version mismatch — update both." hint — sending users
  // to chase a version problem that does not exist. The remedy is a re-pair.
  it('tells the user to re-approve, not to update, on an undeclared-key error', () => {
    const io = memIo();
    const code = mapBridgeError(
      protocolErrorFrom('cookie keys not in declared set: refreshToken'),
      io,
    );
    expect(code).toBe(EXIT.BRIDGE);
    const out = io.errs.join('\n');
    expect(out).toMatch(/cookie keys not in declared set: refreshToken/);
    expect(out).toMatch(/re-approve|revoke/i);
    expect(out).not.toMatch(/version mismatch/i);
  });

  it('names the profile flag so the user knows what to revoke', () => {
    const io = memIo();
    mapBridgeError(protocolErrorFrom('cookie keys not in declared set: a, b'), io);
    expect(io.errs.join('\n')).toMatch(/ContextMint Bridge/);
  });

  // Gate #2 rejects a widened scope in EIGHT different wordings, one per
  // declarable bucket. The first cut of this fix only matched the cookie and
  // {local,session}Storage forms, so IndexedDB / DOM / captureHeaders /
  // graphqlOps / storage-pointer rejections still inherited the misleading
  // version-mismatch hint despite being the same re-pair situation.
  it.each([
    'cookie keys not in declared set: refreshToken',
    'localStorage keys not in declared set: token',
    'sessionStorage keys not in declared set: sid',
    'IndexedDB keys not in declared set: order-42',
    'read_dom names not in declared set: priceLabel',
    'localStorage pointer (auth, /token) not in declared set [outputKey=jwt]',
    '(host, path, headerName) not in declared captureHeaders',
    '(origin, database, store) not in declared indexedDbScopes',
    'graphql_query name not in declared graphqlOps: Autocomplete',
  ])('treats %j as a re-pair, not a version mismatch', (msg) => {
    const io = memIo();
    mapBridgeError(protocolErrorFrom(msg), io);
    const out = io.errs.join('\n');
    expect(out).not.toMatch(/version mismatch/i);
    expect(out).toMatch(/re-approve|revoke/i);
    expect(out).toMatch(/ContextMint Bridge/);
  });

  it('still reports a genuine protocol error as a version mismatch', () => {
    const io = memIo();
    mapBridgeError(new FetchproxyProtocolError('unknown frame type "wat"'), io);
    expect(io.errs.join('\n')).toMatch(/version mismatch/i);
  });
});

describe('mapBridgeError — a missing tab is not a version mismatch', () => {
  // Reported as #204: `fpx post-json https://api.creditkarma.com/graphql` on a
  // current CLI and a current extension printed
  //   bridge error (protocol): no tab matching https://api.creditkarma.com/
  //     — extension/server version mismatch — update both.
  // Nothing was mismatched; nothing was open on that host.
  it('tells the user to open a tab, not to update', () => {
    const io = memIo();
    const code = mapBridgeError(
      protocolErrorFrom('no tab matching https://api.creditkarma.com/'),
      io,
    );
    expect(code).toBe(EXIT.BRIDGE);
    const out = io.errs.join('\n');
    expect(out).toMatch(/no tab matching https:\/\/api\.creditkarma\.com\//);
    expect(out).toMatch(/open a tab/i);
    expect(out).not.toMatch(/version mismatch/i);
    expect(out).not.toMatch(/update both/i);
  });

  it('leaves the unreachable-content-script wording to say its own piece', () => {
    // That message already tells the user to refresh the page. "Open a tab"
    // would be wrong there — one is open.
    const io = memIo();
    mapBridgeError(
      protocolErrorFrom(
        'no tab matching https://x.com/ has the fetchproxy content script loaded ' +
          '(1 URL match, none responded). Refresh the page in your browser to inject ' +
          'the content script, then retry.',
      ),
      io,
    );
    expect(io.errs.join('\n')).toMatch(/Refresh the page/);
  });
});

/**
 * chrischall/fetchproxy#342 — the most ordinary miss in the system told users
 * to update working software.
 *
 * `capture_request_header`, `capture_redirect` and `download` answer
 * `{ok:false, error:'timeout'}` when their window closes with nothing matched.
 * That became a plain `FetchproxyProtocolError`, classified `protocol`, whose
 * blanket remedy is "extension/server version mismatch — update both". It is
 * not a version problem: resy-mcp's capture leg times out on EVERY unattended
 * mint, by design, and the fallback does the work.
 */
describe('a closed extension window is a timeout, not a version problem', () => {
  const thrown = (op?: 'capture' | 'capture_redirect' | 'download') =>
    protocolErrorFrom('timeout', op);

  it('never tells the user to update anything', () => {
    const io = memIo();
    mapBridgeError(thrown('capture'), io);
    expect(io.errs.join(' ')).not.toMatch(/version mismatch|update both/i);
  });

  it('names the tab as the remedy, and says an idle one cannot resolve', () => {
    const io = memIo();
    mapBridgeError(thrown('capture'), io);
    const line = io.errs.join(' ');
    expect(line).toMatch(/signed in/);
    expect(line).toMatch(/idle tab/);
  });

  it('classifies it as a timeout rather than a protocol fault', () => {
    const io = memIo();
    mapBridgeError(thrown('capture_redirect'), io);
    expect(io.errs.join(' ')).toMatch(/^bridge error \(timeout\)/);
  });

  // A download's window closing means the transfer did not finish — telling
  // that user to go interact with the page is the same class of wrong remedy.
  it('gives download its own remedy', () => {
    const io = memIo();
    mapBridgeError(thrown('download'), io);
    expect(io.errs.join(' ')).toMatch(/did not finish|still transferring/);
  });

  // Exact match, not a substring: a message that merely CONTAINS the word is
  // some other failure describing itself, and stealing it would be this same
  // mis-hint pointed the other way.
  it('does not capture a different failure that mentions the word', () => {
    const io = memIo();
    mapBridgeError(protocolErrorFrom('handshake timeout budget exceeded'), io);
    expect(io.errs.join(' ')).toMatch(/version mismatch|update both/i);
  });
});

/**
 * Protocol v4, Task 4.4 — `fpx` is how the operator debugs a straggler.
 *
 * A version mismatch reaches the CLI as a `FetchproxyProtocolVersionError`
 * (server 3.0.0+, Task 4.2), which is NOT a `FetchproxyProtocolError` subclass
 * and so classified `other` — the bucket whose hint is the empty string. So
 * the one failure the whole of Group 4 exists to make legible arrived here
 * rendered as `bridge error (other): …` with no remedy of the CLI's own, one
 * line below a `timeout` bucket that would have told the reader to go check a
 * sign-in. The remedy is named, and it is named off the error's OWN `.peer`
 * rather than off its prose — which half of the bridge is behind decides
 * whether the thing to move is a browser extension or somebody else's MCP
 * process, and those are not the same errand.
 */
describe('a protocol version mismatch names the remedy, not a bucket', () => {
  const mismatch = (peer: 'extension' | 'mcp') =>
    new FetchproxyProtocolVersionError({ ourVersion: 4, theirVersion: 3, peer });

  it('names BOTH versions — a refusal naming one tells the reader nothing', () => {
    const io = memIo();
    const code = mapBridgeError(mismatch('extension'), io);
    expect(code).toBe(EXIT.BRIDGE);
    const out = io.errs.join('\n');
    expect(out).toMatch(/protocol 4/);
    expect(out).toMatch(/speaks 3/);
  });

  it('sends the user to the extension when the EXTENSION is behind', () => {
    const io = memIo();
    const out = (mapBridgeError(mismatch('extension'), io), io.errs.join('\n'));
    expect(out).toMatch(/ContextMint Bridge/);
    // The extension versions on its own release line now, so the remedy is
    // where to get it and which protocol it must speak — never "both halves
    // ship as one release", which stopped being true at the repo split.
    expect(out).not.toMatch(/one release/i);
    expect(out).toMatch(/nullnet-app\/contextmint-bridge\/releases/);
    expect(out).toMatch(/store/i);
    expect(out).toMatch(/fetchproxy protocol 4/);
    expect(out).toMatch(/reload/i);
    // The remedy is not this profile and not a sign-in: saying so is the point
    // of the task, because a thirty-second hang is what used to send people
    // there.
    expect(out).toMatch(/sign-in/);
    expect(out).not.toMatch(/@fetchproxy\/server/);
  });

  it('sends the user to the other MCP when a v3 CONCENTRATOR is behind', () => {
    const io = memIo();
    const out = (mapBridgeError(mismatch('mcp'), io), io.errs.join('\n'));
    expect(out).toMatch(/@fetchproxy\/server/);
    expect(out).toMatch(/restart/i);
    // fpx is the peer here and is not the thing to fix — nothing to reload in
    // a browser, and no flag that routes around the host.
    expect(out).not.toMatch(/chrome:\/\/extensions/);
  });

  it('never renders it as the anonymous `other` bucket', () => {
    const io = memIo();
    mapBridgeError(mismatch('extension'), io);
    expect(io.errs.join('\n')).not.toMatch(/bridge error \(other\)/);
  });

  it('does not inherit the blanket "update both" hint, which names neither end', () => {
    const io = memIo();
    mapBridgeError(mismatch('extension'), io);
    expect(io.errs.join('\n')).not.toMatch(/update both/);
  });

  // The branch is on the TYPE, exactly as the hinted-error branch above is —
  // a regex over "protocol version mismatch" would steal any protocol error
  // that happened to describe itself that way, which is the #204 mis-hint
  // pointed the other way.
  it('does not steal a plain protocol error that merely says the words', () => {
    const io = memIo();
    mapBridgeError(new FetchproxyProtocolError('protocol version mismatch in frame "wat"'), io);
    const out = io.errs.join('\n');
    expect(out).toMatch(/update both/);
    expect(out).not.toMatch(/chrome:\/\/extensions/);
  });
});
