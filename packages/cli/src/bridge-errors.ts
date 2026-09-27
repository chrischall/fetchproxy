import {
  classifyBridgeError,
  FetchproxyHintedError,
  FetchproxyProtocolVersionError,
  FetchproxySessionNotReadyError,
} from '@fetchproxy/server';
import { PROTOCOL_VERSION } from '@fetchproxy/protocol';
import { EXIT, UsageError, type Io } from './output.js';

/**
 * Map a thrown bridge error to an exit code, printing one actionable
 * line to stderr. UsageErrors propagate — main() owns those.
 */
export function mapBridgeError(err: unknown, io: Io): number {
  if (err instanceof UsageError) throw err;
  if (err instanceof FetchproxySessionNotReadyError) {
    const code = (err as { pairCode?: string | null }).pairCode;
    io.err(
      code
        ? pairingPendingLine(code)
        : 'bridge not ready — is your browser running with the ContextMint Bridge extension installed and connected?',
    );
    return EXIT.BRIDGE;
  }
  // The same situation, arriving by the other road. While the extension holds
  // this MCP's pair request unapproved, the server fails calls with its
  // "pairing required for <name> … pair code is: NNNN-NNNN" transport error —
  // a plain FetchproxyProtocolError (or just its message, on the ok:false
  // result paths) rather than the typed session-not-ready error. Left to the
  // classifier it buckets `protocol` and inherits the version-mismatch hint
  // below, which is how a `fpx pair` that merely timed out waiting for the
  // user to click Approve told them to go update their software. The remedy
  // is the approve-the-code line above, so it is answered with that line.
  const pairing = pendingPairFrom(err);
  if (pairing !== null) {
    io.err(
      pairing.code
        ? pairingPendingLine(pairing.code)
        : 'bridge not ready — pairing pending. Approve the pair request in the ContextMint Bridge extension popup and retry.',
    );
    return EXIT.BRIDGE;
  }
  // 3.0.0 (protocol 4), Task 4.4. A version mismatch is refused at the hello
  // now rather than hung on for thirty seconds (server Task 4.2), and it
  // arrives here as its own class — which is NOT a FetchproxyProtocolError
  // subclass, so `classifyBridgeError` buckets it `other`, whose hint is the
  // empty string. Left to that, the one failure the whole refusal exists to
  // make legible printed as `bridge error (other): …`: an anonymous bucket
  // name in front of the only sentence on the line that says anything.
  //
  // So it is answered before the classifier, like the session-not-ready branch
  // above, and the remedy is chosen off the error's own `.peer` rather than
  // off its prose. Which half of the bridge is behind decides what the errand
  // IS: a browser extension to install and reload, or somebody else's MCP
  // process to upgrade and restart. Naming the wrong one is the #204 mis-hint
  // with a version problem that does exist.
  if (err instanceof FetchproxyProtocolVersionError) {
    io.err(`bridge refused: ${err.message}.`);
    io.err(
      err.peer === 'extension'
        ? `Update ContextMint Bridge to a release that speaks fetchproxy protocol ` +
            `${err.ourVersion} — from its store listing, or from ` +
            'https://github.com/nullnet-app/contextmint-bridge/releases — then reload it ' +
            "in your browser's extensions page and retry. Nothing is wrong with this " +
            'profile or your sign-in, and no flag here can bridge the two versions.'
        : 'That MCP holds the fetchproxy bridge port on this machine, so every MCP here — ' +
            'fpx included — dials into it as a peer: upgrade @fetchproxy/server there and ' +
            'restart that process. fpx cannot route around it, and neither the profile nor ' +
            '`fpx trust` is involved.',
    );
    return EXIT.BRIDGE;
  }
  const kind = classifyBridgeError(err);
  const msg = err instanceof Error ? err.message : String(err);
  // The server speaks to its library callers ("pass { domain: '<one of them>' }").
  // A CLI user has no object to pass — name the flag instead. Verbs that can
  // prove the gap up front (read, dom) refuse before connecting; this catches
  // the rest, e.g. `fpx session` on a multi-domain profile.
  if (msg.includes('declared multiple domains')) {
    io.err(
      `${msg.replace(/ — pass \{ domain.*$/, '')} — pick one with --storage-domain <domain>`,
    );
    return EXIT.USAGE;
  }
  // Some rejections know their own remedy — a widened scope needs a re-pair,
  // a missing tab needs a tab. Both arrive as `protocol` errors, so without
  // this they inherit the blanket version-mismatch hint below
  // and send people chasing a version problem that does not exist.
  //
  // The wording knowledge lives on the error itself (server 1.10+) rather than
  // in a regex here — the CLI is not the only consumer that needs it, and a
  // second copy would drift from the first. Branching on the shared
  // FetchproxyHintedError base rather than each subclass (1.12+, #204) means
  // the next hinted error is rendered right here without a new branch; keying
  // on FetchproxyScopeError alone is how the no-tab case ended up mis-hinted.
  if (err instanceof FetchproxyHintedError) {
    io.err(`bridge error (${kind}): ${err.originalError} — ${err.hint}`);
    return EXIT.BRIDGE;
  }
  const hints: Record<string, string> = {
    bridge_down: 'is your browser running with the ContextMint Bridge extension installed?',
    timeout: 'is a tab open on the declared domain and signed in?',
    // Same vocabulary as the FetchproxyProtocolVersionError branch above: the
    // extension by its user-facing name and the protocol number this process
    // speaks, so the reader knows what "matching" means (#412).
    protocol:
      `possible ContextMint Bridge / @fetchproxy/server version mismatch — this ` +
      `fpx speaks fetchproxy protocol ${PROTOCOL_VERSION}; update each to a release that speaks it.`,
    http: '',
    other: '',
  };
  io.err(`bridge error (${kind}): ${msg}${hints[kind] ? ` — ${hints[kind]}` : ''}`);
  return EXIT.BRIDGE;
}

function pairingPendingLine(code: string): string {
  return `bridge not ready — pairing pending. Approve pair code ${code} in the ContextMint Bridge extension popup and retry.`;
}

/**
 * Recognise the server's pairing-required transport error (see
 * `pairingErrorMessage` in `@fetchproxy/server`'s ws-server) and pull out its
 * pair code. `null` when the error is anything else.
 */
function pendingPairFrom(err: unknown): { code: string | null } | null {
  const msg = err instanceof Error ? err.message : typeof err === 'string' ? err : '';
  if (!/\bpairing required for\b/.test(msg)) return null;
  const m = /pair code is:\s*([0-9]{4}-[0-9]{4})/.exec(msg);
  return { code: m ? m[1]! : null };
}
