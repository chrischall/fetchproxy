import {
  classifyBridgeError,
  FetchproxyHintedError,
  FetchproxyProtocolVersionError,
  FetchproxySessionNotReadyError,
} from '@fetchproxy/server';
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
        ? `bridge not ready — pairing pending. Approve pair code ${code} in the Transporter extension popup and retry.`
        : 'bridge not ready — is Chrome running with the Transporter extension installed and connected?',
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
        ? 'Both halves of the bridge ship as one release: install the Transporter build ' +
            'from that release, reload it at chrome://extensions, and retry. Nothing is ' +
            'wrong with this profile or your sign-in, and no flag here can bridge the ' +
            'two versions.'
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
  // this they inherit the blanket "version mismatch — update both" hint below
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
    bridge_down: 'is Chrome running with the Transporter extension installed?',
    timeout: 'is a tab open on the declared domain and signed in?',
    protocol: 'extension/server version mismatch — update both.',
    http: '',
    other: '',
  };
  io.err(`bridge error (${kind}): ${msg}${hints[kind] ? ` — ${hints[kind]}` : ''}`);
  return EXIT.BRIDGE;
}
