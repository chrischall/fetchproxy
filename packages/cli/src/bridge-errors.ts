import { classifyBridgeError, FetchproxySessionNotReadyError } from '@fetchproxy/server';
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
  // A widened declared scope is rejected by the extension's gate #2 until the
  // user re-approves it. That arrives as a `protocol` error, so without this
  // branch it inherited the blanket "version mismatch — update both" hint
  // below and sent people chasing a version problem that does not exist. The
  // actual remedy is a re-pair, and the message should say so.
  if (/\b(cookie|localStorage|sessionStorage) keys not in declared set:/.test(msg)) {
    io.err(
      `bridge error (${kind}): ${msg} — the declared scope changed since you paired. ` +
        'Revoke this MCP in the Transporter extension popup, then re-run to re-approve ' +
        'the new scope.',
    );
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
