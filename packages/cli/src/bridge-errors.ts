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
