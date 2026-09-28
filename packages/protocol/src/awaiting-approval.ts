/**
 * D12 (account-level bridge pairing): the one `hello-rejected` reason that is
 * RETRYABLE.
 *
 * When the extension queues an approval card on a remote link and nobody is at
 * the browser, it answers the hello with `hello-rejected` whose reason starts
 * with {@link AWAITING_APPROVAL_REASON_PREFIX}, rather than holding the hello
 * silently while the MCP waits out its session-ready timeout. The call fails
 * at once with "approve it in your browser", and once the person does, the
 * hello the extension was holding (or the next one) succeeds.
 *
 * A documented prefix rather than a new field, for the same reason as
 * `unsupported-capability:` — every published validator rebuilds
 * `HelloRejectedFrame` as `{type, mcpId, reason}` and drops anything else.
 *
 * Diagnostic only, like every `hello-rejected`: it grants nothing, and a forged
 * one can only make a session fail, which a silent peer could do anyway. What
 * "retryable" changes is that the MCP does not treat it as the extension's
 * final answer.
 */

/**
 * The prefix, matched exactly: case-sensitive and at position 0. A looser
 * match would make a non-retryable refusal retryable.
 */
export const AWAITING_APPROVAL_REASON_PREFIX = 'awaiting-approval:';

/**
 * The extension's detail after the prefix (for example
 * `approve zillow in Chrome`), trimmed — `''` when it gave none — or `null`
 * when the reason is something else.
 */
export function parseAwaitingApprovalReason(reason: string): string | null {
  if (!reason.startsWith(AWAITING_APPROVAL_REASON_PREFIX)) return null;
  return reason.slice(AWAITING_APPROVAL_REASON_PREFIX.length).trim();
}
